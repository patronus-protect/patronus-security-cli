use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::redaction::refine_redaction;
use super::{
    payload::analyze_payload,
    protocol::{Direction, ScanOutcome},
    store::{CompletionError, Store},
    RuntimeResult,
};
use crate::ark::{AnalysisOutcome, ChunkInput, ContentAnalyzer};
use crate::config::Config;

struct UserPromptAnalyzer<'a>(&'a dyn ContentAnalyzer);
struct ScopedAnalyzer<'a> {
    inner: &'a dyn ContentAnalyzer,
    scope: &'a str,
}
impl ContentAnalyzer for ScopedAnalyzer<'_> {
    fn prepare(&mut self) -> crate::error::Result<()> {
        Ok(())
    }
    fn analyze(&self, input: ChunkInput<'_>) -> crate::error::Result<AnalysisOutcome> {
        self.inner.analyze_scoped(input, self.scope)
    }
}
impl ContentAnalyzer for UserPromptAnalyzer<'_> {
    fn prepare(&mut self) -> crate::error::Result<()> {
        Ok(())
    }

    fn analyze(&self, input: ChunkInput<'_>) -> crate::error::Result<AnalysisOutcome> {
        self.0.analyze_user_prompt(input)
    }
}

pub struct Worker {
    wake: mpsc::SyncSender<()>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn start(
        store: Arc<Mutex<Store>>,
        config: Config,
        fingerprint: String,
    ) -> RuntimeResult<Self> {
        let inference_config = config.clone();
        Self::start_with(store, config, fingerprint, move || {
            crate::inference::Inference::new(&inference_config)
                .map(|analyzer| Box::new(analyzer) as Box<dyn ContentAnalyzer>)
                .map_err(|_| "scanner initialization failed".into())
        })
    }

    pub fn start_with<F>(
        store: Arc<Mutex<Store>>,
        config: Config,
        fingerprint: String,
        factory: F,
    ) -> RuntimeResult<Self>
    where
        F: FnOnce() -> RuntimeResult<Box<dyn ContentAnalyzer>> + Send + 'static,
    {
        // Prepared L3 assets can take longer than one minute to map and warm on
        // first use. Reuse the bounded runtime scan budget for startup while
        // preserving the historical one-minute minimum.
        let startup_timeout = Duration::from_millis(config.runtime.scan_timeout_ms.max(60_000));
        let (wake, receiver) = mpsc::sync_channel(1);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = thread::spawn(move || {
            let prepared = factory().and_then(|mut analyzer| {
                analyzer
                    .prepare()
                    .map_err(|_| "local scanner assets are unavailable".to_string())?;
                Ok(analyzer)
            });
            let analyzer = match prepared {
                Ok(analyzer) => {
                    let _ = ready_tx.send(Ok(()));
                    analyzer
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            while !stopping.load(Ordering::Relaxed) {
                let next = store
                    .lock()
                    .map_err(|_| "store unavailable".to_string())
                    .and_then(|mut store| store.claim_next(&fingerprint));
                let work = match next {
                    Ok(Some(work)) => work,
                    Ok(None) => {
                        if receiver.recv_timeout(Duration::from_secs(1))
                            == Err(mpsc::RecvTimeoutError::Disconnected)
                        {
                            break;
                        }
                        if let Ok(mut store) = store.lock() {
                            let _ = store.cleanup();
                        }
                        continue;
                    }
                    Err(_) => break,
                };
                let remaining = work
                    .deadline_ms
                    .saturating_sub(chrono::Utc::now().timestamp_millis());
                let outcome = if remaining <= 0 {
                    ScanOutcome::failed("scan_timeout")
                } else {
                    // One owner consumes this gateway's events. RPC/status handling
                    // remains on the service thread while Ark analyzes a payload.
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let scoped = work.policy_scope.as_ref().map(|scope| ScopedAnalyzer {
                            inner: analyzer.as_ref(),
                            scope,
                        });
                        let active: &dyn ContentAnalyzer = scoped
                            .as_ref()
                            .map(|a| a as &dyn ContentAnalyzer)
                            .unwrap_or(analyzer.as_ref());
                        if let Some(mut original) = work.refinement.clone() {
                            if let Some(refined) = refine_redaction(
                                active,
                                &work.payload,
                                &original,
                                &config.chunking,
                                Instant::now() + Duration::from_millis(remaining as u64),
                            ) {
                                original.redacted = Some(refined);
                            }
                            return original;
                        }
                        let user_prompt = UserPromptAnalyzer(analyzer.as_ref());
                        let selected = if scoped.is_some() {
                            active
                        } else {
                            match work.direction {
                                Direction::Request => &user_prompt as &dyn ContentAnalyzer,
                                Direction::Response => analyzer.as_ref(),
                            }
                        };
                        analyze_payload(
                            selected,
                            &work.payload,
                            &config.chunking,
                            Instant::now() + Duration::from_millis(remaining as u64),
                        )
                    }))
                    .unwrap_or_else(|_| ScanOutcome::failed("scanner_crashed"))
                };
                if let Ok(mut store) = store.lock() {
                    match store.complete(&work.scan_id, &outcome) {
                        // A rejected result is already durably failed. It must
                        // not stop the worker from accepting subsequent text.
                        Ok(()) | Err(CompletionError::Capacity) => {}
                        Err(CompletionError::Storage(_)) => break,
                    }
                } else {
                    break;
                }
            }
        });
        match ready_rx.recv_timeout(startup_timeout) {
            Ok(Ok(())) => {}
            result => {
                stop.store(true, Ordering::Relaxed);
                let _ = wake.try_send(());
                return Err(result
                    .ok()
                    .and_then(Result::err)
                    .unwrap_or_else(|| "local scanner startup timed out".into()));
            }
        }
        Ok(Self {
            wake,
            stop,
            thread: Some(thread),
        })
    }

    pub fn notify(&self) -> RuntimeResult<()> {
        match self.wake.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(())) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(())) => Err("local scanner worker stopped".into()),
        }
    }

    pub fn is_alive(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.wake.try_send(());
        // The owning adapter also bounds child shutdown and terminates a stuck
        // process. A completed drop releases the state-directory lock.
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
