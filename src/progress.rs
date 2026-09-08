use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::cli::ProgressMode;
use crate::config::ProgressConfig;

#[derive(Debug, Serialize)]
struct ProgressEvent<'a> {
    schema: &'static str,
    phase: &'a str,
    processed_bytes: u64,
    total_bytes: u64,
    files_completed: usize,
    files_total: usize,
    chunks_completed: usize,
    skipped: usize,
    failures: usize,
    elapsed_seconds: f64,
    megabytes_per_second: Option<f64>,
    eta_seconds: Option<f64>,
}

pub struct ProgressTracker {
    mode: ProgressMode,
    config: ProgressConfig,
    total_bytes: u64,
    total_files: usize,
    started: Instant,
    scan_started: Option<Instant>,
    last_emit: Instant,
    last_sample: Instant,
    last_bytes: u64,
    smoothed_bytes_per_second: Option<f64>,
    record_path: Option<PathBuf>,
}

impl ProgressTracker {
    pub fn new(
        config: &ProgressConfig,
        total_bytes: u64,
        total_files: usize,
        record_path: Option<PathBuf>,
    ) -> Self {
        let mode = match config.mode {
            ProgressMode::Auto => {
                if std::io::stderr().is_terminal() {
                    ProgressMode::Tty
                } else {
                    ProgressMode::Plain
                }
            }
            other => other,
        };
        let now = Instant::now();
        Self {
            mode,
            config: config.clone(),
            total_bytes,
            total_files,
            started: now,
            scan_started: None,
            last_emit: now
                .checked_sub(Duration::from_secs(config.plain_interval_seconds))
                .unwrap_or(now),
            last_sample: now,
            last_bytes: 0,
            smoothed_bytes_per_second: None,
            record_path,
        }
    }

    pub fn phase(&mut self, phase: &str) {
        if phase == "scanning" {
            let now = Instant::now();
            self.scan_started = Some(now);
            self.last_sample = now;
        }
        let value = serde_json::json!({
            "schema": "patronus.security-scanner.progress.v1",
            "phase": phase
        });
        record(self.record_path.as_deref(), &value);
        match self.mode {
            ProgressMode::Json => eprintln!("{value}"),
            ProgressMode::Off => {}
            _ => eprintln!("{phase}…"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        processed_bytes: u64,
        files: usize,
        chunks: usize,
        skipped: usize,
        failures: usize,
        force: bool,
    ) {
        let now = Instant::now();
        let sample_seconds = now.duration_since(self.last_sample).as_secs_f64();
        if sample_seconds > 0.0 && processed_bytes >= self.last_bytes {
            let instantaneous = (processed_bytes - self.last_bytes) as f64 / sample_seconds;
            self.smoothed_bytes_per_second = Some(match self.smoothed_bytes_per_second {
                Some(previous) => 0.25 * instantaneous + 0.75 * previous,
                None => instantaneous,
            });
            self.last_sample = now;
            self.last_bytes = processed_bytes;
        }
        if self.mode == ProgressMode::Off {
            return;
        }
        let interval = Duration::from_secs(self.config.plain_interval_seconds);
        if !force
            && self.mode == ProgressMode::Plain
            && now.duration_since(self.last_emit) < interval
        {
            return;
        }
        self.last_emit = now;
        let scan_elapsed = self
            .scan_started
            .map(|started| now.duration_since(started))
            .unwrap_or_default();
        let speed = self.smoothed_bytes_per_second.filter(|speed| *speed > 0.0);
        let eta = if processed_bytes >= self.config.eta_min_bytes
            && scan_elapsed >= Duration::from_secs(self.config.eta_min_seconds)
        {
            speed.map(|speed| self.total_bytes.saturating_sub(processed_bytes) as f64 / speed)
        } else {
            None
        };
        let event = ProgressEvent {
            schema: "patronus.security-scanner.progress.v1",
            phase: "scanning",
            processed_bytes,
            total_bytes: self.total_bytes,
            files_completed: files,
            files_total: self.total_files,
            chunks_completed: chunks,
            skipped,
            failures,
            elapsed_seconds: scan_elapsed.as_secs_f64(),
            megabytes_per_second: speed.map(|value| value / 1_000_000.0),
            eta_seconds: eta,
        };
        let value = serde_json::to_value(&event).expect("serializable progress");
        record(self.record_path.as_deref(), &value);
        match self.mode {
            ProgressMode::Json => eprintln!("{value}"),
            ProgressMode::Tty | ProgressMode::Plain | ProgressMode::Auto => {
                let percent = if self.total_bytes == 0 {
                    100.0
                } else {
                    processed_bytes as f64 * 100.0 / self.total_bytes as f64
                };
                let speed = speed
                    .map(|value| format!("{:.1} MB/s", value / 1_000_000.0))
                    .unwrap_or_else(|| "estimating…".into());
                let eta = eta
                    .map(|value| format!("ETA ~{}", duration(value as u64)))
                    .unwrap_or_else(|| "ETA estimating…".into());
                let line = format!("{:.1} MB / {:.1} MB ({percent:.1}%) | {speed} | {eta} | {files}/{} files | {chunks} chunks | {skipped} skipped | {failures} failed", processed_bytes as f64 / 1_000_000.0, self.total_bytes as f64 / 1_000_000.0, self.total_files);
                if self.mode == ProgressMode::Tty {
                    eprint!("\r{line}");
                } else {
                    eprintln!("{} {line}", chrono::Utc::now().to_rfc3339());
                }
            }
            ProgressMode::Off => {}
        }
    }

    pub fn finish(&self) {
        if self.mode == ProgressMode::Tty {
            eprintln!();
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

pub fn initial_phase(mode: ProgressMode, phase: &str, record_path: Option<&Path>) {
    let value = serde_json::json!({
        "schema": "patronus.security-scanner.progress.v1",
        "phase": phase
    });
    record(record_path, &value);
    match mode {
        ProgressMode::Off => {}
        ProgressMode::Json => eprintln!("{value}"),
        _ => eprintln!("{phase}…"),
    }
}

fn record(path: Option<&Path>, value: &serde_json::Value) {
    let Some(path) = path else { return };
    let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(path) else {
        return;
    };
    let _ = writeln!(file, "{value}");
}

pub fn duration(seconds: u64) -> String {
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}
