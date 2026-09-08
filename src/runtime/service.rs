use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::protocol::{Direction, LookupParams, RpcRequest, SubmitParams, PROTOCOL_VERSION};
use super::store::{NewJob, Store, StoreLimits};
use super::worker::Worker;
use super::RuntimeResult;
use crate::config::Config;
use serde_json::{json, Value};

// Bump when approval semantics change, independently of the wire protocol.
// Version 6 binds plugin text surfaces and confidence policies to durable jobs.
const ANALYSIS_POLICY_VERSION: u32 = 8;

pub struct Runtime {
    store: Arc<Mutex<Store>>,
    worker: Worker,
    config: Config,
    fingerprint: String,
}

impl Runtime {
    pub fn start(config: Config, root: &Path) -> RuntimeResult<Self> {
        Self::start_with_cache(config, root, &root.join("result-cache"))
    }

    fn start_with_cache(config: Config, root: &Path, cache_root: &Path) -> RuntimeResult<Self> {
        validate_local(&config)?;
        let fingerprint = blake3::hash(
            &serde_json::to_vec(&json!({
                "scanner": crate::VERSION, "ark_version": crate::ARK_VERSION,
                "policy": ANALYSIS_POLICY_VERSION, "plugin_policies": config.plugin_policies, "ark": config.ark, "analysis": config.analysis, "chunking": config.chunking, "provider": config.provider,
            }))
            .map_err(|_| "invalid scanner configuration".to_string())?,
        )
        .to_hex()
        .to_string();
        let mut store = Store::open_with_cache(
            root,
            cache_root,
            StoreLimits {
                max_payload_bytes: config.runtime.max_payload_bytes,
                max_store_bytes: config.runtime.max_store_bytes,
                max_pending_jobs: config.runtime.max_pending_jobs,
                retention_seconds: config.runtime.retention_seconds,
            },
        )?;
        store.recover(&fingerprint)?;
        let store = Arc::new(Mutex::new(store));
        let worker = Worker::start(store.clone(), config.clone(), fingerprint.clone())?;
        Ok(Self {
            store,
            worker,
            config,
            fingerprint,
        })
    }

    pub fn handle(&self, request: RpcRequest) -> Value {
        let id = request.id;
        if !valid_id(&id) {
            return rpc_error("", "invalid_request");
        }
        match self.dispatch(&request.method, request.params) {
            Ok(result) => json!({"id": id, "result": result}),
            // Never reflect argument values, filesystem errors or scanner text.
            Err(code) => rpc_error(&id, &code),
        }
    }

    fn dispatch(&self, method: &str, params: Value) -> RuntimeResult<Value> {
        match method {
            "hello" => {
                if params != json!({}) {
                    return Err("invalid_params".into());
                }
                Ok(
                    json!({"protocol_version": PROTOCOL_VERSION, "provider": self.config.provider.mode,
                    "scanner_version": crate::VERSION, "ark_version": crate::ARK_VERSION,
                    "ready": self.worker.is_alive(), "runtime": self.config.runtime}),
                )
            }
            "submit" => self.submit(params),
            "check" | "read_redacted" | "cancel" => {
                let params: LookupParams =
                    serde_json::from_value(params).map_err(|_| "invalid_params")?;
                if !valid_session(&params.session) || !valid_id(&params.scan_id) {
                    return Err("invalid_params".into());
                }
                let owner = blake3::hash(params.session.as_bytes()).to_hex().to_string();
                let mut store = self.store.lock().map_err(|_| "store_unavailable")?;
                match method {
                    "check" => store.check(&params.scan_id, &owner),
                    "read_redacted" => {
                        let result = store.request_redacted(
                            &params.scan_id,
                            &owner,
                            self.config.runtime.scan_timeout_ms,
                        )?;
                        if result["status"] == "pending" {
                            self.worker.notify().map_err(|_| "worker_unavailable")?;
                        }
                        Ok(result)
                    }
                    _ => store.cancel(&params.scan_id, &owner),
                }
                .map_err(|_| "store_unavailable".into())
            }
            _ => Err("unknown_method".into()),
        }
    }

    fn submit(&self, params: Value) -> RuntimeResult<Value> {
        let params: SubmitParams = serde_json::from_value(params).map_err(|_| "invalid_params")?;
        if params.policy_scope.as_ref().is_some_and(|scope| {
            !crate::plugin_policies::valid_scope(scope)
                || (scope.ends_with(".user_input") != (params.direction == Direction::Request))
        }) {
            return Err("invalid_params".into());
        }
        if !valid_session(&params.session)
            || params.tool.is_empty()
            || params.tool.len() > 512
            || params.call_id.is_empty()
            || params.call_id.len() > 512
        {
            return Err("invalid_params".into());
        }
        if !self.worker.is_alive() {
            return Err("worker_unavailable".into());
        }
        let timeout = match params.direction {
            Direction::Request => self.config.runtime.request_timeout_ms,
            Direction::Response => self.config.runtime.scan_timeout_ms,
        };
        let id = self
            .store
            .lock()
            .map_err(|_| "store_unavailable")?
            .enqueue(NewJob {
                session_hash: blake3::hash(params.session.as_bytes()).to_hex().to_string(),
                direction: params.direction,
                policy_scope: params.policy_scope,
                tool: params.tool,
                call_id: params.call_id,
                payload: params.payload,
                config_hash: self.fingerprint.clone(),
                deadline_ms: chrono::Utc::now().timestamp_millis() + timeout as i64,
            })
            .map_err(|_| "job_not_accepted".to_string())?;
        self.worker.notify().map_err(|_| "worker_unavailable")?;
        Ok(json!({"scan_id": id, "status": "pending"}))
    }
}

fn validate_local(config: &Config) -> RuntimeResult<()> {
    config
        .validate()
        .map_err(|_| "invalid runtime configuration".to_string())?;
    if config.ark.download_files {
        return Err("runtime requires prepared assets and ark.download_files=false".into());
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_session(value: &str) -> bool {
    value.len() >= 32 && valid_id(value)
}

fn rpc_error(id: &str, code: &str) -> Value {
    json!({"id": id, "error": {"code": code, "message": "Local security scan request could not be completed."}})
}

pub fn serve(config: Config, state_dir: Option<&Path>) -> RuntimeResult<()> {
    std::panic::set_hook(Box::new(|_| eprintln!("Local security scanner failed.")));
    let default_dir = crate::config::user_root()
        .map_err(|error| error.to_string())?
        .join("runtime");
    let max_frame = config.runtime.max_payload_bytes.saturating_add(16 * 1024);
    let cache_dir = crate::config::user_root()
        .map_err(|error| error.to_string())?
        .join("runtime-result-cache");
    let runtime = Runtime::start_with_cache(config, state_dir.unwrap_or(&default_dir), &cache_dir)?;
    serve_stream(&runtime, io::stdin().lock(), io::stdout().lock(), max_frame)
}

pub fn serve_stream(
    runtime: &Runtime,
    mut input: impl BufRead,
    mut output: impl Write,
    max_frame: usize,
) -> RuntimeResult<()> {
    loop {
        let mut frame = Vec::new();
        // take() bounds allocation even for an unterminated oversized message.
        let read = input
            .by_ref()
            .take((max_frame + 1) as u64)
            .read_until(b'\n', &mut frame)
            .map_err(|_| "runtime input failed".to_string())?;
        if read == 0 {
            return Ok(());
        }
        if frame.len() > max_frame {
            return Err("runtime message exceeds size limit".into());
        }
        let response = match serde_json::from_slice::<RpcRequest>(&frame) {
            Ok(request) => runtime.handle(request),
            Err(_) => rpc_error("", "invalid_request"),
        };
        serde_json::to_writer(&mut output, &response)
            .map_err(|_| "runtime output failed".to_string())?;
        output
            .write_all(b"\n")
            .and_then(|_| output.flush())
            .map_err(|_| "runtime output failed".to_string())?;
    }
}
