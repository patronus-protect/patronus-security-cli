use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub response_wait_ms: u64,
    pub request_timeout_ms: u64,
    pub scan_timeout_ms: u64,
    pub retention_seconds: u64,
    pub max_payload_bytes: usize,
    pub max_store_bytes: u64,
    pub max_pending_jobs: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            response_wait_ms: 500,
            request_timeout_ms: 30_000,
            scan_timeout_ms: 60_000,
            retention_seconds: 30 * 86_400,
            max_payload_bytes: 10 * 1024 * 1024,
            max_store_bytes: 512 * 1024 * 1024,
            max_pending_jobs: 64,
        }
    }
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.scan_timeout_ms == 0
            || self.scan_timeout_ms > 300_000
            || self.request_timeout_ms == 0
            || self.request_timeout_ms > self.scan_timeout_ms
            || self.response_wait_ms > self.scan_timeout_ms
            || self.retention_seconds == 0
            || self.retention_seconds > 30 * 86_400
            || self.max_payload_bytes == 0
            || self.max_payload_bytes > 64 * 1024 * 1024
            || self.max_store_bytes < self.max_payload_bytes as u64
            || self.max_pending_jobs == 0
            || self.max_pending_jobs > 4096
        {
            return Err("invalid runtime limits: deadlines, retention, payload and queue limits must be bounded".into());
        }
        Ok(())
    }
}
