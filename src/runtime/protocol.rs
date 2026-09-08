use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Incomplete,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Approved,
    Dangerous,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PayloadCoverage {
    pub fields_total: usize,
    pub fields_scanned: usize,
    pub bytes_total: usize,
    pub bytes_scanned: usize,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeFinding {
    // Opaque field number: an object key or JSON pointer can itself contain secrets.
    pub field_id: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub category: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutcome {
    pub status: JobStatus,
    pub verdict: Option<Verdict>,
    pub findings: Vec<RuntimeFinding>,
    pub coverage: PayloadCoverage,
    pub redacted: Option<Value>,
    pub reason: Option<String>,
}

impl ScanOutcome {
    pub fn failed(reason: &str) -> Self {
        Self {
            status: JobStatus::Failed,
            verdict: None,
            findings: vec![],
            coverage: PayloadCoverage::default(),
            redacted: None,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcRequest {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitParams {
    #[serde(default)]
    pub policy_scope: Option<String>,
    pub session: String,
    pub direction: Direction,
    pub tool: String,
    pub call_id: String,
    pub payload: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupParams {
    pub session: String,
    pub scan_id: String,
}
