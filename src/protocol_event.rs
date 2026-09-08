use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Result, ScannerError};

const EVENT_SCHEMA: &str = "patronus.protocol.event.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtocolEvent {
    pub schema: String,
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub session_id: String,
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<String>,
}

impl ProtocolEvent {
    pub fn validate(&self) -> Result<()> {
        if self.schema != EVENT_SCHEMA {
            return invalid("unsupported protocol event schema");
        }
        bounded_token("host", &self.host, 32)?;
        if !matches!(self.host.as_str(), "codex" | "claude" | "deepseek") {
            return invalid("unsupported host");
        }
        bounded_token("session_id", &self.session_id, 128)?;
        valid_hash("session_id", &self.session_id)?;
        bounded_token("event", &self.event, 64)?;
        if !matches!(
            self.event.as_str(),
            "scan_started" | "scan_completed" | "scan_failed"
        ) {
            return invalid("unsupported event");
        }
        optional_token("direction", self.direction.as_deref(), 16)?;
        if self
            .direction
            .as_deref()
            .is_some_and(|value| !matches!(value, "request" | "response" | "status" | "static"))
        {
            return invalid("unsupported direction");
        }
        optional_token("tool_name", self.tool_name.as_deref(), 128)?;
        optional_token("scan_id", self.scan_id.as_deref(), 256)?;
        optional_token("status", self.status.as_deref(), 32)?;
        if self.status.as_deref().is_some_and(|value| {
            !matches!(
                value,
                "started"
                    | "pending"
                    | "approved"
                    | "dangerous"
                    | "redacted"
                    | "failed"
                    | "unavailable"
                    | "clean"
                    | "findings"
                    | "incomplete"
                    | "cancelled"
                    | "expired"
                    | "completed"
            )
        }) {
            return invalid("unsupported status");
        }
        optional_token("payload_hash", self.payload_hash.as_deref(), 128)?;
        if let Some(value) = &self.payload_hash {
            valid_hash("payload_hash", value)?;
        }
        Ok(())
    }
}

fn optional_token(name: &str, value: Option<&str>, max: usize) -> Result<()> {
    if let Some(value) = value {
        bounded_token(name, value, max)?;
    }
    Ok(())
}

fn bounded_token(name: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return invalid(&format!("invalid {name}"));
    }
    Ok(())
}

fn valid_hash(name: &str, value: &str) -> Result<()> {
    let Some(hex) = value
        .strip_prefix("sha256:")
        .or_else(|| value.strip_prefix("blake3:"))
    else {
        return invalid(&format!("{name} must be hashed"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return invalid(&format!("invalid {name}"));
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(ScannerError::Output(message.into()))
}
