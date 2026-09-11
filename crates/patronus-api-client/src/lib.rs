//! Blocking, bounded client for the Patronus Scan API.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    io::Read,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DEFAULT_BASE_URL: &str = "https://control.patronus.studio/api/v1";
const MAX_RESPONSE_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Authentication,
    Quota,
    RateLimit,
    Validation,
    Timeout,
    Transport,
    Protocol,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
    pub status: Option<u16>,
    pub code: Option<String>,
    pub request_id: Option<String>,
    pub retry_after: Option<u64>,
    pub details: Option<Box<Value>>,
}

impl Error {
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            status: None,
            code: None,
            request_id: None,
            retry_after: None,
            details: None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResponse {
    pub status: String,
    #[serde(default)]
    pub jobs: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extraction: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone)]
pub struct FileUpload {
    pub filename: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

impl FileUpload {
    pub fn new(
        filename: impl Into<String>,
        media_type: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            filename: filename.into(),
            media_type: media_type.into(),
            bytes: bytes.into(),
        }
    }
}

pub struct Client {
    base_url: String,
    api_key: Option<String>,
    anonymous_cookie: Mutex<Option<String>>,
    timeout: Duration,
    poll_interval: Duration,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(api_key: impl Into<String>) -> Result<Self> {
        Self::with_base_url(DEFAULT_BASE_URL, api_key)
    }

    pub fn with_base_url(base_url: impl Into<String>, api_key: impl Into<String>) -> Result<Self> {
        Self::build(base_url.into(), Some(api_key.into()), None)
    }

    pub fn anonymous(cookie: Option<String>) -> Result<Self> {
        Self::with_base_url_anonymous(DEFAULT_BASE_URL, cookie)
    }

    pub fn with_base_url_anonymous(
        base_url: impl Into<String>,
        cookie: Option<String>,
    ) -> Result<Self> {
        Self::build(base_url.into(), None, cookie)
    }

    fn build(base_url: String, api_key: Option<String>, cookie: Option<String>) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_owned();
        let parsed = url::Url::parse(&base_url)
            .map_err(|_| Error::new(ErrorKind::Validation, "Invalid API base URL"))?;
        let local = parsed.scheme() == "http"
            && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        if (parsed.scheme() != "https" && !local)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(Error::new(
                ErrorKind::Validation,
                "API base URL must use HTTPS without credentials, query, or fragment",
            ));
        }
        if api_key.as_deref().is_some_and(|value| {
            value.trim().is_empty()
                || value
                    .chars()
                    .any(|character| matches!(character, '\r' | '\n'))
        }) {
            return Err(Error::new(ErrorKind::Authentication, "API key is required"));
        }
        if cookie
            .as_deref()
            .is_some_and(|value| !Self::valid_anonymous_cookie(value))
        {
            return Err(Error::new(
                ErrorKind::Validation,
                "Invalid anonymous identity cookie",
            ));
        }
        let timeout = Duration::from_secs(60);
        Ok(Self {
            base_url,
            api_key,
            anonymous_cookie: Mutex::new(cookie),
            timeout,
            poll_interval: Duration::from_millis(200),
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(timeout)
                .build(),
        })
    }

    pub fn anonymous_cookie(&self) -> Option<String> {
        self.anonymous_cookie
            .lock()
            .ok()
            .and_then(|value| value.clone())
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(timeout)
            .build();
        self
    }

    pub fn submit_json(&self, body: Value) -> Result<ScanResponse> {
        self.decode(
            self.authorize(self.agent.post(&format!("{}/scan", self.base_url)))
                .set("Content-Type", "application/json")
                .set("Prefer", "wait=1")
                .send_json(body),
        )
    }

    pub fn get_job(&self, job_id: &str) -> Result<Value> {
        self.get_job_until(job_id, Instant::now() + self.timeout)
    }

    fn get_job_until(&self, job_id: &str, deadline: Instant) -> Result<Value> {
        Self::validate_job_id(job_id)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| Error::new(ErrorKind::Timeout, "API scan timeout"))?;
        self.decode_value(
            self.authorize(self.agent.get(&format!("{}/scan/{job_id}", self.base_url)))
                .timeout(remaining)
                .call(),
        )
    }

    pub fn scan_json(&self, body: Value) -> Result<ScanResponse> {
        let deadline = Instant::now() + self.timeout;
        let submission = self.submit_json(body)?;
        self.wait(submission, deadline)
    }

    pub fn scan_text(&self, text: impl Into<String>) -> Result<ScanResponse> {
        self.scan_json(serde_json::json!({ "text": text.into() }))
    }

    pub fn scan_url(&self, url: impl Into<String>) -> Result<ScanResponse> {
        self.scan_json(serde_json::json!({ "url": url.into() }))
    }

    pub fn scan_mcp_server(&self, url: impl Into<String>) -> Result<ScanResponse> {
        self.scan_json(serde_json::json!({ "mcp_server_url": url.into() }))
    }

    pub fn scan_files(
        &self,
        files: &[FileUpload],
        text: Option<&str>,
        config: Option<&Value>,
    ) -> Result<ScanResponse> {
        if files.is_empty() {
            return Err(Error::new(
                ErrorKind::Validation,
                "At least one file is required",
            ));
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let boundary = format!("patronus-{}-{nonce}", std::process::id());
        let mut body = Vec::new();
        for file in files {
            if file.filename.is_empty()
                || file
                    .filename
                    .chars()
                    .any(|value| matches!(value, '\r' | '\n' | '"'))
                || file
                    .media_type
                    .chars()
                    .any(|value| matches!(value, '\r' | '\n'))
            {
                return Err(Error::new(ErrorKind::Validation, "Invalid file metadata"));
            }
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n",
                    file.filename, file.media_type
                )
                .as_bytes(),
            );
            body.extend_from_slice(&file.bytes);
            body.extend_from_slice(b"\r\n");
        }
        for (name, value) in [
            ("text", text.map(str::to_owned)),
            ("config", config.map(Value::to_string)),
        ] {
            if let Some(value) = value {
                body.extend_from_slice(
                    format!(
                        "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
                    )
                    .as_bytes(),
                );
            }
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let deadline = Instant::now() + self.timeout;
        let response = self.decode(
            self.authorize(self.agent.post(&format!("{}/scan", self.base_url)))
                .set(
                    "Content-Type",
                    &format!("multipart/form-data; boundary={boundary}"),
                )
                .set("Prefer", "wait=1")
                .send_bytes(&body),
        )?;
        self.wait(response, deadline)
    }

    pub fn scan_file(&self, file: FileUpload) -> Result<ScanResponse> {
        self.scan_files(&[file], None, None)
    }

    fn authorize(&self, request: ureq::Request) -> ureq::Request {
        let request = request.set("Accept", "application/json");
        if let Some(api_key) = &self.api_key {
            request.set("Authorization", &format!("Bearer {api_key}"))
        } else {
            let request = request.set("X-Patronus-Client", "cli");
            match self.anonymous_cookie() {
                Some(cookie) => request.set("Cookie", &cookie),
                None => request,
            }
        }
    }

    fn wait(&self, mut submission: ScanResponse, deadline: Instant) -> Result<ScanResponse> {
        if submission.status == "completed" {
            if submission.jobs.is_empty()
                || submission.jobs.len() > 32
                || submission.jobs.iter().any(|job| {
                    job.get("job_id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| Self::validate_job_id(id).is_err())
                        || !matches!(
                            job.get("status").and_then(Value::as_str),
                            Some("completed" | "failed")
                        )
                })
            {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "Invalid completed API response",
                ));
            }
            return Ok(submission);
        }
        if submission.status != "accepted"
            || submission.jobs.is_empty()
            || submission.jobs.len() > 32
        {
            return Err(Error::new(ErrorKind::Protocol, "Invalid API jobs"));
        }
        let mut jobs = Vec::with_capacity(submission.jobs.len());
        for accepted in &submission.jobs {
            let id = accepted
                .get("job_id")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::new(ErrorKind::Protocol, "Missing API job identifier"))?;
            Self::validate_job_id(id)?;
            loop {
                if Instant::now() >= deadline {
                    return Err(Error::new(ErrorKind::Timeout, "API scan timeout"));
                }
                let job = self.get_job_until(id, deadline)?;
                match job.get("status").and_then(Value::as_str) {
                    Some("queued" | "running") => std::thread::sleep(
                        self.poll_interval
                            .min(deadline.saturating_duration_since(Instant::now())),
                    ),
                    Some(_) => {
                        jobs.push(job);
                        break;
                    }
                    None => return Err(Error::new(ErrorKind::Protocol, "Missing API job status")),
                }
            }
        }
        submission.status = if jobs
            .iter()
            .all(|job| job.get("status").and_then(Value::as_str) == Some("completed"))
        {
            "completed"
        } else {
            "failed"
        }
        .into();
        submission.jobs = jobs;
        Ok(submission)
    }

    fn validate_job_id(value: &str) -> Result<()> {
        if value.len() == 36
            && value.starts_with("job_")
            && value[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::Protocol,
                "Invalid API job identifier",
            ))
        }
    }

    fn decode(
        &self,
        response: std::result::Result<ureq::Response, ureq::Error>,
    ) -> Result<ScanResponse> {
        serde_json::from_value(Self::normalize_scan_response(self.decode_value(response)?))
            .map_err(|_| Error::new(ErrorKind::Protocol, "Invalid API response"))
    }

    fn normalize_scan_response(value: Value) -> Value {
        let Value::Object(root) = value else {
            return value;
        };
        if root.contains_key("jobs") {
            return Value::Object(root);
        }
        let terminal = matches!(
            root.get("status").and_then(Value::as_str),
            Some("completed" | "failed")
        );
        let public_categories = root.get("categories").and_then(Value::as_object).is_some();
        let valid_job_id = root
            .get("job_id")
            .and_then(Value::as_str)
            .is_some_and(|job_id| Self::validate_job_id(job_id).is_ok());
        if !terminal || (!valid_job_id && !public_categories) {
            return Value::Object(root);
        }

        let mut job = root.clone();
        let mut envelope = Map::new();
        envelope.insert("status".into(), Value::String("completed".into()));
        for field in ["input", "extraction", "coverage", "usage", "request_id"] {
            job.remove(field);
            if let Some(value) = root.get(field) {
                envelope.insert(field.into(), value.clone());
            }
        }
        envelope.insert("jobs".into(), Value::Array(vec![Value::Object(job)]));
        Value::Object(envelope)
    }

    fn decode_value(
        &self,
        response: std::result::Result<ureq::Response, ureq::Error>,
    ) -> Result<Value> {
        let response = match response {
            Ok(response) => {
                self.capture_anonymous_cookie(&response);
                response
            }
            Err(ureq::Error::Status(status, response)) => {
                self.capture_anonymous_cookie(&response);
                return Err(Self::http_error(status, response));
            }
            Err(ureq::Error::Transport(error)) => {
                let kind = if error.to_string().to_lowercase().contains("timed out") {
                    ErrorKind::Timeout
                } else {
                    ErrorKind::Transport
                };
                return Err(Error::new(kind, "API request failed"));
            }
        };
        Self::read_json(response)
            .map_err(|_| Error::new(ErrorKind::Protocol, "Invalid API response"))
    }

    fn valid_anonymous_cookie(value: &str) -> bool {
        value.starts_with("patronus_anon=")
            && value.len() <= 4096
            && value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b';')
    }

    fn capture_anonymous_cookie(&self, response: &ureq::Response) {
        if self.api_key.is_some() {
            return;
        }
        let Some(cookie) = response
            .header("set-cookie")
            .and_then(|value| value.split(';').next())
        else {
            return;
        };
        if Self::valid_anonymous_cookie(cookie) {
            if let Ok(mut stored) = self.anonymous_cookie.lock() {
                *stored = Some(cookie.to_owned());
            }
        }
    }

    fn read_json(response: ureq::Response) -> std::result::Result<Value, ()> {
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ())?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(());
        }
        serde_json::from_slice(&bytes).map_err(|_| ())
    }

    fn http_error(status: u16, response: ureq::Response) -> Error {
        let header_retry_after = response
            .header("retry-after")
            .and_then(|value| value.parse().ok());
        let header_request_id = response.header("x-request-id").map(str::to_owned);
        let value = Self::read_json(response).unwrap_or(Value::Null);
        let retry_after =
            header_retry_after.or_else(|| value.get("quota")?.get("retry_after")?.as_u64());
        let details = value.get("error").unwrap_or(&value);
        let code = details
            .get("code")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let message = details
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("API request failed")
            .to_owned();
        let request_id = details
            .get("request_id")
            .or_else(|| value.get("request_id"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or(header_request_id);
        let kind = if value.get("quota").is_some() {
            ErrorKind::Quota
        } else {
            match status {
                401 | 403 => ErrorKind::Authentication,
                429 if code.as_deref().is_some_and(|value| value.contains("QUOTA")) => {
                    ErrorKind::Quota
                }
                429 => ErrorKind::RateLimit,
                400 | 404 | 409 | 413 | 422 => ErrorKind::Validation,
                _ => ErrorKind::Transport,
            }
        };
        Error {
            kind,
            message,
            status: Some(status),
            code,
            request_id,
            retry_after,
            details: Some(Box::new(value)),
        }
    }
}
