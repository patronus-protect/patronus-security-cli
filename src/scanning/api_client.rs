//! Fixed-origin, bounded API submissions shared by runtime and explicit scans.
use crate::{
    config::Config,
    error::{Result, ScannerError},
};
use serde_json::Value;
use std::{
    io::Read,
    time::{Duration, Instant},
};

pub fn error(message: &str) -> ScannerError {
    ScannerError::Ark(message.into())
}
pub fn token(config: &Config) -> Result<String> {
    std::env::var(&config.provider.api_key_env)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(Ok)
        .unwrap_or_else(crate::auth::access_token)
}
pub fn submit(config: &Config, body: Value) -> Result<Vec<Value>> {
    config.validate()?;
    let endpoint = format!("{}/scan", config.provider.api_base_url);
    submit_at(
        &endpoint,
        &token(config)?,
        body,
        Duration::from_millis(config.runtime.scan_timeout_ms),
    )
}
fn decode(response: std::result::Result<ureq::Response, ureq::Error>) -> Result<Value> {
    let response = response.map_err(|e| match e {
        ureq::Error::Status(401 | 403, _) => {
            error("API authentication required. Run onboarding or auth login.")
        }
        ureq::Error::Status(429, _) => {
            error("API usage limit reached. Check auth usage and retry after reset.")
        }
        _ => error("API request failed; no approval granted."),
    })?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| error("API response unavailable"))?;
    if bytes.len() > 1_048_576 {
        return Err(error("API response exceeds limit"));
    }
    serde_json::from_slice(&bytes).map_err(|_| error("Invalid API response"))
}
fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| error("API scan timeout"))
}
fn submit_at(endpoint: &str, token: &str, body: Value, timeout: Duration) -> Result<Vec<Value>> {
    let deadline = Instant::now() + timeout;
    let client = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(timeout)
        .build();
    let accepted = decode(
        client
            .post(endpoint)
            .set("Authorization", &format!("Bearer {token}"))
            .set("Prefer", "wait=1")
            .send_json(body),
    )?;
    let Some(jobs) = accepted.get("jobs") else {
        return Ok(vec![accepted]);
    };
    let jobs = jobs
        .as_array()
        .filter(|j| !j.is_empty() && j.len() <= 32)
        .ok_or_else(|| error("Invalid API jobs"))?;
    let mut results = Vec::new();
    for job in jobs {
        let id = job["job_id"]
            .as_str()
            .filter(|s| {
                s.len() == 36
                    && s.starts_with("job_")
                    && s[4..].bytes().all(|b| b.is_ascii_hexdigit())
            })
            .ok_or_else(|| error("Invalid API job identifier"))?;
        loop {
            let result = decode(
                client
                    .get(&format!("{endpoint}/{id}"))
                    .set("Authorization", &format!("Bearer {token}"))
                    .timeout(remaining(deadline)?)
                    .call(),
            )?;
            match result["status"].as_str() {
                Some("running" | "queued") => {
                    std::thread::sleep(Duration::from_millis(200).min(remaining(deadline)?))
                }
                Some("completed") => {
                    results.push(result);
                    break;
                }
                _ => return Err(error("API scan did not complete; no approval granted")),
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_untrusted_job_identifier_before_polling() {
        use std::io::{BufRead, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/scan", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut r = std::io::BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            while r.read_line(&mut line).unwrap() > 0 {
                if line.ends_with("\r\n\r\n") {
                    break;
                }
            }
            let body = r#"{"jobs":[{"job_id":"https://foreign.invalid/token"}]}"#;
            write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        assert!(submit_at(
            &endpoint,
            "test",
            serde_json::json!({"text":"hello"}),
            Duration::from_secs(3)
        )
        .is_err());
        thread.join().unwrap();
    }
}
