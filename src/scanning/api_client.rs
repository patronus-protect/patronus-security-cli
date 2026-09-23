//! Fixed-origin, bounded API submissions shared by runtime and explicit scans.
use crate::{
    config::Config,
    error::{Result, ScannerError},
};
use patronus_api_client::{Client, ErrorKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::{Read, Write},
    path::Path,
    time::Duration,
};

pub fn error(message: &str) -> ScannerError {
    ScannerError::Ark(message.into())
}

/// Public failure codes for API authentication. They carry no backend text.
pub const AUTH_MISSING: &str = "authentication_missing";
pub const AUTH_EXPIRED: &str = "authentication_expired";
pub const AUTH_REJECTED: &str = "authentication_rejected";

/// The fixed public reason for an API authentication failure; `None` for any other error.
pub fn authentication_reason(error: &ScannerError) -> Option<&'static str> {
    let ScannerError::Api {
        kind: ErrorKind::Authentication,
        code,
        ..
    } = error
    else {
        return None;
    };
    Some(match code.as_deref() {
        Some(AUTH_MISSING) => AUTH_MISSING,
        Some(AUTH_EXPIRED) => AUTH_EXPIRED,
        _ => AUTH_REJECTED,
    })
}

fn authentication_error(code: &'static str, message: &str) -> ScannerError {
    ScannerError::Api {
        kind: ErrorKind::Authentication,
        message: message.into(),
        code: Some(code.into()),
        retry_after: None,
        details: None,
    }
}

/// No usable credential exists locally: either never signed in or the saved login expired.
fn missing_credential() -> ScannerError {
    let expired = crate::config::user_root()
        .and_then(|root| crate::auth::status(&root))
        .is_ok_and(|status| status.state == "expired");
    if expired {
        authentication_error(
            AUTH_EXPIRED,
            "Patronus login expired. Run `patronus-security-scanner auth login`.",
        )
    } else {
        authentication_error(
            AUTH_MISSING,
            "API authentication required. Run onboarding or `patronus-security-scanner auth login`.",
        )
    }
}
pub fn token(config: &Config) -> Result<String> {
    std::env::var(&config.provider.api_key_env)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(Ok)
        .unwrap_or_else(crate::auth::access_token)
}
pub fn has_token(config: &Config) -> bool {
    std::env::var(&config.provider.api_key_env)
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
        || crate::auth::access_token().is_ok()
}

pub fn submit(config: &Config, body: Value, allow_anonymous: bool) -> Result<Vec<Value>> {
    config.validate()?;
    let timeout = Duration::from_millis(config.runtime.scan_timeout_ms);
    if let Ok(token) = token(config) {
        return submit_at(&config.provider.api_base_url, &token, body, timeout);
    }
    if !allow_anonymous {
        return Err(missing_credential());
    }
    with_anonymous_client(config, |client| {
        client.scan_json(body).map(|response| response.jobs)
    })
}
fn submit_at(base_url: &str, token: &str, body: Value, timeout: Duration) -> Result<Vec<Value>> {
    let deadline = std::time::Instant::now() + timeout;
    let mut attempt = 0u32;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(error("API scan timeout"));
        }
        let result = Client::with_base_url(base_url, token)
            .map_err(map_error)?
            .with_timeout(remaining)
            .scan_json(body.clone());
        match result {
            Ok(response) => return Ok(response.jobs),
            Err(source) if retryable_rate_limit(&source) => {
                let delay = retry_delay(&source, attempt);
                if delay >= deadline.saturating_duration_since(std::time::Instant::now()) {
                    return Err(map_error(source));
                }
                std::thread::sleep(delay);
                attempt = attempt.saturating_add(1);
            }
            Err(source) => return Err(map_error(source)),
        }
    }
}

fn retryable_rate_limit(source: &patronus_api_client::Error) -> bool {
    if source.kind == ErrorKind::RateLimit {
        return true;
    }
    if source.kind != ErrorKind::Quota {
        return false;
    }
    let code = source.code.as_deref().unwrap_or("").to_ascii_lowercase();
    let limit = source
        .details
        .as_deref()
        .and_then(|value| value.pointer("/quota/limit_kind"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    code.contains("rate")
        || code.contains("tokens_per_second")
        || limit.contains("rate")
        || limit.contains("per_second")
}

fn retry_delay(source: &patronus_api_client::Error, attempt: u32) -> Duration {
    let base = source
        .retry_after
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_millis(250u64.saturating_mul(1u64 << attempt.min(4))))
        .min(Duration::from_secs(5));
    let jitter = (u64::from(std::process::id()) + u64::from(attempt).saturating_mul(97)) % 251;
    base + Duration::from_millis(jitter)
}

pub fn submit_anonymous_files(
    config: &Config,
    files: &[patronus_api_client::FileUpload],
    scan_config: &Value,
) -> Result<Vec<Value>> {
    config.validate()?;
    with_anonymous_client(config, |client| {
        client
            .scan_files(files, None, Some(scan_config))
            .map(|response| response.jobs)
    })
}

#[derive(Serialize, Deserialize)]
struct AnonymousIdentity {
    cookie: String,
}

fn with_anonymous_client<T>(
    config: &Config,
    operation: impl FnOnce(&Client) -> patronus_api_client::Result<T>,
) -> Result<T> {
    let root = crate::config::user_root()?;
    let previous = load_anonymous_identity(&root)?;
    let client = Client::with_base_url_anonymous(&config.provider.api_base_url, previous)
        .map_err(map_error)?
        .with_timeout(Duration::from_millis(config.runtime.scan_timeout_ms));
    let result = operation(&client);
    if let Some(cookie) = client.anonymous_cookie() {
        save_anonymous_identity(&root, &cookie)?;
    }
    result.map_err(map_error)
}

fn identity_path(root: &Path) -> std::path::PathBuf {
    root.join("anonymous/identity.json")
}

fn load_anonymous_identity(root: &Path) -> Result<Option<String>> {
    let path = identity_path(root);
    if std::fs::symlink_metadata(root.join("anonymous"))
        .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        return Err(error("Unsafe anonymous identity directory"));
    }
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(ScannerError::Io { path, source }),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 8192 {
        return Err(error("Unsafe anonymous identity file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(error("Anonymous identity file must have permissions 0600"));
        }
    }
    let mut bytes = Vec::new();
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
        .open(&path)
        .map_err(|source| ScannerError::Io {
            path: path.clone(),
            source,
        })?
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|source| ScannerError::Io {
            path: path.clone(),
            source,
        })?;
    if bytes.len() > 8192 {
        return Err(error("Anonymous identity file is too large"));
    }
    let identity: AnonymousIdentity =
        serde_json::from_slice(&bytes).map_err(|_| error("Invalid anonymous identity file"))?;
    Ok(Some(identity.cookie))
}

fn save_anonymous_identity(root: &Path, cookie: &str) -> Result<()> {
    crate::dashboard::ensure_directory(root)?;
    let directory = root.join("anonymous");
    crate::dashboard::ensure_directory(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).map_err(
            |source| ScannerError::Io {
                path: directory.clone(),
                source,
            },
        )?;
    }
    let temporary = directory.join(format!(".identity-{:016x}.tmp", rand::random::<u64>()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|source| ScannerError::Io {
                path: temporary.clone(),
                source,
            })?;
        file.write_all(
            &serde_json::to_vec(&AnonymousIdentity {
                cookie: cookie.to_owned(),
            })
            .map_err(|_| error("Cannot encode anonymous identity"))?,
        )
        .map_err(|source| ScannerError::Io {
            path: temporary.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| ScannerError::Io {
            path: temporary.clone(),
            source,
        })?;
        crate::atomic_file::replace(&temporary, &identity_path(root)).map_err(|source| {
            ScannerError::Io {
                path: directory.clone(),
                source,
            }
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn map_error(source: patronus_api_client::Error) -> ScannerError {
    let message = match source.kind {
        // The server refused a credential that looked valid locally (expired or revoked).
        ErrorKind::Authentication => return authentication_error(
            AUTH_REJECTED,
            "The Patronus API rejected the saved login. Run `patronus-security-scanner auth login`.",
        ),
        ErrorKind::Quota | ErrorKind::RateLimit => return ScannerError::Api {
            kind: source.kind,
            message: format!("API usage limit reached. Run `patronus-security-scanner auth login` or open https://control.patronus.studio/.{}",
                source.retry_after.map(|seconds| format!(" Retry after {seconds} seconds.")).unwrap_or_default()),
            code: source.code,
            retry_after: source.retry_after,
            details: source.details,
        },
        ErrorKind::Timeout => "API scan timeout",
        ErrorKind::Protocol => "Invalid API response",
        ErrorKind::Validation => "API request rejected; no approval granted.",
        ErrorKind::Transport => "API request failed; no approval granted.",
    }
    .to_owned();
    ScannerError::Api {
        kind: source.kind,
        message,
        code: source.code,
        retry_after: source.retry_after,
        details: source.details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_error(kind: ErrorKind, code: &str, limit_kind: &str) -> patronus_api_client::Error {
        patronus_api_client::Error {
            kind,
            message: "bounded test error".into(),
            status: Some(429),
            code: Some(code.into()),
            request_id: None,
            retry_after: Some(1),
            details: Some(Box::new(serde_json::json!({
                "quota": {"limit_kind": limit_kind}
            }))),
        }
    }

    #[test]
    fn retries_rate_limits_but_not_permanent_quota() {
        assert!(retryable_rate_limit(&api_error(
            ErrorKind::RateLimit,
            "RATE_LIMITED",
            "requests_per_second"
        )));
        assert!(retryable_rate_limit(&api_error(
            ErrorKind::Quota,
            "TOKEN_RATE_EXCEEDED",
            "tokens_per_second"
        )));
        assert!(!retryable_rate_limit(&api_error(
            ErrorKind::Quota,
            "QUOTA_EXCEEDED",
            "daily_scan_units"
        )));
    }

    #[test]
    fn rejects_untrusted_job_identifier_before_polling() {
        use std::io::{BufRead, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut r = std::io::BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            while r.read_line(&mut line).unwrap() > 0 {
                if line.ends_with("\r\n\r\n") {
                    break;
                }
            }
            let body =
                r#"{"status":"accepted","jobs":[{"job_id":"https://foreign.invalid/token"}]}"#;
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

    #[test]
    fn anonymous_identity_round_trips_in_a_private_file() {
        let root = tempfile::tempdir().unwrap();
        save_anonymous_identity(root.path(), "patronus_anon=principal.signature").unwrap();
        assert_eq!(
            load_anonymous_identity(root.path()).unwrap().as_deref(),
            Some("patronus_anon=principal.signature")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(identity_path(root.path()))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
