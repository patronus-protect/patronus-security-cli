//! Control Plane login. Only the fixed issuer receives credentials.
use std::fs::OpenOptions;
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::cli::{AuthCommand, OutputFormat};
use crate::error::{IoContext, Result, ScannerError};

pub const CONTROL_ORIGIN: &str = "https://control.patronus.studio";
pub const TOKEN_TTL_SECONDS: i64 = 14 * 24 * 60 * 60;
const CLIENT_ID: &str = "patronus-security-scanner";
const MAX_AUTH_BYTES: u64 = 16_384;

// Deliberately no Debug implementation: access tokens must not enter logs.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    issuer: String,
    access_token: String,
    user_id: String,
    expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct AuthStatus {
    pub state: &'static str,
    pub user_id: Option<String>,
    pub expires_at: Option<i64>,
    pub remaining_seconds: i64,
    pub verified_online: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountUsage {
    pub daily_requests: u64,
    pub monthly_requests: u64,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub daily_limit: Option<u64>,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub monthly_limit: Option<u64>,
    pub tokens_per_second: u64,
    pub day_resets_at: i64,
    pub month_resets_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Usage {
    pub user_id: String,
    pub plan: String,
    pub usage: AccountUsage,
}

pub fn usage(root: &Path) -> Result<Usage> {
    let credentials = load(root)?.ok_or_else(|| error("not signed in; run auth login"))?;
    if credentials.expires_at <= chrono::Utc::now().timestamp() {
        return Err(error("token expired; run auth login again"));
    }
    Client::new().usage(&credentials)
}

fn error(message: &str) -> ScannerError {
    ScannerError::Output(format!("authentication: {message}"))
}

/// Keep actionable HTTP metadata, but never echo an upstream message or body.
fn http_error(status: u16, response: ureq::Response) -> ScannerError {
    let request_id = response
        .header("x-request-id")
        .filter(|value| {
            value.len() == 36
                && value.bytes().enumerate().all(|(index, byte)| {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_hexdigit()
                    }
                })
        })
        .map(str::to_owned);
    let mut bytes = Vec::new();
    let _ = response
        .into_reader()
        .take(MAX_AUTH_BYTES + 1)
        .read_to_end(&mut bytes);
    let body = (bytes.len() as u64 <= MAX_AUTH_BYTES)
        .then(|| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .flatten();
    let code = body
        .as_ref()
        .and_then(|body| body.pointer("/error/code"))
        .and_then(|code| code.as_str())
        .filter(|code| {
            matches!(
                *code,
                "INVALID_GRANT"
                    | "AUTH_REQUIRED"
                    | "INVALID_API_KEY"
                    | "AUTH_UNAVAILABLE"
                    | "ACCOUNT_UNAVAILABLE"
                    | "RATE_LIMITED"
                    | "KEY_NOT_FOUND"
                    | "SCOPE_REQUIRED"
                    | "METHOD_NOT_ALLOWED"
            )
        });
    let guidance = match status {
        400 | 401 | 403 => "code or token is invalid, expired or revoked; run auth login again",
        429 => "Control Plane rate limit reached; wait before starting a new login",
        _ => {
            "Control Plane could not complete authentication; run auth login again with a new code"
        }
    };
    let mut details = format!("HTTP {status}");
    if let Some(code) = code {
        details.push_str(&format!(", {code}"));
    }
    if let Some(id) = request_id {
        details.push_str(&format!(", request {id}"));
    }
    error(&format!("{guidance} ({details})"))
}

fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

struct Login {
    verifier: String,
    state: String,
}

impl Login {
    fn new() -> Self {
        Self {
            verifier: random_secret(),
            state: random_secret(),
        }
    }

    fn url(&self) -> String {
        let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(
            &ring::digest::SHA256,
            self.verifier.as_bytes(),
        ));
        format!("{CONTROL_ORIGIN}/cli-login?client_id={CLIENT_ID}&code_challenge={challenge}&code_challenge_method=S256&state={}", self.state)
    }
}

struct Client {
    origin: String,
    http: ureq::Agent,
}

impl Client {
    fn new() -> Self {
        Self {
            origin: CONTROL_ORIGIN.into(),
            http: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(Duration::from_secs(20))
                .build(),
        }
    }

    fn decode<T: serde::de::DeserializeOwned>(
        response: std::result::Result<ureq::Response, ureq::Error>,
    ) -> Result<T> {
        let response = response.map_err(|err| match err {
            ureq::Error::Status(status, response) => http_error(status, response),
            ureq::Error::Transport(transport) => error(&format!(
                "could not reach the Control Plane ({:?}); check your connection and run auth login again",
                transport.kind()
            )),
        })?;
        // Never render an upstream response body or transport error containing a secret.
        if response.status() != 200 {
            return Err(error("unexpected Control Plane response"));
        }
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_AUTH_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error("could not read Control Plane response"))?;
        if bytes.len() as u64 > MAX_AUTH_BYTES {
            return Err(error("Control Plane response too large"));
        }
        serde_json::from_slice(&bytes).map_err(|_| error("invalid Control Plane response"))
    }

    fn exchange(&self, login: &Login, code: &str) -> Result<Credentials> {
        if code.len() != 43
            || !code
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(error(
                "paste the complete one-time login code shown by the Control Plane",
            ));
        }
        #[derive(Deserialize)]
        struct Token {
            access_token: String,
            token_type: String,
            expires_in: i64,
            user_id: String,
            state: String,
        }
        let started = chrono::Utc::now().timestamp();
        let token: Token = Self::decode(
            self.http
                .post(&format!("{}/api/oauth/token", self.origin))
                .send_form(&[
                    ("grant_type", "authorization_code"),
                    ("client_id", CLIENT_ID),
                    ("code", code),
                    ("code_verifier", &login.verifier),
                    ("state", &login.state),
                ]),
        )?;
        if token.state != login.state
            || token.token_type != "Bearer"
            || !(1..=TOKEN_TTL_SECONDS).contains(&token.expires_in)
            || !valid_token(&token.access_token)
            || !valid_user(&token.user_id)
        {
            return Err(error("invalid Control Plane token metadata"));
        }
        Ok(Credentials {
            issuer: CONTROL_ORIGIN.into(),
            access_token: token.access_token,
            user_id: token.user_id,
            expires_at: started + token.expires_in,
        })
    }

    fn verify(&self, credentials: &Credentials) -> Result<()> {
        #[derive(Deserialize)]
        struct Verification {
            user_id: String,
            expires_at: i64,
        }
        let result: Verification = Self::decode(
            self.http
                .get(&format!("{}/api/oauth/status", self.origin))
                .set(
                    "Authorization",
                    &format!("Bearer {}", credentials.access_token),
                )
                .call(),
        )?;
        if result.user_id != credentials.user_id
            || result.expires_at < chrono::Utc::now().timestamp()
        {
            return Err(error("token is no longer valid; run auth login again"));
        }
        Ok(())
    }

    fn usage(&self, credentials: &Credentials) -> Result<Usage> {
        let result: Usage = Self::decode(
            self.http
                .get(&format!("{}/api/oauth/usage", self.origin))
                .set(
                    "Authorization",
                    &format!("Bearer {}", credentials.access_token),
                )
                .call(),
        )?;
        if result.user_id != credentials.user_id
            || !matches!(result.plan.as_str(), "free" | "light" | "pro")
            || result.usage.day_resets_at <= 0
            || result.usage.month_resets_at <= 0
        {
            return Err(error("invalid account usage response"));
        }
        Ok(result)
    }

    fn revoke(&self, credentials: &Credentials) -> Result<()> {
        let _: serde_json::Value = Self::decode(
            self.http
                .post(&format!("{}/api/oauth/revoke", self.origin))
                .set(
                    "Authorization",
                    &format!("Bearer {}", credentials.access_token),
                )
                .send_json(serde_json::json!({})),
        )?;
        Ok(())
    }
}

fn valid_token(value: &str) -> bool {
    (16..=8192).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

fn valid_user(value: &str) -> bool {
    value.strip_prefix("user_").is_some_and(|id| {
        !id.is_empty() && id.len() <= 128 && id.bytes().all(|c| c.is_ascii_alphanumeric())
    })
}

fn load(root: &Path) -> Result<Option<Credentials>> {
    let path = root.join("auth/credentials.json");
    if std::fs::symlink_metadata(root.join("auth"))
        .is_ok_and(|meta| meta.file_type().is_symlink() || !meta.is_dir())
    {
        return Err(error("unsafe auth directory"));
    }
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(ScannerError::Io { path, source }),
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > MAX_AUTH_BYTES
            {
                return Err(error("unsafe credentials file"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o777 != 0o600 {
                    return Err(error("credentials file must have permissions 0600"));
                }
            }
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&path).at(&path)?;
    let metadata = file.metadata().at(&path)?;
    if !metadata.is_file() || metadata.len() > MAX_AUTH_BYTES {
        return Err(error("unsafe credentials file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o777 != 0o600 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(error(
                "credentials must be private and owned by the current user",
            ));
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_AUTH_BYTES + 1)
        .read_to_end(&mut bytes)
        .at(&path)?;
    if bytes.len() as u64 > MAX_AUTH_BYTES {
        return Err(error("credentials file too large"));
    }
    let credentials: Credentials =
        serde_json::from_slice(&bytes).map_err(|_| error("invalid credentials file"))?;
    if credentials.issuer != CONTROL_ORIGIN
        || !valid_token(&credentials.access_token)
        || !valid_user(&credentials.user_id)
    {
        return Err(error("invalid stored credentials"));
    }
    Ok(Some(credentials))
}

fn save(root: &Path, credentials: &Credentials) -> Result<()> {
    crate::dashboard::ensure_directory(root)?;
    let directory = root.join("auth");
    crate::dashboard::ensure_directory(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .at(&directory)?;
    }
    let temporary = directory.join(format!(".{}.tmp", random_secret()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary).at(&temporary)?;
        file.write_all(
            &serde_json::to_vec(credentials).map_err(|_| error("could not encode credentials"))?,
        )
        .at(&temporary)?;
        file.sync_all().at(&temporary)?;
        crate::atomic_file::replace(&temporary, &directory.join("credentials.json"))
            .at(&directory)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub fn status(root: &Path) -> Result<AuthStatus> {
    let credentials = load(root)?;
    let remaining = credentials.as_ref().map_or(0, |c| {
        (c.expires_at - chrono::Utc::now().timestamp()).max(0)
    });
    Ok(AuthStatus {
        state: if credentials.is_none() {
            "signed_out"
        } else if remaining == 0 {
            "expired"
        } else {
            "signed_in"
        },
        user_id: credentials.as_ref().map(|c| c.user_id.clone()),
        expires_at: credentials.as_ref().map(|c| c.expires_at),
        remaining_seconds: remaining,
        verified_online: false,
    })
}

/// API/MCP callers share the same fixed-issuer bearer credential.
pub fn access_token() -> Result<String> {
    let root = crate::config::user_root()?;
    let credentials = load(&root)?.ok_or_else(|| error("not signed in; run auth login"))?;
    if credentials.expires_at <= chrono::Utc::now().timestamp() {
        return Err(error("token expired; run auth login again"));
    }
    Ok(credentials.access_token)
}

pub fn execute(command: AuthCommand) -> Result<()> {
    let root = crate::config::user_root()?;
    let client = Client::new();
    match command {
        AuthCommand::Login { no_browser } => {
            if status(&root)?.state == "signed_in" {
                println!(
                    "Already signed in. Run auth logout before signing in to another account."
                );
                return Ok(());
            }
            let login = Login::new();
            let url = login.url();
            println!("Open this link, sign in and authorize this CLI:\n\n{url}\n\nPaste the one-time login code below. Your API/MCP token will be valid for 14 days.");
            if !no_browser {
                open_browser(&url);
            }
            print!("Login code: ");
            std::io::stdout()
                .flush()
                .map_err(|_| error("could not display login prompt"))?;
            let mut code = String::new();
            std::io::stdin()
                .lock()
                .take(256)
                .read_line(&mut code)
                .map_err(|_| error("could not read login code"))?;
            let credentials = client.exchange(&login, code.trim())?;
            save(&root, &credentials)?;
            refresh_dashboard(&root);
            println!(
                "Signed in. Token expires at {}. Use auth token for API/MCP clients.",
                expiry(credentials.expires_at)
            );
        }
        AuthCommand::Status { format, check } => {
            let mut state = status(&root)?;
            if check && state.state == "signed_in" {
                client.verify(&load(&root)?.ok_or_else(|| error("credentials changed; retry"))?)?;
                state.verified_online = true;
            }
            match format {
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string(&state).map_err(|_| error("could not encode status"))?
                ),
                OutputFormat::Human => {
                    println!("Patronus: {}", state.state);
                    if let Some(expiration) = state.expires_at {
                        println!("Expires: {}", expiry(expiration));
                    }
                    if !state.verified_online {
                        println!(
                            "Local status. Use auth status --check to verify revocation online."
                        );
                    }
                }
            }
        }
        AuthCommand::Usage { format } => {
            let result = usage(&root)?;
            if matches!(format, OutputFormat::Json) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result)
                        .map_err(|_| error("could not serialize usage"))?
                );
            } else {
                println!("Plan: {}", result.plan);
                for (label, used, limit, reset) in [
                    (
                        "Daily",
                        result.usage.daily_requests,
                        result.usage.daily_limit,
                        result.usage.day_resets_at,
                    ),
                    (
                        "Monthly",
                        result.usage.monthly_requests,
                        result.usage.monthly_limit,
                        result.usage.month_resets_at,
                    ),
                ] {
                    let limit = limit.map_or_else(|| "unlimited".into(), |v| v.to_string());
                    let reset = chrono::DateTime::from_timestamp_millis(reset)
                        .ok_or_else(|| error("invalid usage reset"))?;
                    println!("{label}: {used} / {limit} requests; resets {reset}");
                }
                println!("Tokens per second: {}", result.usage.tokens_per_second);
            }
        }
        AuthCommand::Token => println!("{}", access_token()?),
        AuthCommand::Logout { local } => {
            if let Some(credentials) = load(&root)? {
                if !local && credentials.expires_at > chrono::Utc::now().timestamp() {
                    client.revoke(&credentials)?;
                }
                std::fs::remove_file(root.join("auth/credentials.json")).at(&root)?;
            }
            refresh_dashboard(&root);
            println!(
                "Signed out{}.",
                if local {
                    " locally; the server token remains valid until expiry or revocation"
                } else {
                    ""
                }
            );
        }
    }
    Ok(())
}

fn expiry(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|date| date.to_rfc3339())
        .unwrap_or_else(|| "unknown".into())
}

fn refresh_dashboard(root: &Path) {
    if crate::dashboard::rebuild_index(root, &root.join("output")).is_err() {
        eprintln!("Login state saved; run protocol render to refresh the dashboard.");
    }
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = std::process::Command::new("xdg-open");
    let _ = command
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

struct BrowserHandoff {
    login: Login,
    created: std::time::Instant,
}
fn handoffs() -> &'static std::sync::Mutex<std::collections::HashMap<String, BrowserHandoff>> {
    static PENDING: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, BrowserHandoff>>,
    > = std::sync::OnceLock::new();
    PENDING.get_or_init(Default::default)
}
pub fn begin_browser_login() -> Result<serde_json::Value> {
    if status(&crate::config::user_root()?)?.state == "signed_in" {
        return Err(error(
            "already signed in; sign out before starting a new login",
        ));
    }
    let mut pending = handoffs()
        .lock()
        .map_err(|_| error("login state unavailable"))?;
    pending.retain(|_, v| v.created.elapsed() < Duration::from_secs(300));
    if pending.len() >= 8 {
        return Err(error("too many pending logins"));
    }
    let login = Login::new();
    let url = login.url();
    let id = random_secret();
    pending.insert(
        id.clone(),
        BrowserHandoff {
            login,
            created: std::time::Instant::now(),
        },
    );
    Ok(serde_json::json!({"handoff_id":id,"authorization_url":url,"expires_in":300}))
}
pub fn finish_browser_login(id: &str, code: &str) -> Result<AuthStatus> {
    let pending = handoffs()
        .lock()
        .map_err(|_| error("login state unavailable"))?
        .remove(id)
        .ok_or_else(|| error("login expired; start again"))?;
    if pending.created.elapsed() >= Duration::from_secs(300) {
        return Err(error("login expired; start again"));
    }
    let root = crate::config::user_root()?;
    if status(&root)?.state == "signed_in" {
        return Err(error(
            "already signed in; sign out before starting a new login",
        ));
    }
    let credentials = Client::new().exchange(&pending.login, code.trim())?;
    save(&root, &credentials)?;
    refresh_dashboard(&root);
    status(&root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(expiry: i64) -> Credentials {
        Credentials {
            issuer: CONTROL_ORIGIN.into(),
            access_token: "test_bearer_never_in_status".into(),
            user_id: "user_test".into(),
            expires_at: expiry,
        }
    }

    #[test]
    fn private_credentials_roundtrip_and_expire_without_exposing_the_token() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(status(dir.path()).unwrap().state, "signed_out");
        save(
            dir.path(),
            &credentials(chrono::Utc::now().timestamp() + TOKEN_TTL_SECONDS),
        )
        .unwrap();
        let current = status(dir.path()).unwrap();
        assert_eq!(current.state, "signed_in");
        assert!(current.remaining_seconds > 13 * 86_400);
        assert!(!serde_json::to_string(&current)
            .unwrap()
            .contains("test_bearer"));
        crate::dashboard::rebuild_index(dir.path(), &dir.path().join("output")).unwrap();
        let index = std::fs::read_to_string(dir.path().join("index.html")).unwrap();
        assert!(index.contains("account-status connected"));
        assert!(index.contains(">Open Control Plane</a>"));
        assert!(!index.contains("test_bearer"));
        save(dir.path(), &credentials(1)).unwrap();
        assert_eq!(status(dir.path()).unwrap().state, "expired");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dir.path().join("auth/credentials.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_or_public_credentials() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), &credentials(1)).unwrap();
        let path = dir.path().join("auth/credentials.json");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(dir.path()).is_err());
        std::fs::remove_file(&path).unwrap();
        symlink("elsewhere", &path).unwrap();
        assert!(load(dir.path()).is_err());
    }

    fn server(body: String, status: u16) -> (Client, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut headers = String::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                headers.push_str(&line);
            }
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).unwrap();
            write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            headers + &String::from_utf8(bytes).unwrap()
        });
        let mut client = Client::new();
        client.origin = origin;
        (client, thread)
    }

    #[test]
    fn pkce_link_omits_verifier_and_exchange_sends_it_only_to_the_token_endpoint() {
        let login = Login::new();
        let link = login.url();
        assert!(link.starts_with("https://control.patronus.studio/cli-login?"));
        assert!(!link.contains(&login.verifier));
        let (client, thread) = server(serde_json::json!({ "access_token": "test_bearer_123456789", "token_type": "Bearer", "expires_in": TOKEN_TTL_SECONDS, "user_id": "user_test", "state": login.state }).to_string(), 200);
        let result = client.exchange(&login, &"c".repeat(43)).unwrap();
        assert!(result.expires_at > chrono::Utc::now().timestamp() + 13 * 86_400);
        let request = thread.join().unwrap();
        assert!(request.starts_with("POST /api/oauth/token "));
        assert!(request.contains(&format!("code_verifier={}", login.verifier)));
        assert!(request.contains("grant_type=authorization_code"));
    }

    #[test]
    fn rejects_wrong_state_and_excessive_lifetime_and_never_echoes_upstream_secrets() {
        let login = Login::new();
        for (state, lifetime) in [
            ("wrong".to_string(), TOKEN_TTL_SECONDS),
            (login.state.clone(), TOKEN_TTL_SECONDS + 1),
        ] {
            let (client, thread) = server(serde_json::json!({ "access_token": "test_bearer_123456789", "token_type": "Bearer", "expires_in": lifetime, "user_id": "user_test", "state": state }).to_string(), 200);
            assert!(client.exchange(&login, &"c".repeat(43)).is_err());
            thread.join().unwrap();
        }
        let (client, thread) = server("SECRET_UPSTREAM_BODY".into(), 401);
        let result = client
            .exchange(&login, &"c".repeat(43))
            .err()
            .unwrap()
            .to_string();
        assert!(!result.contains("SECRET_UPSTREAM_BODY"));
        thread.join().unwrap();
    }
    #[test]
    fn upstream_http_errors_show_only_allowlisted_diagnostics() {
        let login = Login::new();
        for code in ["AUTH_UNAVAILABLE", "PRIVATE_UPSTREAM_TOKEN"] {
            let (client, thread) = server(serde_json::json!({"error":{"code":code,"message":"PRIVATE_UPSTREAM_TOKEN"},"access_token":"PRIVATE_UPSTREAM_TOKEN"}).to_string(), 503);
            let message = client
                .exchange(&login, &"c".repeat(43))
                .err()
                .unwrap()
                .to_string();
            assert!(message.contains("HTTP 503"));
            assert_eq!(
                message.contains("AUTH_UNAVAILABLE"),
                code == "AUTH_UNAVAILABLE"
            );
            assert!(!message.contains("PRIVATE_UPSTREAM_TOKEN"));
            thread.join().unwrap();
        }
    }

    #[test]
    fn usage_is_account_bound_and_preserves_unlimited() {
        let body = serde_json::json!({"user_id":"user_test","plan":"pro","usage":{
            "daily_requests":12,"monthly_requests":55,"daily_limit":null,"monthly_limit":null,
            "tokens_per_second":25000,"day_resets_at":1800000000000_i64,"month_resets_at":1801000000000_i64
        }});
        let (client, thread) = server(body.to_string(), 200);
        let usage = client.usage(&credentials(3600)).unwrap();
        assert_eq!(usage.usage.daily_requests, 12);
        assert_eq!(usage.usage.monthly_limit, None);
        assert!(thread.join().unwrap().starts_with("GET /api/oauth/usage "));
        let mut wrong = body.clone();
        wrong["user_id"] = serde_json::json!("user_other");
        let (client, thread) = server(wrong.to_string(), 200);
        assert!(client.usage(&credentials(3600)).is_err());
        thread.join().unwrap();
        let mut missing = body;
        missing["usage"]
            .as_object_mut()
            .unwrap()
            .remove("daily_limit");
        assert!(serde_json::from_value::<Usage>(missing).is_err());
    }
}

// Loopback dashboard handoffs keep PKCE verifiers in the CLI process only.
