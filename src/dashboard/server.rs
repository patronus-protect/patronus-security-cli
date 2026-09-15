//! Loopback-only control surface. No CORS, no credentials in URLs, bounded requests.
use crate::{
    ark::{ChunkInput, ContentAnalyzer},
    config::Config,
    error::{Result, ScannerError},
};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

const LIMIT: usize = 1024 * 1024;
struct Request {
    method: String,
    path: String,
    headers: std::collections::BTreeMap<String, String>,
    body: Vec<u8>,
}

pub fn serve(port: u16) -> Result<()> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).map_err(fail)?;
    let host = listener.local_addr().map_err(fail)?.to_string();
    let token = format!(
        "{:032x}{:032x}",
        rand::random::<u128>(),
        rand::random::<u128>()
    );
    println!("Patronus dashboard: http://{host}/\nPress Ctrl+C to stop.");
    for stream in listener.incoming() {
        let mut stream = stream.map_err(fail)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(fail)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(fail)?;
        let result = read_request(&mut stream).and_then(|request| handle(request, &host, &token));
        let (status, content_type, body) = match result {
            Ok(body) => body,
            Err(error) => (
                400,
                "application/json",
                json!({"error": error.to_string()}).to_string(),
            ),
        };
        let _ = write!(stream, "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{body}", if status == 200 { "OK" } else { "Bad Request" }, body.len());
    }
    Ok(())
}

fn read_request(stream: &mut TcpStream) -> Result<Request> {
    let mut bytes = vec![];
    let mut buffer = [0; 4096];
    let end = loop {
        let count = stream.read(&mut buffer).map_err(fail)?;
        if count == 0 {
            return Err(fail("Incomplete request"));
        }
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break end + 4;
        }
        if bytes.len() > 16384 {
            return Err(fail("Headers too large"));
        }
    };
    if end > 16384 {
        return Err(fail("Headers too large"));
    }
    let header = std::str::from_utf8(&bytes[..end]).map_err(fail)?;
    let mut lines = header.split("\r\n");
    let parts: Vec<_> = lines.next().unwrap_or("").split_whitespace().collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" {
        return Err(fail("Invalid request"));
    }
    let method = parts[0].to_owned();
    let path = parts[1].to_owned();
    let mut headers = std::collections::BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| fail("Invalid header"))?;
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return Err(fail("Duplicate header"));
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(fail("Unsupported transfer encoding"));
    }
    let length = headers
        .get("content-length")
        .map(|v| v.parse::<usize>())
        .transpose()
        .map_err(fail)?
        .unwrap_or(0);
    if length > LIMIT {
        return Err(fail("Request too large"));
    }
    while bytes.len() < end + length {
        let count = stream.read(&mut buffer).map_err(fail)?;
        if count == 0 {
            return Err(fail("Incomplete body"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(Request {
        method,
        path,
        headers,
        body: bytes[end..end + length].to_vec(),
    })
}

fn handle(request: Request, host: &str, token: &str) -> Result<(u16, &'static str, String)> {
    if request.headers.get("host").map(String::as_str) != Some(host)
        || request
            .headers
            .get("origin")
            .is_some_and(|origin| origin != &format!("http://{host}"))
        || request
            .headers
            .get("sec-fetch-site")
            .is_some_and(|site| !["same-origin", "none"].contains(&site.as_str()))
    {
        return Err(fail("Untrusted origin"));
    }
    if request.method == "GET" && (request.path == "/" || request.path == "/index.html") {
        let root = crate::config::user_root()?;
        crate::dashboard::rebuild_index(&root, &root.join("output"))?;
        let page = std::fs::read_to_string(root.join("index.html")).map_err(fail)?
            .replace("default-src 'none';", "default-src 'none'; script-src 'self'; connect-src 'self';")
            .replace("</head>", &format!("<meta name=\"patronus-token\" content=\"{token}\"><script src=\"/dashboard.js\" defer></script></head>"));
        return Ok((200, "text/html", page));
    }
    if request.method == "GET" && request.path == "/dashboard.js" {
        return Ok((
            200,
            "text/javascript",
            concat!(
                include_str!("dashboard.js"),
                "\n",
                include_str!("dashboard_setup.js"),
                "\n",
                include_str!("table_pagination.js")
            )
            .into(),
        ));
    }
    if request.method == "GET" && request.path == "/table-pagination.js" {
        return Ok((
            200,
            "text/javascript",
            include_str!("table_pagination.js").into(),
        ));
    }
    if request.method == "GET" && request.path.ends_with(".html") {
        let relative = request.path.trim_start_matches('/');
        let components: Vec<_> = relative.split('/').collect();
        if !matches!(components.first(), Some(&"output" | &"protocol"))
            || components.iter().any(|part| {
                part.is_empty()
                    || *part == "."
                    || *part == ".."
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
        {
            return Err(fail("Invalid report path"));
        }
        let mut path = crate::config::user_root()?;
        for part in components {
            path.push(part);
            if std::fs::symlink_metadata(&path)
                .map_err(fail)?
                .file_type()
                .is_symlink()
            {
                return Err(fail("Invalid report path"));
            }
        }
        let page = std::fs::read_to_string(path)
            .map_err(fail)?
            .replace(
                "default-src 'none';",
                "default-src 'none'; script-src 'self';",
            )
            .replace(
                "</head>",
                "<script src=\"/table-pagination.js\" defer></script></head>",
            );
        return Ok((200, "text/html", page));
    }
    if request.headers.get("x-patronus-token").map(String::as_str) != Some(token) {
        return Err(fail("Missing dashboard authorization"));
    }
    let mut config = Config::load(None, None)?;
    if request.method == "GET" && request.path == "/api/onboarding" {
        return Ok((
            200,
            "application/json",
            json!({"setup":crate::onboarding::status()?,"job":crate::onboarding::job_status()})
                .to_string(),
        ));
    }

    if request.method == "GET" && request.path == "/api/usage" {
        let root = crate::config::user_root()?;
        let auth = crate::auth::status(&root)?;
        let result = if auth.state == "signed_in" {
            match crate::auth::usage(&root) {
                Ok(usage) => json!({"state": "available", "account": usage}),
                Err(_) => {
                    json!({"state": "unavailable", "message": "Account usage is currently unavailable. Refresh or sign in again."})
                }
            }
        } else {
            json!({"state": auth.state})
        };
        return Ok((200, "application/json", result.to_string()));
    }
    if request.method == "GET" && request.path == "/api/scan" {
        return Ok((
            200,
            "application/json",
            dashboard_scan_state().lock().map_err(fail)?.to_string(),
        ));
    }
    if request.method == "GET" && request.path == "/api/state" {
        return Ok((
            200,
            "application/json",
            json!({"config": config, "rules": crate::policy::rules(), "profiles": crate::plugin_policies::resolved(&config), "data_root": crate::config::user_root()?, "maintenance": {"cargo_install": crate::maintenance::cargo_install(), "standalone_install":crate::releases::standalone_install(),"repository":crate::releases::REPOSITORY}, "version": crate::VERSION, "revision": revision(&config)?})
                .to_string(),
        ));
    }
    if request.method == "GET" && request.path == "/api/integrations" {
        return Ok((
            200,
            "application/json",
            crate::integrations::dashboard_statuses().to_string(),
        ));
    }
    if request.method != "POST"
        || request.headers.get("content-type").map(String::as_str) != Some("application/json")
    {
        return Err(fail("Expected JSON POST"));
    }
    let data: Value = serde_json::from_slice(&request.body).map_err(fail)?;
    match request.path.as_str() {
        "/api/scan" => {
            start_dashboard_scan(config.clone(), data.clone())?;
            return Ok((
                200,
                "application/json",
                json!({"state":"running"}).to_string(),
            ));
        }
        "/api/auth/start" => {
            return Ok((
                200,
                "application/json",
                crate::auth::begin_browser_login()?.to_string(),
            ))
        }
        "/api/auth/complete" => {
            let id = data["handoff_id"]
                .as_str()
                .ok_or_else(|| fail("Missing login handoff"))?;
            let code = data["code"]
                .as_str()
                .ok_or_else(|| fail("Missing login code"))?;
            let status = crate::auth::finish_browser_login(id, code)?;
            return Ok((200, "application/json", json!(status).to_string()));
        }
        "/api/auth/logout" => {
            crate::auth::execute(crate::cli::AuthCommand::Logout { local: false })?
        }
        "/api/onboarding" => {
            let action = data["action"]
                .as_str()
                .ok_or_else(|| fail("Missing setup action"))?;
            if action == "configure" {
                if crate::onboarding::job_status()["state"] == "running" {
                    return Err(fail("Wait for the setup step to complete"));
                }
                if request.headers.get("if-match") != Some(&revision(&config)?) {
                    return Err(fail("Settings changed; reload before saving"));
                }
                let mode = serde_json::from_value(data["mode"].clone()).map_err(fail)?;
                let level = data["level"]
                    .as_str()
                    .ok_or_else(|| fail("Select an analysis level"))?;
                crate::onboarding::configure(mode, level)?;
            } else {
                let value = crate::onboarding::start_job(
                    action,
                    data["host"].as_str().map(str::to_string),
                    data["source"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(std::path::PathBuf::from),
                )?;
                return Ok((200, "application/json", value.to_string()));
            }
        }

        "/api/config" | "/api/policies" => {
            if crate::onboarding::job_status()["state"] == "running" {
                return Err(fail("Wait for setup to complete before changing settings"));
            }
            if request.headers.get("if-match") != Some(&revision(&config)?) {
                return Err(fail("Settings changed; reload before saving"));
            }
            if request.path == "/api/config" {
                config = serde_json::from_value(data).map_err(fail)?;
            } else {
                let scope = data["scope"]
                    .as_str()
                    .ok_or_else(|| fail("Missing plugin scope"))?;
                if !crate::plugin_policies::valid_scope(scope) {
                    return Err(fail("Unknown plugin scope"));
                }
                let profile: crate::plugin_policies::Profile =
                    serde_json::from_value(data["profile"].clone()).map_err(fail)?;
                profile.validate().map_err(fail)?;
                config.plugin_policies.insert(scope.into(), profile);
            }
            crate::local_settings::save(&config)?;
        }
        "/api/integration" => {
            let host = match data["host"].as_str() {
                Some("codex") => crate::cli::IntegrationHost::Codex,
                Some("claude") => crate::cli::IntegrationHost::Claude,
                Some("deepseek") => crate::cli::IntegrationHost::Deepseek,
                _ => return Err(fail("Unknown integration")),
            };
            let action = match data["action"].as_str() {
                Some("update") => crate::cli::IntegrationAction::Update,
                Some("install") => crate::cli::IntegrationAction::Install,
                Some("enable") => crate::cli::IntegrationAction::Enable,
                Some("disable") => crate::cli::IntegrationAction::Disable,
                Some("uninstall") => crate::cli::IntegrationAction::Uninstall,
                _ => return Err(fail("Unknown action")),
            };
            crate::integrations::execute(crate::cli::IntegrationArgs {
                host,
                action,
                source: data["source"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(std::path::PathBuf::from),
                scope: crate::cli::IntegrationScope::User,
                profile: None,
                keep_data: false,
            })?;
        }
        "/api/maintenance" => {
            let command = match data["action"].as_str() {
                Some("update") => crate::cli::MaintenanceCommand::Update,
                Some("uninstall") if data["confirmed"] == true => {
                    crate::cli::MaintenanceCommand::Uninstall {
                        all: data["all"] == true,
                        yes: true,
                    }
                }
                _ => return Err(fail("Unknown or unconfirmed maintenance action")),
            };
            crate::maintenance::execute(command)?;
        }
        _ => return Err(fail("Unknown endpoint")),
    }
    Ok((
        200,
        "application/json",
        json!({"ok": true, "revision": revision(&config)?}).to_string(),
    ))
}

fn dashboard_scan_state() -> &'static std::sync::Mutex<Value> {
    static STATE: std::sync::OnceLock<std::sync::Mutex<Value>> = std::sync::OnceLock::new();
    STATE.get_or_init(|| std::sync::Mutex::new(json!({"state":"idle"})))
}

fn start_dashboard_scan(mut config: Config, data: Value) -> Result<()> {
    let mut state = dashboard_scan_state().lock().map_err(fail)?;
    if state["state"] == "running" {
        return Err(fail("A dashboard scan is already running"));
    }
    *state = json!({"state":"running"});
    if let Err(error) = std::thread::Builder::new()
        .name("patronus-dashboard-scan".into())
        .spawn(move || {
            let next = match dashboard_scan(&mut config, &data) {
                Ok(result) => json!({"state":"complete","result":result}),
                Err(error) => json!({"state":"failed","message":error.to_string()}),
            };
            if let Ok(mut state) = dashboard_scan_state().lock() {
                *state = next;
            }
        })
    {
        *state = json!({"state":"idle"});
        return Err(fail(error));
    }
    Ok(())
}

fn dashboard_scan(config: &mut Config, data: &Value) -> Result<Value> {
    let kind = data["kind"]
        .as_str()
        .ok_or_else(|| fail("Missing scan type"))?;
    if matches!(kind, "url" | "mcp") {
        let target = data["target"]
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| fail("Enter a URL or MCP target"))?;
        let report = crate::remote_scan::scan(
            config,
            kind,
            target.trim(),
            data["server"].as_str().filter(|value| !value.is_empty()),
        )?;
        return serde_json::to_value(report).map_err(fail);
    }

    let (content, display_path) = match kind {
        "text" => {
            let text = data["text"]
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| fail("Enter text to scan"))?;
            (text.to_owned(), "dashboard-text".to_owned())
        }
        "file" => {
            let raw = data["target"]
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| fail("Enter an absolute file path"))?;
            let path = std::path::Path::new(raw.trim());
            if !path.is_absolute() {
                return Err(fail("File path must be absolute"));
            }
            let metadata = std::fs::symlink_metadata(path).map_err(fail)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > LIMIT as u64
            {
                return Err(fail("File must be a regular UTF-8 file under 1 MiB"));
            }
            (
                std::fs::read_to_string(path)
                    .map_err(|_| fail("File must be readable UTF-8 text"))?,
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("dashboard-file")
                    .to_owned(),
            )
        }
        _ => return Err(fail("Unknown scan type")),
    };

    config.output.include_evidence_text = false;
    let mut analyzer = crate::inference::Inference::new(config)?;
    analyzer.prepare()?;
    let outcome = analyzer.analyze(ChunkInput {
        run_id: "dashboard",
        chunk_id: "dashboard-1",
        file_id: "dashboard",
        path: &display_path,
        content: &content,
        input_tokens: Some(crate::inference::input_tokens(&content)),
    })?;
    let findings = outcome
        .classifications
        .into_iter()
        .filter(|classification| classification.matched)
        .map(|classification| {
            json!({
                "category": classification.category,
                "label": classification.label,
                "level": classification.level,
                "confidence": classification.confidence
            })
        })
        .collect::<Vec<_>>();
    let complete = outcome.failures.is_empty() && !outcome.degraded;
    let status = if !complete {
        "INCOMPLETE"
    } else if findings.is_empty() {
        "CLEAN"
    } else {
        "FINDINGS"
    };
    Ok(json!({"status":status,"complete":complete,"findings":findings}))
}

fn revision(config: &Config) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(config).map_err(fail)?)
        .to_hex()
        .to_string())
}
fn fail(error: impl std::fmt::Display) -> ScannerError {
    ScannerError::Output(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(host: &str) -> Request {
        Request {
            method: "GET".into(),
            path: "/api/state".into(),
            headers: [("host".into(), host.into())].into_iter().collect(),
            body: vec![],
        }
    }
    #[test]
    fn control_api_rejects_missing_token_and_cross_origin() {
        assert!(handle(request("127.0.0.1:1234"), "127.0.0.1:1234", "secret").is_err());
        let mut req = request("attacker.example");
        req.headers
            .insert("x-patronus-token".into(), "secret".into());
        assert!(handle(req, "127.0.0.1:1234", "secret").is_err());
        let mut req = request("127.0.0.1:1234");
        req.headers
            .insert("origin".into(), "https://attacker.example".into());
        req.headers
            .insert("x-patronus-token".into(), "secret".into());
        assert!(handle(req, "127.0.0.1:1234", "secret").is_err());
    }
    #[test]
    fn report_routes_reject_traversal_before_reading() {
        for path in [
            "/output/../config.html",
            "/output/%2e%2e/config.html",
            "/auth.html",
        ] {
            let mut req = request("127.0.0.1:1234");
            req.path = path.into();
            assert!(handle(req, "127.0.0.1:1234", "secret").is_err());
        }
    }
    #[test]
    fn pagination_script_uses_fifteen_rows_per_page() {
        let mut req = request("127.0.0.1:1234");
        req.path = "/table-pagination.js".into();
        let (status, content_type, body) = handle(req, "127.0.0.1:1234", "secret").unwrap();
        assert_eq!(status, 200);
        assert_eq!(content_type, "text/javascript");
        assert!(body.contains("pageSize=15"));
    }
}
