//! Explicit URL/MCP API scans. Targets are resolved by the CLI, never fetched here.
use crate::{
    api_client::error,
    cli::{OutputFormat, RemoteScanArgs, ScanOptions},
    config::Config,
    error::{Result, ScannerError},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteReport {
    pub schema: String,
    pub kind: String,
    pub provider: String,
    pub status: String,
    pub approved: bool,
    pub complete: bool,
    pub categories: Vec<String>,
    pub findings: Vec<RemoteFinding>,
    pub jobs: usize,
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteFinding {
    pub category: String,
    pub level: String,
    pub confidence: f64,
}

#[derive(Debug, Serialize)]
struct RemoteFailure<'a> {
    schema: &'static str,
    kind: &'a str,
    provider: &'static str,
    status: &'static str,
    approved: bool,
    complete: bool,
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_command: Option<&'static str>,
}

fn failure_reason(error: &ScannerError) -> &'static str {
    if let ScannerError::Api { kind, .. } = error {
        return match kind {
            patronus_api_client::ErrorKind::Authentication => "authentication_missing",
            patronus_api_client::ErrorKind::Quota | patronus_api_client::ErrorKind::RateLimit => {
                "usage_limit_reached"
            }
            patronus_api_client::ErrorKind::Timeout => "remote_scan_timeout",
            patronus_api_client::ErrorKind::Validation => "invalid_target",
            patronus_api_client::ErrorKind::Transport => "remote_api_unavailable",
            patronus_api_client::ErrorKind::Protocol => "remote_scan_failed",
        };
    }
    let message = error.to_string().to_lowercase();
    if message.contains("not signed in")
        || message.contains("token expired")
        || message.contains("authentication required")
    {
        "authentication_missing"
    } else if message.contains("usage limit") || message.contains("rate limit") {
        "usage_limit_reached"
    } else if message.contains("timeout") {
        "remote_scan_timeout"
    } else if message.contains("api request failed") || message.contains("api response unavailable")
    {
        "remote_api_unavailable"
    } else if matches!(error, ScannerError::Config { .. }) {
        "configuration_unavailable"
    } else if message.contains("expected")
        || message.contains("mcp config")
        || message.contains("https url")
    {
        "invalid_target"
    } else {
        "remote_scan_failed"
    }
}

pub fn https_target(target: &str) -> Result<String> {
    let parsed = url::Url::parse(target).map_err(|_| error("Expected a public HTTPS URL"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || target.len() > 8192
    {
        return Err(error(
            "Expected HTTPS without embedded credentials or fragment",
        ));
    }
    Ok(parsed.to_string())
}
pub fn mcp_target(target: &str, server: Option<&str>) -> Result<String> {
    if target.starts_with("https://") {
        return https_target(target);
    }
    let path = Path::new(target);
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| error("MCP config not found; provide its path or an HTTPS server URL"))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 1_048_576 {
        return Err(error("MCP config must be a regular file under 1 MiB"));
    }
    let bytes = std::fs::read(path).map_err(|_| error("MCP config unavailable"))?;
    let value: Value = if path.extension().is_some_and(|s| s == "toml") {
        let text = std::str::from_utf8(&bytes).map_err(|_| error("Invalid MCP config encoding"))?;
        serde_json::to_value(
            toml::from_str::<toml::Value>(text).map_err(|_| error("Invalid MCP configuration"))?,
        )
        .map_err(|_| error("Invalid MCP configuration"))?
    } else {
        serde_json::from_slice(&bytes)
            .map_err(|_| error("Expected JSON or TOML MCP configuration"))?
    };
    let map = value
        .get("mcpServers")
        .or_else(|| value.get("mcp_servers"))
        .and_then(Value::as_object);
    let definition = if let Some(map) = map {
        if let Some(name) = server {
            map.get(name)
                .ok_or_else(|| error("MCP server name not found"))?
        } else if map.len() == 1 {
            map.values().next().unwrap()
        } else {
            return Err(error("Multiple MCP servers: select one with --server NAME"));
        }
    } else {
        &value
    };
    if definition.get("command").is_some() {
        return Err(error("The API scans public HTTPS MCP servers; local stdio servers cannot be inspected remotely. No process was started."));
    }
    if definition
        .get("headers")
        .and_then(Value::as_object)
        .is_some_and(|m| !m.is_empty())
        || definition.get("bearer_token_env_var").is_some()
    {
        return Err(error(
            "The API cannot forward private MCP credentials. Use a public HTTPS endpoint.",
        ));
    }
    https_target(
        definition["url"]
            .as_str()
            .ok_or_else(|| error("MCP configuration has no HTTPS URL"))?,
    )
}
pub fn scan(
    config: &Config,
    kind: &str,
    target: &str,
    server: Option<&str>,
) -> Result<RemoteReport> {
    let target = match kind {
        "url" => https_target(target)?,
        "mcp" => mcp_target(target, server)?,
        _ => return Err(error("Unknown remote scan type")),
    };
    let target_id = crate::chunk::hash(format!("{kind}\0{target}").as_bytes());
    let anonymous = kind == "url" && !crate::api_client::has_token(config);
    let categories: Vec<String> = config
        .ark
        .categories
        .iter()
        .map(|c| {
            if c == "prompt_injection" {
                "injection".into()
            } else {
                c.clone()
            }
        })
        .filter(|category: &String| !anonymous || matches!(category.as_str(), "injection" | "dlp"))
        .collect();
    // Categories with identical gates share one fetch. Per-category overrides
    // get their own request so no disabled L1 gate or model level is lost.
    let mut groups: Vec<(Value, Vec<String>)> = Vec::new();
    for category in &categories {
        let canonical = if category == "injection" {
            "prompt_injection"
        } else {
            category
        };
        let mut gates = json!({"rules":config.analysis.l1_rules,
            "models":config.analysis.l1_detectors.iter().map(|(k,v)| (format!("native:{k}"), *v)).collect::<std::collections::BTreeMap<_,_>>()});
        if let Some(enabled) = config.analysis.l1.get(canonical) {
            gates["l1"] = json!(enabled);
        }
        let settings = json!({"max_level":config.analysis.level(canonical, &config.ark).to_uppercase(), "gates":gates});
        if let Some((_, members)) = groups
            .iter_mut()
            .find(|(candidate, _)| *candidate == settings)
        {
            members.push(category.clone());
        } else {
            groups.push((settings, vec![category.clone()]));
        }
    }
    let start = std::time::Instant::now();
    let mut report = RemoteReport {
        schema: "patronus.remote.scan.v1".into(),
        kind: kind.into(),
        provider: "api".into(),
        status: "CLEAN".into(),
        approved: true,
        complete: true,
        categories: categories.clone(),
        findings: vec![],
        jobs: 0,
        duration_ms: 0,
        target_id,
        scanned_at: Some(chrono::Utc::now()),
    };
    if groups.is_empty() {
        return Err(error("No categories enabled"));
    }
    for (mut settings, members) in groups {
        settings["categories"] = json!(members);
        let mut body = json!({"config":settings});
        body[if kind == "url" {
            "url"
        } else {
            "mcp_server_url"
        }] = json!(target);
        let jobs = crate::api_client::submit(config, body, kind == "url")?;
        let partial = summarize(kind, &members, &jobs)?;
        report.jobs += partial.jobs;
        report
            .findings
            .extend(partial.findings.into_iter().filter(|finding| {
                let category = if finding.category == "injection" {
                    "prompt_injection"
                } else {
                    &finding.category
                };
                !(matches!(finding.level.as_str(), "l2" | "l3")
                    && matches!(category, "prompt_injection" | "threat")
                    && config
                        .analysis
                        .confidence
                        .get(category)
                        .is_some_and(|threshold| finding.confidence < *threshold))
            }));
    }
    report.approved = report.findings.is_empty();
    report.status = if report.approved { "CLEAN" } else { "FINDINGS" }.into();
    report.duration_ms = start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    persist_report(&report)?;
    Ok(report)
}

fn persist_report(report: &RemoteReport) -> Result<()> {
    let root = crate::config::user_root()?.join("remote-scans");
    crate::dashboard::ensure_directory(&root)?;
    let id = format!(
        "{}-{:016x}.json",
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
        rand::random::<u64>()
    );
    crate::output::atomic_write(
        &root.join(id),
        &serde_json::to_vec(&report).map_err(|_| error("Cannot save remote scan report"))?,
    )?;
    Ok(())
}

type ApiErrorFields<'a> = (
    Option<&'a str>,
    Option<u64>,
    Option<&'a Value>,
    Option<&'a Value>,
    Option<&'static str>,
);

fn api_error_fields(error: &ScannerError) -> ApiErrorFields<'_> {
    let ScannerError::Api {
        code,
        retry_after,
        details,
        ..
    } = error
    else {
        return (None, None, None, None, None);
    };
    let body = details.as_deref();
    let quota = body.and_then(|value| value.get("quota"));
    let usage = body.and_then(|value| value.get("usage"));
    let next = match failure_reason(error) {
        "usage_limit_reached" | "authentication_missing" => {
            Some("patronus-security-scanner auth login")
        }
        _ => None,
    };
    (code.as_deref(), *retry_after, quota, usage, next)
}

fn remote_file(path: &Path, options: &ScanOptions) -> Result<RemoteReport> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| error("File not found"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(error(
            "Anonymous API upload requires one regular, non-symlink file",
        ));
    }
    if metadata.len() > 100_000 {
        return Err(error("Anonymous API files must not exceed 100,000 bytes"));
    }
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| error("Invalid file name"))?;
    let media_type = match path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("txt") => "text/plain",
        Some("md" | "markdown") => "text/markdown",
        Some("html" | "htm") => "text/html",
        Some("pdf") => "application/pdf",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        _ => {
            return Err(error(
                "Anonymous API files must be TXT, Markdown, HTML, PDF, or DOCX",
            ))
        }
    };
    let mut config = Config::load(options.config.as_deref(), None)?;
    config.apply_scan_options(options)?;
    let categories: Vec<String> = config
        .ark
        .categories
        .iter()
        .map(|value| {
            if value == "prompt_injection" {
                "injection".into()
            } else {
                value.clone()
            }
        })
        .collect();
    let settings = json!({
        "categories": categories,
        "max_level": config.ark.max_level.to_uppercase(),
        "gates": {"rules": config.analysis.l1_rules, "models": config.analysis.l1_detectors.iter().map(|(key,value)| (format!("native:{key}"), *value)).collect::<std::collections::BTreeMap<_,_>>()}
    });
    let bytes = std::fs::read(path).map_err(|_| error("File unavailable"))?;
    let target_id = crate::chunk::hash(&bytes);
    let start = std::time::Instant::now();
    let jobs = crate::api_client::submit_anonymous_files(
        &config,
        &[patronus_api_client::FileUpload::new(
            filename, media_type, bytes,
        )],
        &settings,
    )?;
    let mut report = summarize("file", &categories, &jobs)?;
    report.target_id = target_id;
    report.scanned_at = Some(chrono::Utc::now());
    report.duration_ms = start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    persist_report(&report)?;
    Ok(report)
}

pub fn execute_file(path: &Path, options: ScanOptions) -> Result<i32> {
    if options.activate_store_content
        || options.no_repo_config
        || options.output.is_some()
        || options.progress.is_some()
        || options.quiet
        || !options.include.is_empty()
        || !options.ignore.is_empty()
        || options.fail_on.is_some()
    {
        return Err(error(
            "Anonymous file uploads support only --config, --format, --max-level and --category",
        ));
    }
    execute_result("file", options.format, remote_file(path, &options))
}

fn execute_result(kind: &str, format: OutputFormat, report: Result<RemoteReport>) -> Result<i32> {
    let json = format == OutputFormat::Json;
    let report = match report {
        Ok(report) => report,
        Err(error) if json => {
            let (code, retry_after, quota, usage, next_command) = api_error_fields(&error);
            println!(
                "{}",
                serde_json::to_string_pretty(&RemoteFailure {
                    schema: "patronus.remote.scan.error.v1",
                    kind,
                    provider: "api",
                    status: "FAILED",
                    approved: false,
                    complete: false,
                    reason: failure_reason(&error),
                    code,
                    retry_after,
                    quota,
                    usage,
                    next_command,
                })
                .map_err(|_| crate::api_client::error("Cannot serialize remote scan failure"))?
            );
            return Ok(4);
        }
        Err(error) => return Err(error),
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|_| error("Cannot serialize scan report"))?
        );
    } else {
        println!(
            "{}: {} · API · {} ms\n{} categories checked; {} findings; complete coverage.",
            kind,
            report.status,
            report.duration_ms,
            report.categories.len(),
            report.findings.len()
        );
    }
    Ok(if report.approved { 0 } else { 1 })
}
fn summarize(kind: &str, categories: &[String], jobs: &[Value]) -> Result<RemoteReport> {
    if jobs.is_empty() {
        return Err(error("No API results"));
    }
    let mut findings = Vec::new();
    for job in jobs {
        if job["status"] != "completed"
            || job["completion"]["state"] != "complete"
            || job["completion"]["failures"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        {
            return Err(error("API scan coverage incomplete"));
        }
        for category in categories {
            let item = &job["categories"][category];
            let label = item["class_name"]
                .as_str()
                .ok_or_else(|| error("Missing API classification"))?;
            let confidence = item["confidence"]
                .as_f64()
                .filter(|s| s.is_finite() && (0.0..=1.0).contains(s))
                .ok_or_else(|| error("Invalid API confidence"))?;
            let level = item["level"].as_str().unwrap_or("").to_lowercase();
            if !["l1", "l2", "l3"].contains(&level.as_str()) {
                return Err(error("Invalid API level"));
            }
            if !crate::ark::is_benign(label) {
                findings.push(RemoteFinding {
                    category: category.clone(),
                    level,
                    confidence,
                });
            }
        }
    }
    Ok(RemoteReport {
        schema: "patronus.remote.scan.v1".into(),
        kind: kind.into(),
        provider: "api".into(),
        status: if findings.is_empty() {
            "CLEAN"
        } else {
            "FINDINGS"
        }
        .into(),
        approved: findings.is_empty(),
        complete: true,
        categories: categories.to_vec(),
        findings,
        jobs: jobs.len(),
        duration_ms: 0,
        target_id: String::new(),
        scanned_at: None,
    })
}
pub fn execute(kind: &str, args: RemoteScanArgs, server: Option<&str>) -> Result<i32> {
    let format = args.format;
    let report = (|| {
        let mut config = Config::load(args.config.as_deref(), None)?;
        if let Some(level) = args.max_level {
            config.ark.max_level = level.as_str().into();
        }
        if !args.category.is_empty() {
            config.ark.categories = args.category;
        }
        scan(&config, kind, &args.target, server)
    })();
    execute_result(kind, format, report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_private_credentials_and_stdio() {
        assert!(https_target("https://user:secret@example.org/").is_err());
        assert!(https_target("file:///tmp/data").is_err());
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("mcp.json");
        std::fs::write(&p, r#"{"mcpServers":{"one":{"command":"do-not-run"}}}"#).unwrap();
        assert!(mcp_target(p.to_str().unwrap(), None).is_err());
        std::fs::write(&p,r#"{"mcpServers":{"one":{"url":"https://example.org/mcp"},"two":{"url":"https://example.org/other"}}}"#).unwrap();
        assert!(mcp_target(p.to_str().unwrap(), None).is_err());
        assert_eq!(
            mcp_target(p.to_str().unwrap(), Some("one")).unwrap(),
            "https://example.org/mcp"
        );
    }
    #[test]
    fn no_partial_approval_and_no_raw_labels_in_reports() {
        let good = json!({"status":"completed","completion":{"state":"complete","failures":[]},"categories":{"injection":{"class_name":"benign","confidence":1.0,"level":"L1"}}});
        assert!(
            summarize("url", &["injection".into()], std::slice::from_ref(&good))
                .unwrap()
                .approved
        );
        assert!(summarize("url", &["injection".into(), "dlp".into()], &[good]).is_err());
    }

    #[test]
    fn local_mode_remote_scans_use_the_api_route() {
        let config: Config = toml::from_str(crate::config::DEFAULTS).unwrap();
        let error = scan(&config, "url", "http://example.org", None).unwrap_err();
        assert!(error.to_string().contains("Expected HTTPS"));
    }

    #[test]
    fn classifies_remote_failures_without_exposing_diagnostics() {
        assert_eq!(
            failure_reason(&crate::api_client::error("not signed in; run auth login")),
            "authentication_missing"
        );
        assert_eq!(
            failure_reason(&crate::api_client::error("API scan timeout")),
            "remote_scan_timeout"
        );
        assert_eq!(
            failure_reason(&crate::api_client::error(
                "API request failed; private diagnostic"
            )),
            "remote_api_unavailable"
        );
    }
}
