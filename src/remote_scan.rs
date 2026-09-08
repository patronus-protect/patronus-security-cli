//! Explicit URL/MCP API scans. Targets are resolved by the CLI, never fetched here.
use crate::{
    api_client::error,
    cli::{OutputFormat, RemoteScanArgs},
    config::{Config, ProviderMode},
    error::Result,
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
    if config.provider.mode == ProviderMode::Local {
        return Err(error("URL and MCP scans require the API. Run onboarding and explicitly select Hybrid or API."));
    }
    let target = match kind {
        "url" => https_target(target)?,
        "mcp" => mcp_target(target, server)?,
        _ => return Err(error("Unknown remote scan type")),
    };
    let target_id = crate::chunk::hash(format!("{kind}\0{target}").as_bytes());
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
        let jobs = crate::api_client::submit(config, body)?;
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
    Ok(report)
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
pub fn execute(kind: &str, args: RemoteScanArgs) -> Result<i32> {
    let mut config = Config::load(args.config.as_deref(), None)?;
    if let Some(level) = args.max_level {
        config.ark.max_level = level.as_str().into();
    }
    if !args.category.is_empty() {
        config.ark.categories = args.category;
    }
    let report = scan(&config, kind, &args.target, args.server.as_deref())?;
    if args.format == OutputFormat::Json {
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
}
