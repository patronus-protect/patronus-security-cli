use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::dashboard_auth::{
    attest_protocol_event, verify_attestation, verify_protocol_attestation, ProtocolAttestation,
};
pub use crate::dashboard_auth::{attest_run, provision_dashboard_key, RunAttestation};
use crate::error::{IoContext, Result, ScannerError};
use crate::output::atomic_write;
pub use crate::protocol_event::ProtocolEvent;
use crate::report::{Report, ScanStatus};

pub fn workspace_root(output_root: &Path) -> PathBuf {
    if output_root.file_name().is_some_and(|name| name == "output") {
        output_root.parent().unwrap_or(output_root).to_path_buf()
    } else {
        output_root.to_path_buf()
    }
}

pub fn append_protocol_event(root: &Path, event: &ProtocolEvent) -> Result<PathBuf> {
    persist_protocol_event(root, event, true)
}

pub fn persist_protocol_event(root: &Path, event: &ProtocolEvent, render: bool) -> Result<PathBuf> {
    event.validate()?;
    ensure_directory(root)?;
    let lock_path = root.join(".dashboard.lock");
    ensure_regular_or_missing(&lock_path)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .at(&lock_path)?;
    lock.lock_exclusive().map_err(|source| ScannerError::Io {
        path: lock_path.clone(),
        source,
    })?;

    let result = append_protocol_locked(root, event, render);
    let _ = lock.unlock();
    result
}

fn append_protocol_locked(root: &Path, event: &ProtocolEvent, render: bool) -> Result<PathBuf> {
    let protocol_root = root.join("protocol");
    ensure_directory(&protocol_root)?;
    let session_name = blake3::hash(event.session_id.as_bytes())
        .to_hex()
        .to_string();
    let jsonl = protocol_root.join(format!("{session_name}.jsonl"));
    ensure_regular_or_missing(&jsonl)?;
    let mut records = read_protocol_records(root, &jsonl)?;
    let sequence = u64::try_from(records.len())
        .map_err(|_| ScannerError::Output("too many protocol events".into()))?;
    let previous_record_hash = records.last().map(protocol_record_hash).transpose()?;
    let (attestation, authentication) =
        attest_protocol_event(root, event, sequence, previous_record_hash)?;
    let record = ProtocolRecord {
        schema: "patronus.protocol.record.v1".into(),
        event: event.clone(),
        attestation,
        authentication,
    };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&jsonl)
        .at(&jsonl)?;
    serde_json::to_writer(&mut file, &record)
        .map_err(|error| ScannerError::Output(error.to_string()))?;
    file.write_all(b"\n").at(&jsonl)?;
    file.sync_all().at(&jsonl)?;

    if !render {
        return Ok(jsonl);
    }

    records.push(record);
    let events = records
        .iter()
        .map(|record| record.event.clone())
        .collect::<Vec<_>>();
    let html_path = protocol_root.join(format!("{session_name}.html"));
    atomic_write(&html_path, render_protocol(&events).as_bytes())?;
    let output_root = root.join("output");
    rebuild_index_locked(root, &output_root)?;
    Ok(html_path)
}

pub fn rebuild_index(root: &Path, output_root: &Path) -> Result<()> {
    ensure_directory(root)?;
    if output_root.exists() {
        ensure_directory(output_root)?;
    }
    let lock_path = root.join(".dashboard.lock");
    ensure_regular_or_missing(&lock_path)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .at(&lock_path)?;
    lock.lock_exclusive().map_err(|source| ScannerError::Io {
        path: lock_path.clone(),
        source,
    })?;
    let result = rebuild_index_locked(root, output_root);
    let _ = lock.unlock();
    result
}

pub fn prune_completed_reports(
    root: &Path,
    output_root: &Path,
    keep_per_target: usize,
) -> Result<()> {
    ensure_directory(root)?;
    if output_root.exists() {
        ensure_directory(output_root)?;
    }
    let lock_path = root.join(".dashboard.lock");
    ensure_regular_or_missing(&lock_path)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .at(&lock_path)?;
    lock.lock_exclusive().map_err(|source| ScannerError::Io {
        path: lock_path.clone(),
        source,
    })?;
    let result = prune_completed_reports_locked(output_root, keep_per_target)
        .and_then(|_| rebuild_index_locked(root, output_root));
    let _ = lock.unlock();
    result
}

fn prune_completed_reports_locked(output_root: &Path, keep_per_target: usize) -> Result<()> {
    let mut reports = verified_reports(output_root)?;
    reports.sort_by(|a, b| b.1.started_at.cmp(&a.1.started_at));
    let mut targets = std::collections::HashMap::new();
    for (run, report) in reports {
        let count = targets
            .entry((report.target_kind, report.target.clone()))
            .or_insert(0usize);
        *count += 1;
        if *count > keep_per_target {
            std::fs::remove_dir_all(&run).at(&run)?;
        }
    }
    Ok(())
}

fn rebuild_index_locked(root: &Path, output_root: &Path) -> Result<()> {
    let scans = completed_reports(output_root)?;
    let sessions = protocol_summaries(root, &root.join("protocol"))?;
    atomic_write(
        &root.join("index.html"),
        render_index(root, &scans, &sessions).as_bytes(),
    )
}

#[derive(Debug, Deserialize)]
struct StoredManifest {
    schema: String,
    run_id: String,
    status: ScanStatus,
    scan_root: String,
    scanner_version: String,
    ark_version: String,
    artifact_hashes: std::collections::BTreeMap<String, String>,
    attestation: RunAttestation,
    authentication: String,
}

fn completed_reports(output_root: &Path) -> Result<Vec<(PathBuf, Report)>> {
    let reports = verified_reports(output_root)?;
    let workspace = workspace_root(output_root);
    let index_href = if workspace == output_root {
        "../index.html"
    } else {
        "../../index.html"
    };
    let mut reports = reports
        .into_iter()
        .map(|(run, report)| {
            let html_path = run.join("report.html");
            atomic_write(
                &html_path,
                render_report_with_index(&report, index_href).as_bytes(),
            )?;
            Ok((html_path, report))
        })
        .collect::<Result<Vec<_>>>()?;
    reports.sort_by(|a, b| b.1.started_at.cmp(&a.1.started_at));
    let mut targets = std::collections::HashSet::new();
    reports.retain(|(_, report)| targets.insert((report.target_kind, report.target.clone())));
    Ok(reports)
}

fn verified_reports(output_root: &Path) -> Result<Vec<(PathBuf, Report)>> {
    let mut reports = Vec::new();
    let entries = match std::fs::read_dir(output_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(reports),
        Err(source) => {
            return Err(ScannerError::Io {
                path: output_root.into(),
                source,
            })
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| ScannerError::Io {
            path: output_root.into(),
            source,
        })?;
        if !entry
            .file_type()
            .is_ok_and(|kind| kind.is_dir() && !kind.is_symlink())
        {
            continue;
        }
        let run = entry.path();
        if !regular(&run.join("COMPLETE"))
            || !regular(&run.join("manifest.json"))
            || !regular(&run.join("report.json"))
        {
            continue;
        }
        let manifest_path = run.join("manifest.json");
        let Ok(manifest_bytes) = std::fs::read(&manifest_path) else {
            continue;
        };
        let Ok(manifest) = serde_json::from_slice::<StoredManifest>(&manifest_bytes) else {
            continue;
        };
        let report_path = run.join("report.json");
        let Ok(report_bytes) = std::fs::read(&report_path) else {
            continue;
        };
        let expected = format!("blake3:{}", blake3::hash(&report_bytes).to_hex());
        if manifest.schema != "patronus.security-scanner.manifest.v1"
            || manifest.artifact_hashes.get("report.json") != Some(&expected)
            || manifest.attestation.run_id != manifest.run_id
            || manifest.attestation.report_hash != expected
            || manifest.attestation.status != manifest.status
            || manifest.attestation.scan_root != manifest.scan_root
            || manifest.attestation.scanner_version != manifest.scanner_version
            || manifest.attestation.ark_version != manifest.ark_version
            || !verify_attestation(
                &workspace_root(output_root),
                &manifest.attestation,
                &manifest.authentication,
            )?
        {
            continue;
        }
        let Ok(report) = serde_json::from_slice::<Report>(&report_bytes) else {
            continue;
        };
        if report.schema != "patronus.security-scanner.report.v1"
            || report.run_id != manifest.run_id
            || report.status != manifest.status
            || run.file_name().and_then(|name| name.to_str()) != Some(report.run_id.as_str())
        {
            continue;
        }
        reports.push((run, report));
    }
    Ok(reports)
}

#[derive(Debug)]
struct ProtocolSummary {
    html_path: PathBuf,
    host: String,
    session_id: String,
    latest: DateTime<Utc>,
    status: String,
    events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolRecord {
    schema: String,
    event: ProtocolEvent,
    attestation: ProtocolAttestation,
    authentication: String,
}

fn protocol_summaries(root: &Path, protocol_root: &Path) -> Result<Vec<ProtocolSummary>> {
    let mut summaries = Vec::new();
    let entries = match std::fs::read_dir(protocol_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(summaries),
        Err(source) => {
            return Err(ScannerError::Io {
                path: protocol_root.into(),
                source,
            })
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| ScannerError::Io {
            path: protocol_root.into(),
            source,
        })?;
        let path = entry.path();
        if !regular(&path)
            || path
                .extension()
                .is_none_or(|extension| extension != "jsonl")
        {
            continue;
        }
        let Ok(records) = read_protocol_records(root, &path) else {
            continue;
        };
        let events = records
            .iter()
            .map(|record| record.event.clone())
            .collect::<Vec<_>>();
        let Some(last) = events.last() else { continue };
        let expected_name = format!(
            "{}.jsonl",
            blake3::hash(last.session_id.as_bytes()).to_hex()
        );
        if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
            continue;
        }
        let html_path = path.with_extension("html");
        atomic_write(&html_path, render_protocol(&events).as_bytes())?;
        summaries.push(ProtocolSummary {
            html_path,
            host: last.host.clone(),
            session_id: last.session_id.clone(),
            latest: last.timestamp,
            status: last.status.clone().unwrap_or_else(|| last.event.clone()),
            events: events.len(),
        });
    }
    summaries.sort_by(|a, b| b.latest.cmp(&a.latest));
    Ok(summaries)
}

fn read_protocol_records(root: &Path, path: &Path) -> Result<Vec<ProtocolRecord>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(ScannerError::Io {
                path: path.into(),
                source,
            })
        }
    };
    let mut records = Vec::new();
    let mut previous_record_hash = None;
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.at(path)?;
        let record: ProtocolRecord = serde_json::from_str(&line).map_err(|error| {
            ScannerError::Output(format!(
                "invalid protocol record {}:{}: {error}",
                path.display(),
                index + 1
            ))
        })?;
        record.event.validate()?;
        let expected_sequence = u64::try_from(index)
            .map_err(|_| ScannerError::Output("too many protocol events".into()))?;
        if record.schema != "patronus.protocol.record.v1"
            || record.attestation.sequence != expected_sequence
            || record.attestation.previous_record_hash != previous_record_hash
            || !verify_protocol_attestation(
                root,
                &record.event,
                &record.attestation,
                &record.authentication,
            )?
        {
            return Err(ScannerError::Output(format!(
                "unauthenticated protocol record {}:{}",
                path.display(),
                index + 1
            )));
        }
        previous_record_hash = Some(protocol_record_hash(&record)?);
        records.push(record);
    }
    Ok(records)
}

fn protocol_record_hash(record: &ProtocolRecord) -> Result<String> {
    let bytes =
        serde_json::to_vec(record).map_err(|error| ScannerError::Output(error.to_string()))?;
    Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

pub fn render_report(report: &Report) -> String {
    render_report_with_index(report, "../../index.html")
}

pub fn render_report_with_index(report: &Report, index_href: &str) -> String {
    let findings = if report.findings.is_empty() {
        "<p>No supported signals were projected from completed classifications.</p>".into()
    } else {
        let rows = report
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "<tr><td>{}</td><td>{}–{}</td><td>{}</td><td>{}</td><td>{:.3}</td></tr>",
                    html(&finding.path),
                    finding.line_start,
                    finding.line_end,
                    html(&finding.category),
                    html(&finding.label),
                    finding.confidence
                )
            })
            .collect::<String>();
        format!("<div class=\"table-wrap\"><table><thead><tr><th>Path</th><th>Lines</th><th>Category</th><th>Label</th><th>Confidence</th></tr></thead><tbody>{rows}</tbody></table></div>")
    };
    let skipped = if report.skipped.is_empty() {
        "<p>None.</p>".into()
    } else {
        let rows = report
            .skipped
            .iter()
            .map(|item| {
                format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    html(&item.reason),
                    item.count
                )
            })
            .collect::<String>();
        format!("<div class=\"table-wrap\"><table><thead><tr><th>Reason</th><th>Files</th></tr></thead><tbody>{rows}</tbody></table></div>")
    };
    let failures = if report.failures.is_empty() {
        "<p>None.</p>".into()
    } else {
        let rows = report
            .failures
            .iter()
            .map(|failure| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html(failure.path.as_deref().unwrap_or("")),
                    html(&failure.kind),
                    html(&failure.message)
                )
            })
            .collect::<String>();
        format!("<div class=\"table-wrap\"><table><thead><tr><th>Path</th><th>Kind</th><th>Message</th></tr></thead><tbody>{rows}</tbody></table></div>")
    };
    let disclaimer = report
        .scope_disclaimer
        .iter()
        .map(|item| format!("<li>{}</li>", html(item)))
        .collect::<String>();
    page(&format!("Patronus scan {}", html(&report.run_id)), &format!(
        "<main><p><a href=\"{}\">All Patronus activity</a></p><h1>Static scan</h1>\
         <p class=\"status {}\">{:?}</p><p>{}</p>\
         <dl><dt>Run</dt><dd>{}</dd><dt>Started</dt><dd>{}</dd><dt>Duration</dt><dd>{} ms</dd>\
         <dt>Target</dt><dd>{:?} / {}</dd><dt>Scanner</dt><dd>{}</dd><dt>Ark</dt><dd>{} ({}, {})</dd></dl>\
         <h2>Coverage</h2><p>{}/{} eligible files, {} skipped, {} failures, {} analyzed bytes of {} eligible bytes, {} chunks and {} classifications.</p>\
         <h2>Findings</h2><p>Findings are matched content signals, not confirmed vulnerabilities. Fixtures, examples, benchmarks and detector documentation can intentionally contain matches.</p>{}<h2>Skipped content</h2>{}<h2>Failures</h2>{}\
         <h2>Scope disclaimer</h2><p>This report covers supported Ark signals only. It does not establish the absence of:</p><ul>{}</ul></main>",
        html(index_href), status_class(report.status), report.status, html(&report.conclusion), html(&report.run_id),
        report.started_at.to_rfc3339(), report.duration_ms, report.target_kind, html(&report.target),
        html(&report.scanner_version), html(&report.ark_version), html(&report.ark_max_level),
        html(&report.ark_categories.iter().map(|category| match report.ark_category_levels.get(category) {
            Some(level) => format!("{category}: {level}"), None => category.clone(),
        }).collect::<Vec<_>>().join(", ")), report.coverage.analyzed_files, report.coverage.eligible_files,
        report.coverage.skipped_files, report.coverage.failures, report.coverage.analyzed_bytes,
        report.coverage.eligible_bytes, report.coverage.chunks, report.coverage.classifications,
        findings, skipped, failures, disclaimer
    ))
}

fn render_protocol(events: &[ProtocolEvent]) -> String {
    let title = events
        .first()
        .map(|event| format!("{} session", event.host))
        .unwrap_or_else(|| "Protocol session".into());
    let rows = events
        .iter()
        .map(|event| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                event.timestamp.to_rfc3339(),
                html(&event.event),
                html(event.direction.as_deref().unwrap_or("")),
                html(event.tool_name.as_deref().unwrap_or("")),
                html(event.status.as_deref().unwrap_or("")),
                html(event.scan_id.as_deref().unwrap_or("")),
                event.duration_ms.map(|value| value.to_string()).unwrap_or_default(),
                html(event.payload_hash.as_deref().unwrap_or(""))
            )
        })
        .collect::<String>();
    page(&title, &format!("<main><p><a href=\"../index.html\">All Patronus activity</a></p><h1>{}</h1><p>{} safe metadata events. Raw tool payloads are not recorded.</p><div class=\"table-wrap\"><table><thead><tr><th>Time</th><th>Event</th><th>Direction</th><th>Tool</th><th>Status</th><th>Scan</th><th>Duration ms</th><th>Payload hash</th></tr></thead><tbody>{}</tbody></table></div></main>", html(&title), events.len(), rows))
}

fn render_index(root: &Path, scans: &[(PathBuf, Report)], sessions: &[ProtocolSummary]) -> String {
    let scan_rows = scans.iter().map(|(path, report)| format!(
        "<tr><td><a class=\"mono\" href=\"{}\">{}</a><small>{}</small></td><td><span class=\"status {}\">{:?}</span></td><td>{}</td><td>{}/{}</td><td>{}</td></tr>",
        relative_href(root, path), html(&report.run_id), html(&report.target), status_class(report.status), report.status,
        report.started_at.format("%d %b %Y · %H:%M UTC"), report.coverage.analyzed_files, report.coverage.eligible_files,
        report.findings.len()
    )).collect::<String>();
    let session_rows = sessions.iter().map(|session| format!(
        "<tr><td><a href=\"{}\">{}</a></td><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
        relative_href(root, &session.html_path), html(&session.host), short_id(&session.session_id),
        session.latest.format("%d %b %Y · %H:%M UTC"), html(&session.status), session.events
    )).collect::<String>();
    let scan_rows = if scans.is_empty() {
        "<tr><td colspan=\"5\" class=\"empty\"><strong>No scans yet</strong>Completed scans will appear here with their coverage and findings.</td></tr>".into()
    } else {
        scan_rows
    };
    let session_rows = if sessions.is_empty() {
        "<tr><td colspan=\"5\" class=\"empty\"><strong>No session activity yet</strong>Your plugins will add activity as they check incoming text.</td></tr>".into()
    } else {
        session_rows
    };
    let findings: usize = scans.iter().map(|(_, report)| report.findings.len()).sum();
    let events: usize = sessions.iter().map(|session| session.events).sum();
    let commands = command_reference();
    let controls = include_str!("dashboard_controls.html");
    let onboarding = include_str!("dashboard_onboarding.html");
    let api_panel = include_str!("dashboard_api.html");
    let remote = remote_scan_rows(root);
    page_with_account(
        "Patronus activity",
        &format!(
            r##"<main>
      <div class="hero"><div><span class="eyebrow">Security overview</span><h1>Your security.<br><em>In one place.</em></h1><p>Review scan results and the text checks made by your agent plugins.</p></div><span class="pill">Stored on this device</span></div>
      <div class="dashboard-tabs">
      <input class="tab-radio" type="radio" name="dashboard-tab" id="tab-get-started"><label for="tab-get-started">Get started</label>
      <input class="tab-radio" type="radio" name="dashboard-tab" id="tab-overview" checked><label for="tab-overview">Activity</label>
      <input class="tab-radio" type="radio" name="dashboard-tab" id="tab-api"><label for="tab-api">API</label>
      <input class="tab-radio" type="radio" name="dashboard-tab" id="tab-policies"><label for="tab-policies">Policies</label>
      <input class="tab-radio" type="radio" name="dashboard-tab" id="tab-settings"><label for="tab-settings">Settings</label>
      <input class="tab-radio" type="radio" name="dashboard-tab" id="tab-commands"><label for="tab-commands">Help</label>
      <div class="tab-content activity-content"><div class="control-toolbar"><label>Search activity<input id="activity-search" type="search" placeholder="Host, category or scan"></label><label>Source<select id="activity-type"><option value="">All sources</option><option value="runtime">Plugin runtime</option><option value="file">Files &amp; repositories</option><option value="url">URL</option><option value="mcp">MCP server</option></select></label><label>Result<select id="activity-result"><option value="">All results</option><option value="approved">Approved</option><option value="findings">Findings</option><option value="failed">Failed</option><option value="incomplete">Incomplete</option><option value="pending">Pending</option></select></label></div>
      <div class="metrics"><div class="metric"><span>Scanned targets</span><strong>{}</strong></div><div class="metric"><span>Recorded findings</span><strong>{}</strong></div><div class="metric"><span>Agent sessions</span><strong>{}</strong></div><div class="metric"><span>Protocol events</span><strong>{}</strong></div></div>
      <section class="panel"><div class="panel-head"><div><h2>Static scans</h2><p>Latest result for each file or repository you explicitly checked</p></div><span class="pill">{} targets</span></div><div class="table-wrap"><table><thead><tr><th>Scan / target</th><th>Status</th><th>Started</th><th>Files checked</th><th>Findings</th></tr></thead><tbody>{}</tbody></table></div></section>
      <section class="panel"><div class="panel-head"><div><h2>Protocol sessions</h2><p>Input and result checks across your agents</p></div><span class="pill">{} sessions</span></div><div class="table-wrap"><table><thead><tr><th>Host</th><th>Session</th><th>Last activity</th><th>Last status</th><th>Events</th></tr></thead><tbody>{}</tbody></table></div></section>
      <section class="panel" data-scan-kind="remote"><div class="panel-head"><div><h2>URL &amp; MCP scans</h2><p>Explicit API checks. Public MCP metadata is inspected without executing tools.</p></div></div><div class="table-wrap"><table><thead><tr><th>Recorded</th><th>Type</th><th>Result</th><th>Categories</th><th>Findings</th><th>Latency</th></tr></thead><tbody>{remote}</tbody></table></div></section>
      </div>{onboarding}{api_panel}{controls}<div class="tab-content commands-content"><section class="panel"><div class="panel-head"><div><h2>Use Patronus in your chat</h2><p>Automatic text protection and explicit security scans</p></div></div><div class="settings"><div><h3>Ask for a scan</h3><p>Check this file, folder or repository.<br>Check this URL: https://example.org<br>Check this MCP server: its HTTPS URL or configuration file and server name.</p><p>URL and MCP scans use the API. Local stdio MCP processes are not started by the scanner.</p></div><div><h3>Control protection</h3><p><code>patronus on / off / status</code> controls the current chat. Pending scan receipts mean the source tool already ran; the agent retrieves the scan result instead of repeating the action.</p><p>Select the <strong>Get started</strong> tab or run <code>patronus-security-scanner onboarding</code>.</p></div></div></section><section class="panel"><div class="panel-head"><div><h2>Scanner commands</h2><p>Every command in this scanner build, with its description and options</p></div></div><div class="command-list">{commands}</div></section></div></div>
    </main>"##,
            scans.len(),
            findings,
            sessions.len(),
            events,
            scans.len(),
            scan_rows,
            sessions.len(),
            session_rows
        ),
        Some(root),
    )
}

fn command_reference() -> String {
    use clap::CommandFactory;
    fn visit(command: clap::Command, prefix: &str, result: &mut String) {
        let description = command
            .get_about()
            .map(|text| text.to_string())
            .unwrap_or_default();
        let help = command
            .clone()
            .bin_name(prefix)
            .render_long_help()
            .to_string();
        result.push_str(&format!("<details class=\"command\"><summary><code>{}</code><span>{}</span></summary><pre>{}</pre></details>", html(prefix), html(&description), html(&help)));
        let positional = if command.has_subcommands() {
            command
                .get_positionals()
                .map(|arg| format!(" &lt;{}&gt;", arg.get_id()))
                .collect::<String>()
        } else {
            String::new()
        };
        for subcommand in command
            .get_subcommands()
            .filter(|command| command.get_name() != "help")
        {
            let path = format!(
                "{prefix}{} {}",
                positional.replace("&lt;", "<").replace("&gt;", ">"),
                subcommand.get_name()
            );
            visit(subcommand.clone(), &path, result);
        }
    }
    let mut result = String::new();
    visit(
        crate::cli::Cli::command(),
        "patronus-security-scanner",
        &mut result,
    );
    result
}

fn regular(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

pub fn ensure_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ScannerError::Output(format!(
                "refusing non-directory or symlinked scanner path {}",
                path.display()
            )))
        }
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ScannerError::Io {
                path: path.into(),
                source,
            })
        }
    }
    std::fs::create_dir_all(path).at(path)?;
    let metadata = std::fs::symlink_metadata(path).at(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ScannerError::Output(format!(
            "refusing non-directory or symlinked scanner path {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_regular_or_missing(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(ScannerError::Output(format!(
                "refusing non-file or symlinked scanner path {}",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ScannerError::Io {
            path: path.into(),
            source,
        }),
    }
}

fn page(title: &str, body: &str) -> String {
    page_with_account(title, body, None)
}

fn page_with_account(title: &str, body: &str, root: Option<&Path>) -> String {
    use base64::Engine;
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let icon = encode(include_bytes!("../../plugins/codex/assets/icon.png"));
    let fonts = format!("@font-face{{font-family:Inter;font-style:normal;font-weight:100 900;font-display:swap;src:url(data:font/woff2;base64,{}) format('woff2')}}@font-face{{font-family:Manrope;font-style:normal;font-weight:200 800;font-display:swap;src:url(data:font/woff2;base64,{}) format('woff2')}}", encode(include_bytes!("assets/inter-latin.woff2")), encode(include_bytes!("assets/manrope-latin.woff2")));
    let account = root.and_then(|path| crate::auth::status(path).ok());
    let account_label = if account
        .as_ref()
        .is_some_and(|status| status.state == "signed_in")
    {
        "Account"
    } else {
        "Sign in"
    };
    let account_status = match account {
        Some(status) if status.state == "signed_in" => format!("<p>Signed in when this snapshot was saved. Token expiry: <strong>{}</strong>. Check current status with <code>patronus-security-scanner auth status --check</code>.</p>", chrono::DateTime::from_timestamp(status.expires_at.unwrap_or_default(), 0).map(|date| date.to_rfc3339()).unwrap_or_default()),
        Some(status) if status.state == "expired" => "<p>Your token has expired. Sign in again to use the API and MCP.</p>".into(),
        _ => "<p>Connect your Control Plane account for API and MCP access. Local scans work without signing in.</p>".into(),
    };
    let login = format!(
        r##"<aside id="sign-in" class="login-panel" aria-labelledby="login-heading"><div><a class="close-login" href="#" aria-label="Close sign in">Close</a><span class="eyebrow">Patronus account</span><h2 id="login-heading">Sign in to your scanner</h2>{account_status}<ol><li>Start the login in your terminal:<pre>patronus-security-scanner auth login</pre></li><li>Open the generated <a href="https://control.patronus.studio/" target="_blank" rel="noopener noreferrer">control.patronus.studio</a> link, sign in and authorize your CLI.</li><li>Copy the one-time code into the waiting terminal. The code expires after five minutes.</li></ol><p>Your shared API and MCP token is valid for <strong>14 days</strong>. Credentials stay in the CLI's private auth store.</p><pre>patronus-security-scanner auth status --check
patronus-security-scanner auth logout</pre><p>This HTML file is a snapshot. Login and logout refresh the shared index; reload it to see changes.</p></div></aside>"##
    );
    let login = if root.is_some() { login } else { String::new() };
    let account_link = if root.is_some() {
        format!(r##"<a class="button" href="#sign-in">{account_label}</a>"##)
    } else {
        String::new()
    };
    format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'"><link rel="icon" href="data:image/png;base64,{icon}"><title>{}</title><style>{fonts}{}</style></head><body><header><div class="topbar"><div class="brand"><img alt="Patronus" src="data:image/png;base64,{icon}"><span>Patronus<span style="font-weight:400;color:var(--muted)"> / Security</span></span></div><div class="header-actions"><span class="local">Local activity</span>{account_link}</div></div></header>{login}{}<footer>Patronus Security · This is a saved activity snapshot. Raw runtime payloads are not included in protocol logs.</footer></body></html>"##,
        html(title),
        include_str!("dashboard.css"),
        body
    )
}

fn html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn status_class(status: ScanStatus) -> &'static str {
    match status {
        ScanStatus::Clean => "clean",
        ScanStatus::Findings => "findings",
        ScanStatus::Incomplete => "incomplete",
        ScanStatus::Failed => "failed",
    }
}

fn relative_href(root: &Path, path: &Path) -> String {
    html(
        &path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/"),
    )
}

fn short_id(value: &str) -> String {
    html(&value.chars().take(16).collect::<String>())
}

fn remote_scan_rows(root: &Path) -> String {
    let Ok(entries) = std::fs::read_dir(root.join("remote-scans")) else {
        return "<tr><td colspan=\"6\">No URL or MCP scans yet. Ask your agent to check a public HTTPS URL or MCP server.</td></tr>".into();
    };
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    let mut rows = String::new();
    let mut targets = std::collections::HashSet::new();
    for path in paths.into_iter().rev().take(200) {
        if !std::fs::symlink_metadata(&path)
            .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink() && m.len() <= 1_048_576)
        {
            continue;
        }
        let Some(report) = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<crate::remote_scan::RemoteReport>(&b).ok())
        else {
            continue;
        };
        if report.schema != "patronus.remote.scan.v1"
            || !["url", "mcp"].contains(&report.kind.as_str())
            || !["CLEAN", "FINDINGS"].contains(&report.status.as_str())
            || !report.complete
        {
            continue;
        }
        if !report.target_id.is_empty() && !targets.insert(report.target_id.clone()) {
            continue;
        }
        let time = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .split('-')
            .next()
            .unwrap_or("");
        rows.push_str(&format!("<tr data-remote-kind=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{} ms</td></tr>",html(&report.kind),html(time),html(&report.kind),html(&report.status),html(&report.categories.join(", ")),report.findings.len(),report.duration_ms));
    }
    if rows.is_empty() {
        "<tr><td colspan=\"6\">No remote scan reports available.</td></tr>".into()
    } else {
        rows
    }
}
pub(crate) mod auth;
pub mod server;
