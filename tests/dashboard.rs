use chrono::{TimeZone, Utc};
use patronus_security_scanner::dashboard::{
    append_protocol_event, attest_run, persist_protocol_event, prune_completed_reports,
    rebuild_index, render_report, ProtocolEvent,
};
use patronus_security_scanner::report::{Coverage, Finding, Report, ScanStatus};
use patronus_security_scanner::target::TargetKind;

#[test]
fn report_html_is_self_contained_and_escapes_report_values() {
    let report = sample_report();
    let html = render_report(&report);
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("default-src 'none'"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("class=\"table-wrap\""));
    assert!(html.contains("matched content signals, not confirmed vulnerabilities"));
    assert!(!html.contains("<script>"));
    assert!(!html.contains("http://"));
    assert!(!html.contains("https://"));
}

#[test]
fn protocol_append_writes_safe_session_html_and_shared_index() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(".patronus-security-scanner");
    let event = ProtocolEvent {
        schema: "patronus.protocol.event.v1".into(),
        timestamp: Utc.with_ymd_and_hms(2026, 9, 4, 8, 0, 0).unwrap(),
        host: "codex".into(),
        session_id: format!("blake3:{}", "a".repeat(64)),
        event: "scan_completed".into(),
        direction: Some("response".into()),
        tool_name: Some("read_file".into()),
        scan_id: Some("scan-1".into()),
        status: Some("pending".into()),
        duration_ms: Some(4),
        payload_hash: Some(format!("blake3:{}", "b".repeat(64))),
    };
    let session_html = append_protocol_event(&root, &event).unwrap();
    assert!(session_html.is_file());
    let session = std::fs::read_to_string(session_html).unwrap();
    assert!(session.contains("pending"));
    assert!(!session.contains("payload_hash"));
    let index = std::fs::read_to_string(root.join("index.html")).unwrap();
    assert!(index.contains("Protocol sessions"));
    assert!(index.contains("codex"));
    assert!(index.contains("for=\"tab-get-started\">Setup"));
    assert!(index.contains("for=\"tab-api\">Scan"));
    assert!(index.contains("id=\"scan-form\""));
    assert!(index.contains("id=\"account-action\" href=\"#sign-in\">Connect Control Plane"));
    assert!(index.contains("id=\"upgrade-cta\" hidden"));
    let jsonl = std::fs::read_dir(root.join("protocol"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .unwrap();
    let stored = std::fs::read_to_string(jsonl).unwrap();
    assert!(!stored.contains("arguments"));
    assert!(!stored.contains("result"));

    let before = std::fs::read(root.join("index.html")).unwrap();
    let mut next = event.clone();
    next.status = Some("approved".into());
    let journal = persist_protocol_event(&root, &next, false).unwrap();
    assert_eq!(std::fs::read_to_string(journal).unwrap().lines().count(), 2);
    assert_eq!(std::fs::read(root.join("index.html")).unwrap(), before);
    rebuild_index(&root, &root.join("output")).unwrap();
    assert!(std::fs::read_to_string(root.join("index.html"))
        .unwrap()
        .contains("approved"));
}

#[test]
fn protocol_rejects_unknown_or_path_shaped_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let mut event = ProtocolEvent {
        schema: "patronus.protocol.event.v1".into(),
        timestamp: Utc::now(),
        host: "codex".into(),
        session_id: "../../escape".into(),
        event: "scan".into(),
        direction: None,
        tool_name: None,
        scan_id: None,
        status: None,
        duration_ms: None,
        payload_hash: None,
    };
    assert!(append_protocol_event(dir.path(), &event).is_err());
    event.session_id = format!("blake3:{}", "a".repeat(64));
    event.schema = "unknown".into();
    assert!(append_protocol_event(dir.path(), &event).is_err());
}

#[test]
fn corrupt_old_protocol_does_not_block_new_dashboard_events() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(".patronus-security-scanner");
    std::fs::create_dir_all(root.join("protocol")).unwrap();
    std::fs::write(root.join("protocol/broken.jsonl"), "not json\n").unwrap();
    let event = ProtocolEvent {
        schema: "patronus.protocol.event.v1".into(),
        timestamp: Utc::now(),
        host: "deepseek".into(),
        session_id: format!("sha256:{}", "a".repeat(64)),
        event: "scan_completed".into(),
        direction: Some("response".into()),
        tool_name: Some("document".into()),
        scan_id: Some("scan-2".into()),
        status: Some("approved".into()),
        duration_ms: Some(8),
        payload_hash: Some(format!("sha256:{}", "b".repeat(64))),
    };
    append_protocol_event(&root, &event).unwrap();
    let index = std::fs::read_to_string(root.join("index.html")).unwrap();
    assert!(index.contains("deepseek"));
    assert!(!index.contains("not json"));
}

#[test]
fn remote_activity_shows_only_the_latest_result_for_each_target() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(".patronus-security-scanner");
    let remote = root.join("remote-scans");
    std::fs::create_dir_all(&remote).unwrap();
    let report = |duration_ms| {
        serde_json::json!({
            "schema": "patronus.remote.scan.v1",
            "kind": "url",
            "provider": "api",
            "status": "CLEAN",
            "approved": true,
            "complete": true,
            "categories": ["injection"],
            "findings": [],
            "jobs": 1,
            "duration_ms": duration_ms,
            "target_id": format!("blake3:{}", "a".repeat(64)),
            "scanned_at": "2026-09-08T10:00:00Z"
        })
    };
    std::fs::write(
        remote.join("20260908T100000Z-first.json"),
        serde_json::to_vec(&report(11)).unwrap(),
    )
    .unwrap();
    std::fs::write(
        remote.join("20260908T110000Z-second.json"),
        serde_json::to_vec(&report(22)).unwrap(),
    )
    .unwrap();

    rebuild_index(&root, &root.join("output")).unwrap();
    let index = std::fs::read_to_string(root.join("index.html")).unwrap();
    assert!(index.contains("22 ms"));
    assert!(!index.contains("11 ms"));
}

#[test]
fn forged_or_tampered_protocol_is_not_rendered_or_extended() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(".patronus-security-scanner");
    let protocol = root.join("protocol");
    std::fs::create_dir_all(&protocol).unwrap();
    let event = ProtocolEvent {
        schema: "patronus.protocol.event.v1".into(),
        timestamp: Utc::now(),
        host: "codex".into(),
        session_id: format!("sha256:{}", "c".repeat(64)),
        event: "scan_completed".into(),
        direction: Some("response".into()),
        tool_name: Some("read_file".into()),
        scan_id: Some("forged-scan".into()),
        status: Some("approved".into()),
        duration_ms: Some(1),
        payload_hash: Some(format!("sha256:{}", "d".repeat(64))),
    };
    std::fs::write(
        protocol.join("attacker.jsonl"),
        format!("{}\n", serde_json::to_string(&event).unwrap()),
    )
    .unwrap();

    append_protocol_event(&root, &event).unwrap();
    let legitimate = protocol.join(format!(
        "{}.jsonl",
        blake3::hash(event.session_id.as_bytes()).to_hex()
    ));
    let mut record: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&legitimate).unwrap().trim()).unwrap();
    record["event"]["status"] = serde_json::Value::String("dangerous".into());
    std::fs::write(
        &legitimate,
        format!("{}\n", serde_json::to_string(&record).unwrap()),
    )
    .unwrap();

    rebuild_index(&root, &root.join("output")).unwrap();
    let index = std::fs::read_to_string(root.join("index.html")).unwrap();
    assert!(!index.contains("forged-scan"));
    assert!(!index.contains("dangerous"));
    assert!(append_protocol_event(&root, &event).is_err());
}

#[test]
fn dashboard_regenerates_report_html_and_rejects_tampered_report_json() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(".patronus-security-scanner");
    let output = root.join("output");
    let run = output.join("run-1");
    std::fs::create_dir_all(&run).unwrap();
    let report = sample_report();
    let report_bytes = serde_json::to_vec_pretty(&report).unwrap();
    std::fs::write(run.join("report.json"), &report_bytes).unwrap();
    std::fs::write(run.join("report.html"), "<script>owned()</script>").unwrap();
    std::fs::write(run.join("COMPLETE"), "complete").unwrap();
    let report_hash = format!("blake3:{}", blake3::hash(&report_bytes).to_hex());
    let (attestation, authentication) = attest_run(
        &root,
        "run-1",
        dir.path(),
        &report_hash,
        ScanStatus::Findings,
    )
    .unwrap();
    let scan_root = attestation.scan_root.clone();
    let manifest = serde_json::json!({
        "schema": "patronus.security-scanner.manifest.v1",
        "run_id": "run-1",
        "status": "FINDINGS",
        "scan_root": scan_root,
        "scanner_version": env!("CARGO_PKG_VERSION"),
        "ark_version": "0.1.7",
        "artifact_hashes": {
            "report.json": report_hash
        },
        "attestation": attestation,
        "authentication": authentication
    });
    std::fs::write(
        run.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    rebuild_index(&root, &output).unwrap();
    let generated = std::fs::read_to_string(run.join("report.html")).unwrap();
    assert!(!generated.contains("<script>"));
    assert!(generated.contains("Static scan"));
    assert!(std::fs::read_to_string(root.join("index.html"))
        .unwrap()
        .contains("run-1"));

    let newer_run = output.join("run-2");
    std::fs::create_dir_all(&newer_run).unwrap();
    let mut newer = sample_report();
    newer.run_id = "run-2".into();
    newer.started_at = Utc.with_ymd_and_hms(2026, 9, 4, 9, 0, 0).unwrap();
    newer.completed_at = Utc.with_ymd_and_hms(2026, 9, 4, 9, 0, 1).unwrap();
    newer.report_path = "output/run-2/report.md".into();
    let newer_bytes = serde_json::to_vec_pretty(&newer).unwrap();
    std::fs::write(newer_run.join("report.json"), &newer_bytes).unwrap();
    std::fs::write(newer_run.join("COMPLETE"), "complete").unwrap();
    let newer_hash = format!("blake3:{}", blake3::hash(&newer_bytes).to_hex());
    let (newer_attestation, newer_authentication) = attest_run(
        &root,
        "run-2",
        dir.path(),
        &newer_hash,
        ScanStatus::Findings,
    )
    .unwrap();
    std::fs::write(
        newer_run.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "patronus.security-scanner.manifest.v1",
            "run_id": "run-2",
            "status": "FINDINGS",
            "scan_root": newer_attestation.scan_root.clone(),
            "scanner_version": env!("CARGO_PKG_VERSION"),
            "ark_version": "0.1.7",
            "artifact_hashes": {"report.json": newer_hash},
            "attestation": newer_attestation,
            "authentication": newer_authentication
        }))
        .unwrap(),
    )
    .unwrap();
    rebuild_index(&root, &output).unwrap();
    let latest_index = std::fs::read_to_string(root.join("index.html")).unwrap();
    assert!(latest_index.contains("run-2"));
    assert!(!latest_index.contains("run-1"));

    let replay_root = dir.path().join("replayed/.patronus-security-scanner");
    let replay_run = replay_root.join("output/run-1");
    std::fs::create_dir_all(&replay_run).unwrap();
    for name in ["report.json", "report.html", "manifest.json", "COMPLETE"] {
        std::fs::copy(run.join(name), replay_run.join(name)).unwrap();
    }
    rebuild_index(&replay_root, &replay_root.join("output")).unwrap();
    assert!(!std::fs::read_to_string(replay_root.join("index.html"))
        .unwrap()
        .contains("run-1"));

    std::fs::write(run.join("report.json"), b"{}").unwrap();
    rebuild_index(&root, &output).unwrap();
    assert!(!std::fs::read_to_string(root.join("index.html"))
        .unwrap()
        .contains("run-1"));
}

#[test]
fn completed_report_retention_keeps_two_per_target() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(".patronus-security-scanner");
    let output = root.join("output");
    std::fs::create_dir_all(&output).unwrap();

    for (index, hour) in [(1, 8), (2, 9), (3, 10)] {
        let mut report = sample_report();
        report.run_id = format!("run-{index}");
        report.started_at = Utc.with_ymd_and_hms(2026, 9, 4, hour, 0, 0).unwrap();
        report.completed_at = Utc.with_ymd_and_hms(2026, 9, 4, hour, 0, 1).unwrap();
        write_authenticated_report(&root, &output, &report);
    }
    std::fs::create_dir_all(output.join("unverified")).unwrap();

    prune_completed_reports(&root, &output, 2).unwrap();

    assert!(!output.join("run-1").exists());
    assert!(output.join("run-2").is_dir());
    assert!(output.join("run-3").is_dir());
    assert!(output.join("unverified").is_dir());
}

#[cfg(unix)]
#[test]
fn protocol_root_symlink_cannot_escape_the_workspace() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    symlink(&outside, workspace.join(".patronus-security-scanner")).unwrap();
    let event = ProtocolEvent {
        schema: "patronus.protocol.event.v1".into(),
        timestamp: Utc::now(),
        host: "codex".into(),
        session_id: format!("sha256:{}", "a".repeat(64)),
        event: "scan_completed".into(),
        direction: Some("response".into()),
        tool_name: Some("read_file".into()),
        scan_id: Some("scan-escape".into()),
        status: Some("pending".into()),
        duration_ms: Some(1),
        payload_hash: Some(format!("sha256:{}", "b".repeat(64))),
    };
    assert!(append_protocol_event(&workspace.join(".patronus-security-scanner"), &event).is_err());
    assert!(!outside.join("index.html").exists());
    assert!(!outside.join("protocol").exists());
}

fn sample_report() -> Report {
    Report {
        schema: "patronus.security-scanner.report.v1".into(),
        run_id: "run-1".into(),
        status: ScanStatus::Findings,
        conclusion: "Review <script>alert(1)</script>".into(),
        target_kind: TargetKind::Repo,
        target: ".".into(),
        scanner_version: env!("CARGO_PKG_VERSION").into(),
        ark_version: "0.1.7".into(),
        ark_categories: vec!["prompt_injection".into()],
        ark_max_level: "l1".into(),
        ark_category_levels: Default::default(),
        started_at: Utc.with_ymd_and_hms(2026, 9, 4, 8, 0, 0).unwrap(),
        completed_at: Utc.with_ymd_and_hms(2026, 9, 4, 8, 0, 1).unwrap(),
        duration_ms: 1000,
        coverage: Coverage {
            discovered_files: 1,
            eligible_files: 1,
            analyzed_files: 1,
            skipped_files: 0,
            eligible_bytes: 10,
            analyzed_bytes: 10,
            chunks: 1,
            classifications: 1,
            failures: 0,
            degraded: false,
        },
        findings: vec![Finding {
            finding_id: "id".into(),
            path: "&file.txt".into(),
            category: "prompt_injection".into(),
            label: "INJECTION".into(),
            confidence: 1.0,
            level: "l1".into(),
            source: "ark".into(),
            line_start: 1,
            line_end: 1,
            original_byte_start: 0,
            original_byte_end: 1,
        }],
        skipped: vec![],
        failures: vec![],
        report_path: "output/run-1/report.md".into(),
        scope_disclaimer: vec![],
    }
}

fn write_authenticated_report(root: &std::path::Path, output: &std::path::Path, report: &Report) {
    let run = output.join(&report.run_id);
    std::fs::create_dir_all(&run).unwrap();
    let report_bytes = serde_json::to_vec_pretty(report).unwrap();
    std::fs::write(run.join("report.json"), &report_bytes).unwrap();
    std::fs::write(run.join("COMPLETE"), "complete").unwrap();
    let report_hash = format!("blake3:{}", blake3::hash(&report_bytes).to_hex());
    let (attestation, authentication) = attest_run(
        root,
        &report.run_id,
        root.parent().unwrap(),
        &report_hash,
        report.status,
    )
    .unwrap();
    let manifest = serde_json::json!({
        "schema": "patronus.security-scanner.manifest.v1",
        "run_id": report.run_id,
        "status": report.status,
        "scan_root": attestation.scan_root.clone(),
        "scanner_version": attestation.scanner_version.clone(),
        "ark_version": attestation.ark_version.clone(),
        "artifact_hashes": {"report.json": report_hash},
        "attestation": attestation,
        "authentication": authentication
    });
    std::fs::write(
        run.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}
