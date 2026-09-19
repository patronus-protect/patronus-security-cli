use chrono::Utc;
use patronus_security_scanner::ark::{Evidence, FinalClassification, ScanNotice};
use patronus_security_scanner::chunk::ChunkRecord;
use patronus_security_scanner::cli::FailOn;
use patronus_security_scanner::discovery::FileRecord;
use patronus_security_scanner::report::{
    build_report, exit_code, markdown, terminal_summary, ReportBuilder, ScanStatus,
};
use patronus_security_scanner::target::TargetKind;

#[test]
fn every_evidence_becomes_one_deduplicated_finding() {
    let chunk = sample_chunk();
    let classification = sample_classification();
    let mut builder = ReportBuilder::new();
    builder.chunk_count = 2;
    builder.classification(&classification, &chunk);
    builder.classification(&classification, &chunk);
    let files = vec![sample_file(true, None)];
    let report = build_report(
        "run".into(),
        TargetKind::File,
        "/tmp/example.txt".into(),
        Utc::now(),
        10,
        &files,
        1,
        4,
        1,
        4,
        vec!["dlp".into()],
        "l1".into(),
        builder,
        "run/report.md".into(),
    );
    assert_eq!(report.status, ScanStatus::Findings);
    assert_eq!(report.target, "/tmp/example.txt");
    assert_eq!(report.findings.len(), 2);
    let labels = report
        .findings
        .iter()
        .map(|finding| finding.label.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(labels, std::collections::HashSet::from(["EMAIL", "PHONE"]));
    assert_eq!(report.coverage.classifications, 2);
    let email = report
        .findings
        .iter()
        .find(|finding| finding.label == "EMAIL")
        .unwrap();
    assert_eq!((email.original_byte_start, email.original_byte_end), (1, 2));
    assert_eq!(email.confidence, 0.81);
    let phone = report
        .findings
        .iter()
        .find(|finding| finding.label == "PHONE")
        .unwrap();
    assert_eq!((phone.original_byte_start, phone.original_byte_end), (2, 4));
    assert_eq!(phone.confidence, 0.72);
    assert_eq!(exit_code(report.status, FailOn::Findings), 1);
    assert_eq!(exit_code(report.status, FailOn::Never), 0);
}

#[test]
fn any_skip_forces_incomplete_ahead_of_reassurance() {
    let builder = ReportBuilder::new();
    let files = vec![sample_file(false, Some("binary".into()))];
    let report = build_report(
        "run".into(),
        TargetKind::File,
        "/tmp/example.txt".into(),
        Utc::now(),
        10,
        &files,
        1,
        4,
        0,
        0,
        vec!["dlp".into()],
        "l1".into(),
        builder,
        "run/report.md".into(),
    );
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(exit_code(report.status, FailOn::Incomplete), 3);
}

#[test]
fn local_fallback_after_api_usage_limit_is_reported_once_without_failing_the_scan() {
    let mut builder = ReportBuilder::new();
    builder.notice(&ScanNotice::api_usage_limit("local", Some(600)));
    builder.notice(&ScanNotice::api_usage_limit("local", Some(600)));
    let files = vec![sample_file(true, None)];
    let report = build_report(
        "run".into(),
        TargetKind::File,
        "/tmp/example.txt".into(),
        Utc::now(),
        10,
        &files,
        1,
        4,
        1,
        4,
        vec!["dlp".into()],
        "l1".into(),
        builder,
        "run/report.md".into(),
    );
    assert_eq!(
        report.notices,
        vec![ScanNotice::api_usage_limit("local", Some(600))]
    );
    assert_ne!(report.status, ScanStatus::Failed);
    for text in [terminal_summary(&report), markdown(&report)] {
        assert!(text.contains("API usage limit reached"), "{text}");
        assert!(text.contains("scanned locally"), "{text}");
        assert!(text.contains("600"), "{text}");
    }
}

fn sample_classification() -> FinalClassification {
    FinalClassification {
        schema: "patronus.security-scanner.classification.v1",
        run_id: "run".into(),
        chunk_id: "chunk".into(),
        file_id: "file".into(),
        path: "a.txt".into(),
        category: "dlp".into(),
        source: "native:dlp".into(),
        level: "l1".into(),
        terminal: true,
        matched: true,
        label: "credential".into(),
        confidence: 0.9,
        decision: None,
        evidence: vec![
            Evidence {
                start: 1,
                end: 2,
                label: "EMAIL".into(),
                confidence: 0.81,
                line_start: 1,
                line_end: 1,
                text: None,
            },
            Evidence {
                start: 2,
                end: 4,
                label: "PHONE".into(),
                confidence: 0.72,
                line_start: 1,
                line_end: 1,
                text: None,
            },
        ],
        duration_ms: 1,
        warnings: vec![],
    }
}

fn sample_chunk() -> ChunkRecord {
    ChunkRecord {
        schema: "patronus.security-scanner.chunk.v1",
        chunk_id: "chunk".into(),
        file_id: "file".into(),
        path: "a.txt".into(),
        chunk_index: 0,
        content_hash: "blake3:x".into(),
        original_byte_start: 0,
        original_byte_end: 4,
        decoded_char_start: 0,
        decoded_char_end: 4,
        line_start: 1,
        line_end: 1,
        input_bytes: 4,
        decoded_byte_start: 0,
        decoded_byte_end: 4,
    }
}

fn sample_file(eligible: bool, reason: Option<String>) -> FileRecord {
    FileRecord {
        schema: "patronus.security-scanner.file.v1",
        path: "a.txt".into(),
        size_bytes: 4,
        eligible,
        skip_reason: reason,
        absolute_path: "a.txt".into(),
    }
}
