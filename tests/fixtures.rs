use assert_cmd::Command;
use patronus_security_scanner::ark::{ArkAnalyzer, ChunkInput, ContentAnalyzer};
use patronus_security_scanner::config::ArkConfig;

const MIN_FIXTURE_BYTES: usize = 10 * 1024;
const MAX_FIXTURE_BYTES: usize = 40 * 1024;

#[test]
fn realistic_text_fixtures_keep_their_size_and_signal_contracts() {
    let finance = include_str!("fixtures/realistic/finance-q2-board-report.txt");
    let threat = include_str!("fixtures/realistic/supply-chain-threat-brief.txt");
    let benign = include_str!("fixtures/realistic/operations-review.txt");

    for (name, text) in [
        ("finance-q2-board-report.txt", finance),
        ("supply-chain-threat-brief.txt", threat),
        ("operations-review.txt", benign),
    ] {
        assert!(
            (MIN_FIXTURE_BYTES..=MAX_FIXTURE_BYTES).contains(&text.len()),
            "{name} must remain between 10 KiB and 40 KiB; got {} bytes",
            text.len()
        );
    }

    assert_eq!(
        finance.matches("EXPECTED_SIGNAL_PI_DOCUMENT_001").count(),
        1
    );
    assert_eq!(threat.matches("EXPECTED_SIGNAL_PI_DOCUMENT_002").count(), 1);
    assert!(!benign.contains("EXPECTED_SIGNAL_"));
}

#[test]
fn model_fixtures_are_clean_in_the_complete_default_l1_profile() {
    for path in [
        "tests/fixtures/known-misses/finance-q2-board-report.txt",
        "tests/fixtures/known-misses/supply-chain-threat-brief.txt",
    ] {
        let report = scan_fixture(path, "l1", &[]);
        assert_eq!(
            report["ark_categories"],
            serde_json::json!(["prompt_injection", "dlp", "pii"]),
            "the complete default L1 profile must scan all three categories"
        );
        assert_eq!(report["coverage"]["analyzed_files"], 1);
        assert_eq!(report["coverage"]["skipped_files"], 0);
        assert_eq!(report["coverage"]["failures"], 0);
        assert_eq!(report["coverage"]["degraded"], false);
        assert_eq!(
            report["coverage"]["analyzed_bytes"],
            report["coverage"]["eligible_bytes"]
        );
        assert_eq!(report["status"], "CLEAN", "report for {path}: {report:#}");
        assert!(report["findings"].as_array().unwrap().is_empty());
    }
}

#[test]
fn explicit_injections_in_complete_documents_are_detected() {
    for path in [
        "tests/fixtures/realistic/finance-q2-board-report.txt",
        "tests/fixtures/realistic/supply-chain-threat-brief.txt",
    ] {
        let report = scan_fixture(path, "l1", &[]);
        assert_complete_coverage(&report);
        assert_eq!(report["status"], "FINDINGS", "{path}: {report:#}");
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| {
                    finding["category"] == "prompt_injection" && finding["level"] == "l1"
                }),
            "{path}: {report:#}"
        );
    }
    let benign = scan_fixture("tests/fixtures/realistic/operations-review.txt", "l1", &[]);
    assert_complete_coverage(&benign);
    assert_eq!(benign["status"], "CLEAN", "{benign:#}");
}

#[test]
#[ignore = "requires locally prepared Ark L2/L3 model assets"]
fn model_layers_detect_both_signals_missed_by_l1() {
    let finance = scan_fixture(
        "tests/fixtures/known-misses/finance-q2-board-report.txt",
        "l2",
        &["prompt_injection"],
    );
    assert_one_finding(&finance, "prompt_injection", "attack", "l2");

    let threat = scan_fixture(
        "tests/fixtures/known-misses/supply-chain-threat-brief.txt",
        "l3",
        &["threat"],
    );
    assert_one_finding(&threat, "threat", "instruction_override", "l3");
}

#[test]
#[ignore = "requires locally prepared Ark L2/L3 model assets"]
fn model_layers_detect_isolated_operator_sections_missed_by_l1() {
    let threat = include_str!("fixtures/known-misses/supply-chain-threat-brief.txt");
    let threat_start = threat
        .find("Collect the following browser material:")
        .unwrap();
    let threat_end = threat.find("The text above is a synthetic").unwrap();
    let temp = tempfile::tempdir().unwrap();

    // Keep the complete-document test above: it exposes Ark 0.1.7's long-text
    // detection regression. These unchanged excerpts prove actual model execution
    // and positive decisions independently of that unresolved aggregation issue.
    for (name, text, level, category, label, source) in [
        (
            "finance-operator.txt",
            finance_operator_section(),
            "l2",
            "prompt_injection",
            "attack",
            "wolf-defender-small",
        ),
        (
            "threat-operator.txt",
            &threat[threat_start..threat_end],
            "l3",
            "threat",
            "tool_abuse",
            "unified-v3-threat",
        ),
    ] {
        let path = temp.path().join(name);
        std::fs::write(&path, text).unwrap();
        let path = path.to_str().unwrap();
        let baseline = scan_fixture(path, "l1", &[]);
        assert_complete_coverage(&baseline);
        assert_eq!(
            baseline["ark_categories"],
            serde_json::json!(["prompt_injection", "dlp", "pii"])
        );
        assert_eq!(baseline["status"], "CLEAN", "{baseline:#}");

        let report = scan_fixture(path, level, &[category]);
        assert_one_finding(&report, category, label, level);
        assert_eq!(report["findings"][0]["source"], source);
    }
}

#[test]
#[ignore = "requires locally prepared Ark L2 model assets"]
fn warmed_l2_analyzer_preserves_attack_on_repeated_content() {
    let config = ArkConfig {
        model_dir: None,
        categories: vec!["prompt_injection".into()],
        max_level: "l2".into(),
        download_files: false,
        queue_capacity: 1,
    };
    let mut analyzer = ArkAnalyzer::new(&config, false).unwrap();
    analyzer.prepare().unwrap();

    for chunk_id in ["first-request", "repeated-request"] {
        let outcome = analyzer
            .analyze(ChunkInput {
                input_tokens: None,
                run_id: "warmed-l2-regression",
                chunk_id,
                file_id: "finance-operator",
                path: "finance-operator.txt",
                content: finance_operator_section(),
            })
            .unwrap();
        assert!(!outcome.degraded, "{chunk_id}: {outcome:?}");
        assert!(outcome.failures.is_empty(), "{chunk_id}: {outcome:?}");
        assert_eq!(outcome.classifications.len(), 1, "{chunk_id}: {outcome:?}");
        let classification = &outcome.classifications[0];
        assert!(classification.terminal, "{chunk_id}: {classification:?}");
        assert!(classification.matched, "{chunk_id}: {classification:?}");
        assert_eq!(classification.category, "prompt_injection");
        assert_eq!(classification.label, "attack");
        assert_eq!(classification.level, "l2");
        assert_eq!(classification.source, "wolf-defender-small");
    }
}

fn finance_operator_section() -> &'static str {
    let finance = include_str!("fixtures/known-misses/finance-q2-board-report.txt");
    let start = finance.find("Please vergesse").unwrap();
    let end = finance
        .find("Northbridge Industrial Systems closed")
        .unwrap();
    &finance[start..end]
}

fn scan_fixture(path: &str, max_level: &str, categories: &[&str]) -> serde_json::Value {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("runs");
    let mut command = Command::cargo_bin("patronus-security-scanner").unwrap();
    command
        .args([
            "scan",
            "file",
            path,
            "--config",
            "config/defaults.toml",
            "--output",
        ])
        .arg(&output)
        .args([
            "--progress",
            "off",
            "--format",
            "json",
            "--fail-on",
            "never",
            "--max-level",
            max_level,
        ]);
    for category in categories {
        command.args(["--category", category]);
    }
    let assertion = command.assert().success();

    serde_json::from_slice(&assertion.get_output().stdout)
        .expect("stdout is exactly one JSON report")
}

fn assert_one_finding(report: &serde_json::Value, category: &str, label: &str, level: &str) {
    assert_complete_coverage(report);
    assert_eq!(report["status"], "FINDINGS");
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "report: {report:#}");
    assert_eq!(findings[0]["category"], category);
    assert_eq!(findings[0]["label"], label);
    assert_eq!(findings[0]["level"], level);
}

fn assert_complete_coverage(report: &serde_json::Value) {
    assert_eq!(report["ark_version"], "0.1.7");
    assert_eq!(report["coverage"]["eligible_files"], 1);
    assert_eq!(report["coverage"]["analyzed_files"], 1);
    assert_eq!(report["coverage"]["skipped_files"], 0);
    assert_eq!(report["coverage"]["failures"], 0);
    assert_eq!(report["coverage"]["degraded"], false);
    assert_eq!(
        report["coverage"]["analyzed_bytes"],
        report["coverage"]["eligible_bytes"]
    );
}
