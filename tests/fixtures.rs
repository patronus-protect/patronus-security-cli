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
            serde_json::json!([
                "pii",
                "dlp",
                "injection",
                "jailbreak",
                "prompt_extraction",
                "tool_poisoning",
                "exfiltration"
            ]),
            "the complete default L1 profile scans Ark Core's default categories"
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
                .any(|finding| { finding["category"] == "injection" && finding["level"] == "l1" }),
            "{path}: {report:#}"
        );
    }
    let benign = scan_fixture("tests/fixtures/realistic/operations-review.txt", "l1", &[]);
    assert_complete_coverage(&benign);
    assert_eq!(benign["status"], "CLEAN", "{benign:#}");
}

#[test]
#[ignore = "requires a prepared Wolf Defender Edge bundle in PATRONUS_TEST_MODEL_DIR"]
fn wolf_edge_detects_the_injection_document_l1_misses() {
    let finance = scan_fixture(
        "tests/fixtures/known-misses/finance-q2-board-report.txt",
        "l3",
        &["injection"],
    );
    assert_one_finding(&finance, "injection", "injection", "l3");
    assert_eq!(finance["findings"][0]["source"], "wolf");
}

#[test]
#[ignore = "requires a prepared Wolf Defender Edge bundle in PATRONUS_TEST_MODEL_DIR"]
fn wolf_edge_answers_the_isolated_operator_section() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("finance-operator.txt");
    std::fs::write(&path, finance_operator_section()).unwrap();
    let path = path.to_str().unwrap();
    let report = scan_fixture(path, "l3", &["injection"]);
    assert_complete_coverage(&report);
    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings.iter().any(|f| f["category"] == "injection"),
        "rules, L1 model or Wolf must flag the operator section: {report:#}"
    );
}

#[test]
#[ignore = "requires a prepared Wolf Defender Edge bundle in PATRONUS_TEST_MODEL_DIR"]
fn warmed_wolf_analyzer_preserves_attack_on_repeated_content() {
    let config = ArkConfig {
        model_dir: std::env::var_os("PATRONUS_TEST_MODEL_DIR").map(Into::into),
        categories: vec!["injection".into()],
        max_level: "l3".into(),
        download_files: false,
        queue_capacity: 1,
    };
    let mut analyzer = ArkAnalyzer::new(&config, false).unwrap();
    analyzer.prepare().unwrap();

    for chunk_id in ["first-request", "repeated-request"] {
        let outcome = analyzer
            .analyze(ChunkInput {
                input_tokens: None,
                run_id: "warmed-wolf-regression",
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
        assert_eq!(classification.category, "injection");
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
    // Model tests take their prepared models from PATRONUS_TEST_MODEL_DIR.
    let config = match std::env::var("PATRONUS_TEST_MODEL_DIR") {
        Ok(dir) => {
            let path = temp.path().join("config.toml");
            std::fs::write(
                &path,
                std::fs::read_to_string("config/defaults.toml")
                    .unwrap()
                    .replace("[ark]\n", &format!("[ark]\nmodel_dir = {dir:?}\n")),
            )
            .unwrap();
            path.to_string_lossy().into_owned()
        }
        Err(_) => "config/defaults.toml".into(),
    };
    let mut command = Command::cargo_bin("patronus-security-scanner").unwrap();
    command
        .args(["scan", "file", path, "--config", &config, "--output"])
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
    assert_eq!(report["ark_version"], "0.1.18");
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
