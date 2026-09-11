use assert_cmd::Command;
use serde_json::Value;
fn cli(root: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("patronus-security-scanner").unwrap();
    c.env("PATRONUS_DATA_DIR", root);
    c
}
#[test]
fn setup_is_resumable_and_check_is_real_and_persisted() {
    let root = tempfile::tempdir().unwrap();
    let before = cli(root.path())
        .args(["onboarding", "--status", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let before: Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(before["configuration_verified"], false);
    assert_eq!(before["auth"]["state"], "signed_out");
    let result = cli(root.path())
        .args(["onboarding", "--check", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(result["detected"], true);
    assert_eq!(result["provider"], "local");
    assert_eq!(result.as_object().unwrap().len(), 2);
    assert!(result.get("cold_ms").is_none());
    assert!(result.get("warm_ms").is_none());
    for _ in 0..2 {
        let after = cli(root.path())
            .args(["onboarding", "--status", "--format", "json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let after: Value = serde_json::from_slice(&after).unwrap();
        assert_eq!(after["configuration_verified"], true);
        assert_eq!(after["check"], result);
    }
}
#[test]
fn no_interactive_setup_and_remote_scans_require_authentication() {
    let root = tempfile::tempdir().unwrap();
    cli(root.path())
        .arg("onboarding")
        .assert()
        .failure()
        .stderr(predicates::str::contains("interactive terminal"));
    for kind in ["url", "mcp"] {
        let output = cli(root.path())
            .args(["scan", kind, "https://example.org/", "--format", "json"])
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();
        let output: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(output["schema"], "patronus.remote.scan.error.v1");
        assert_eq!(output["kind"], kind);
        assert_eq!(output["provider"], "api");
        assert_eq!(output["reason"], "authentication_missing");
    }
    assert!(!root.path().join("auth/credentials.json").exists());
}
#[test]
fn dashboard_has_setup_and_remote_activity_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("remote-scans");
    std::fs::create_dir(&folder).unwrap();
    let report = serde_json::json!({"schema":"patronus.remote.scan.v1","kind":"mcp","provider":"api","status":"CLEAN","approved":true,"complete":true,"categories":["injection","pii"],"findings":[],"jobs":1,"duration_ms":24});
    std::fs::write(
        folder.join("20260908T120000Z-test.json"),
        report.to_string(),
    )
    .unwrap();
    for _ in 0..2 {
        cli(root.path())
            .args(["protocol", "render"])
            .assert()
            .success();
        let html = std::fs::read_to_string(root.path().join("index.html")).unwrap();
        assert!(html.contains("Set up Patronus"));
        assert!(html.contains("URL &amp; MCP scans"));
        assert!(html.contains("24 ms"));
        assert!(html.contains(">Help</label>"));
        assert!(!html.contains("Access Rules"));
    }
}
