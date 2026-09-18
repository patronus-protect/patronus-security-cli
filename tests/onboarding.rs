use assert_cmd::Command;
use serde_json::Value;
fn cli(root: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("patronus-security-scanner").unwrap();
    c.env("PATRONUS_DATA_DIR", root);
    c
}
#[cfg(unix)]
#[test]
fn status_reads_installed_claude_even_when_snapshot_has_no_host() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("claude");
    std::fs::write(&bin, "#!/bin/sh\nprintf '%s\\n' '[{\"id\":\"patronus-security@patronus-local\",\"scope\":\"user\",\"enabled\":true}]'\n").unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(
        root.path().join("onboarding.json"),
        r#"{"installed_hosts":null,"restart_required":null}"#,
    )
    .unwrap();
    let output = cli(root.path())
        .env("PATRONUS_CLAUDE_BIN", &bin)
        .env("PATH", root.path())
        .args(["onboarding", "--status", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: Value = serde_json::from_slice(&output).unwrap();
    assert!(status["installed_hosts"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("claude")));
    assert_eq!(status["restart_required"], true);
    let marketplace = root.path().join("marketplace");
    std::fs::create_dir_all(marketplace.join(".claude-plugin")).unwrap();
    std::fs::write(marketplace.join(".claude-plugin/marketplace.json"), "{}").unwrap();
    cli(root.path())
        .env("PATRONUS_CLAUDE_BIN", &bin)
        .args([
            "integration",
            "claude",
            "install",
            "--source",
            marketplace.to_str().unwrap(),
        ])
        .assert()
        .success();
    let saved: Value =
        serde_json::from_slice(&std::fs::read(root.path().join("onboarding.json")).unwrap())
            .unwrap();
    assert!(saved["installed_at"].is_i64());
    assert!(saved.get("installed_hosts").is_none());
    std::fs::write(root.path().join("onboarding.json"), r#"{"installed_at":0}"#).unwrap();
    let output = cli(root.path())
        .env("PATRONUS_CLAUDE_BIN", &bin)
        .env("PATH", root.path())
        .args(["onboarding", "--status", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(status["restart_required"], false);
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
fn no_interactive_setup_and_remote_scan_authentication_contract() {
    let root = tempfile::tempdir().unwrap();
    cli(root.path())
        .arg("onboarding")
        .assert()
        .failure()
        .stderr(predicates::str::contains("interactive terminal"));
    let url = cli(root.path())
        .args(["scan", "url", "https://example.org/", "--format", "json"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let url: Value = serde_json::from_slice(&url).unwrap();
    assert_eq!(url["schema"], "patronus.remote.scan.error.v1");
    assert_eq!(url["kind"], "url");
    assert_eq!(url["provider"], "api");
    assert_ne!(url["reason"], "authentication_missing");

    let mcp = cli(root.path())
        .args(["scan", "mcp", "https://example.org/", "--format", "json"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let mcp: Value = serde_json::from_slice(&mcp).unwrap();
    assert_eq!(mcp["schema"], "patronus.remote.scan.error.v1");
    assert_eq!(mcp["kind"], "mcp");
    assert_eq!(mcp["provider"], "api");
    assert_eq!(mcp["reason"], "authentication_missing");
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
        assert!(html.contains(">Commands</label>"));
        assert!(!html.contains("Access Rules"));
    }
}
