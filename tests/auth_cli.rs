use assert_cmd::Command;
use predicates::str::contains;

fn cli(root: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("patronus-security-scanner").unwrap();
    command.env("PATRONUS_DATA_DIR", root);
    command
}

#[cfg(unix)]
#[test]
fn repeated_login_reuses_the_existing_token_without_overwriting_it() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let auth = root.path().join("auth");
    std::fs::create_dir(&auth).unwrap();
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = auth.join("credentials.json");
    let expires_at = chrono::Utc::now().timestamp() + 3600;
    let original = serde_json::json!({"issuer":"https://control.patronus.studio","access_token":"test_existing_token_123456789","user_id":"user_test","expires_at":expires_at}).to_string();
    std::fs::write(&path, &original).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    cli(root.path())
        .args(["auth", "login", "--no-browser"])
        .assert()
        .success()
        .stdout(contains("Already signed in"));
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
}

#[test]
fn signed_out_status_token_and_local_logout_are_safe() {
    let root = tempfile::tempdir().unwrap();
    cli(root.path())
        .args(["auth", "status", "--format", "json"])
        .assert()
        .success()
        .stdout(contains("signed_out"));
    cli(root.path())
        .args(["auth", "token"])
        .assert()
        .failure()
        .stderr(contains("not signed in"));
    cli(root.path())
        .args(["auth", "logout", "--local"])
        .assert()
        .success();
    assert!(!root.path().join("auth/credentials.json").exists());
    let index = std::fs::read_to_string(root.path().join("index.html")).unwrap();
    assert!(index.contains(">Connect Control Plane</a>"));
    assert!(index.contains("14 days"));
    assert!(index.contains("Scanner commands"));
    for command in [
        "auth login",
        "auth logout",
        "plugins pause",
        "scan repo",
        "protocol render",
        "integration &lt;host&gt; install",
    ] {
        assert!(index.contains(command), "missing {command}");
    }
    assert!(!index.contains("<script"));
}

#[test]
fn default_reports_and_protocol_are_shared_across_workspaces() {
    let root = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir().unwrap();
    let file = repo.path().join("readme.txt");
    std::fs::write(&file, "A short ordinary project description.").unwrap();
    cli(root.path())
        .current_dir(repo.path())
        .args(["scan", "file"])
        .arg(&file)
        .args(["--progress", "off"])
        .assert()
        .success();
    assert!(root.path().join("index.html").is_file());
    assert!(root.path().join("output").is_dir());
    assert!(!repo.path().join(".patronus-security-scanner").exists());
    cli(root.path())
        .current_dir(repo.path())
        .args(["serve", "--stdio"])
        .write_stdin("")
        .assert()
        .success();
    assert!(root.path().join("runtime").is_dir());
    cli(root.path())
        .current_dir(repo.path())
        .args(["protocol", "render"])
        .assert()
        .success();
    let output = cli(root.path())
        .current_dir(repo.path())
        .args(["config", "print", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let config: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        config["output"]["root"],
        root.path().join("output").display().to_string()
    );
}
