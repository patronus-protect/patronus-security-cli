use std::path::Path;

use assert_cmd::Command;

#[test]
fn bare_command_prints_help_without_a_terminal() {
    Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Usage: patronus-security-scanner",
        ));
}

#[test]
fn version_contract_is_stable() {
    Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .arg("version")
        .assert()
        .success()
        .stdout(predicates::str::contains("patronus-ark 0.1.8"));
}

#[test]
fn unsupported_scan_and_update_flags_fail_before_running() {
    for args in [
        vec!["scan", "repo", ".", "--anonymous-api"],
        vec!["scan", "directory", ".", "--anonymous-api"],
        vec!["scan", "url", "https://example.org", "--server", "unused"],
        vec!["scan", "file", "example.txt", "--color", "always"],
    ] {
        Command::cargo_bin("patronus-security-scanner")
            .unwrap()
            .args(args)
            .assert()
            .failure();
    }
    Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .args([
            "scan",
            "file",
            "example.txt",
            "--anonymous-api",
            "--fail-on",
            "never",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Anonymous file uploads support only",
        ));
    Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .args(["integration", "claude", "update", "--source", "example.tgz"])
        .assert()
        .code(6)
        .stderr(predicates::str::contains("--source is supported only"));
    Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .args(["scan", "file", "example.txt", "--include", "*.txt"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "--include and --ignore apply only",
        ));
    Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .args(["onboarding", "--format", "json"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--format is supported only"));
}

#[test]
fn protocol_append_uses_the_workspace_report_root() {
    let temp = tempfile::tempdir().unwrap();
    let event = format!(
        r#"{{"schema":"patronus.protocol.event.v1","timestamp":"2026-09-04T08:18:00Z","host":"codex","session_id":"sha256:{}","event":"scan_completed","direction":"response","tool_name":"read_file","scan_id":"scan-1","status":"pending","duration_ms":5,"payload_hash":"sha256:{}"}}"#,
        "a".repeat(64),
        "b".repeat(64)
    );
    Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .args(["protocol", "append", "--root"])
        .arg(temp.path())
        .write_stdin(event)
        .assert()
        .success();
    let root = temp.path().join(".patronus-security-scanner");
    assert!(root.join("index.html").is_file());
    assert!(root.join("protocol").is_dir());
}

#[test]
fn config_init_can_select_provider_without_running_it() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.toml");
    Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .args(["config", "init", "--provider", "api", "--path"])
        .arg(&path)
        .assert()
        .success();
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.contains("mode = \"api\""));
}

#[test]
fn removed_webmcp_provider_is_rejected() {
    Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .args(["config", "init", "--provider", "webmcp"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("invalid value"));
}

#[test]
fn integration_errors_have_a_stable_exit_code() {
    Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .args(["integration", "codex", "disable", "--scope", "project"])
        .assert()
        .code(6)
        .stderr(predicates::str::contains(
            "Codex lifecycle supports only --scope user",
        ));
}

#[cfg(unix)]
#[test]
fn integration_status_is_agent_readable_for_all_hosts() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let fake = |name: &str, body: &str| {
        let path = temp.path().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
        path
    };

    let codex = fake(
        "codex",
        "printf '%s\\n' 'patronus-security@patronus-local  installed, enabled  0.1.0'",
    );
    let codex_home = temp.path().join("codex-home");
    std::fs::create_dir_all(&codex_home).unwrap();
    let codex_status = status_json(
        &["integration", "codex", "status", "--format", "json"],
        &[("PATRONUS_CODEX_BIN", &codex), ("CODEX_HOME", &codex_home)],
    );
    assert_eq!(codex_status["installed"], true);
    assert_eq!(codex_status["enabled"], true);
    assert_eq!(codex_status["ready"], false);
    assert_eq!(codex_status["state"], "incomplete");
    assert_eq!(
        codex_status["commands"]["enable"],
        "patronus-security-scanner integration codex enable"
    );

    let claude = fake(
        "claude",
        r#"printf '%s\n' '[{"id":"patronus-security@patronus-local","scope":"project","enabled":true}]'"#,
    );
    let claude_status = status_json(
        &[
            "integration",
            "claude",
            "status",
            "--scope",
            "project",
            "--format",
            "json",
        ],
        &[("PATRONUS_CLAUDE_BIN", &claude)],
    );
    assert_eq!(claude_status["state"], "active");
    assert_eq!(claude_status["ready"], true);
    assert_eq!(
        claude_status["commands"]["uninstall"],
        "patronus-security-scanner integration claude uninstall --scope project"
    );

    let dsh_home = temp.path().join("dsh-home");
    let profile = dsh_home.join("profiles/headless");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::write(
        profile.join("package.json"),
        r#"{"dependencies":{"@patronus/deepseek-security":"file:test"},"dsh":{"profile":{"bundles":["@patronus/deepseek-security"]}}}"#,
    )
    .unwrap();
    let dsh = fake(
        "dsh",
        "printf '%s\\n' '- id: patronus-security' '  disabled: false'",
    );
    let deepseek_status = status_json(
        &[
            "integration",
            "deepseek",
            "status",
            "--profile",
            "headless",
            "--format",
            "json",
        ],
        &[("PATRONUS_DSH_BIN", &dsh), ("DSH_HOME", &dsh_home)],
    );
    assert_eq!(deepseek_status["state"], "active");
    assert_eq!(deepseek_status["ready"], true);
    assert_eq!(
        deepseek_status["commands"]["disable"],
        "patronus-security-scanner integration deepseek disable --profile headless"
    );

    let missing = temp.path().join("missing-codex");
    let unavailable = status_json(
        &["integration", "codex", "status", "--format", "json"],
        &[
            ("PATRONUS_CODEX_BIN", &missing),
            ("CODEX_HOME", &codex_home),
        ],
    );
    assert_eq!(unavailable["state"], "unreachable");
    assert_eq!(unavailable["reachable"], false);
    assert!(unavailable["message"]
        .as_str()
        .unwrap()
        .contains("enable Patronus or disable/uninstall it"));
    assert!(!unavailable["message"]
        .as_str()
        .unwrap()
        .contains("No such file"));
}

#[cfg(unix)]
fn status_json(args: &[&str], env: &[(&str, &Path)]) -> serde_json::Value {
    let mut command = Command::cargo_bin("patronus-security-scanner").unwrap();
    command.args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn file_scan_writes_complete_pipe_safe_json_and_support_dry_run() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("runs");
    let assertion = Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .args([
            "scan",
            "file",
            "tests/fixtures/benign/readme.txt",
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
        ])
        .assert()
        .success();
    let stdout = assertion.get_output().stdout.clone();
    let report: serde_json::Value =
        serde_json::from_slice(&stdout).expect("stdout is exactly one JSON value");
    assert_eq!(report["schema"], "patronus.security-scanner.report.v1");
    assert_eq!(report["status"], "CLEAN");
    assert_eq!(report["ark_version"], "0.1.8");
    assert!(report["findings"].as_array().unwrap().is_empty());
    let run = only_child(&output);
    assert!(output.join("index.html").is_file());
    assert!(run.join("COMPLETE").is_file());
    for artifact in [
        "manifest.json",
        "files.jsonl",
        "chunks.jsonl",
        "classifications.jsonl",
        "findings.json",
        "failures.jsonl",
        "report.json",
        "report.md",
        "report.html",
    ] {
        assert!(run.join(artifact).is_file(), "missing {artifact}");
    }

    let bundle = temp.path().join("support.zip");
    Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .args(["support-us", "--run"])
        .arg(&run)
        .args(["--dry-run", "--bundle-out"])
        .arg(&bundle)
        .assert()
        .success()
        .stdout(predicates::str::contains("no network request was made"));
    assert!(bundle.is_file());
}

fn only_child(path: &Path) -> std::path::PathBuf {
    let children = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|entry| entry.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(children.len(), 1);
    children[0].clone()
}
