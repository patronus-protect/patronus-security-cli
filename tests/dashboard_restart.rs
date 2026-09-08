use std::{
    io::Write,
    process::{Command, Stdio},
};
#[test]
fn activity_survives_separate_cli_processes_and_rebuilds() {
    let root = tempfile::tempdir().unwrap();
    let cli = env!("CARGO_BIN_EXE_patronus-security-scanner");
    let event = serde_json::json!({"schema":"patronus.protocol.event.v1","timestamp":"2026-09-07T12:00:00Z","host":"codex","session_id":format!("sha256:{}","a".repeat(64)),"event":"scan_completed","direction":"response","tool_name":"read_file","status":"approved","duration_ms":4,"payload_hash":format!("sha256:{}","b".repeat(64))});
    let mut child = Command::new(cli)
        .env("PATRONUS_DATA_DIR", root.path())
        .args(["protocol", "append", "--journal-only"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(event.to_string().as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
    let journal = std::fs::read_dir(root.path().join("protocol"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .unwrap();
    let original = std::fs::read(&journal).unwrap();
    for _ in 0..2 {
        assert!(Command::new(cli)
            .env("PATRONUS_DATA_DIR", root.path())
            .args(["protocol", "render"])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success());
        let html = std::fs::read_to_string(root.path().join("index.html")).unwrap();
        assert!(html.contains("codex"));
        assert!(html.contains("approved"));
        assert!(!html.contains("No session activity yet"));
        assert_eq!(std::fs::read(&journal).unwrap(), original);
    }
}
