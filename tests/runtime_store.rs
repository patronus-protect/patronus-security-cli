use patronus_security_scanner::ark::ScanNotice;
use patronus_security_scanner::runtime::protocol::{
    Direction, JobStatus, PayloadCoverage, ScanOutcome, Verdict,
};
use patronus_security_scanner::runtime::store::{NewJob, Store, StoreLimits};
use serde_json::{json, Value};
use tempfile::TempDir;

fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn job(payload: Value) -> NewJob {
    NewJob {
        policy_scope: None,
        session_hash: "session-a".into(),
        direction: Direction::Response,
        tool: "document".into(),
        call_id: "call-1".into(),
        payload,
        config_hash: "config-a".into(),
        deadline_ms: now() + 60_000,
    }
}

fn approved() -> ScanOutcome {
    ScanOutcome {
        status: JobStatus::Completed,
        verdict: Some(Verdict::Approved),
        findings: vec![],
        coverage: PayloadCoverage {
            fields_total: 1,
            fields_scanned: 1,
            bytes_total: 6,
            bytes_scanned: 6,
            complete: true,
        },
        redacted: None,
        reason: None,
        notice: None,
    }
}

fn setup() -> (TempDir, Store) {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("store"), StoreLimits::default()).unwrap();
    (temp, store)
}

fn finish(store: &mut Store, id: &str, outcome: &ScanOutcome) {
    assert_eq!(store.claim_next("config-a").unwrap().unwrap().scan_id, id);
    store.complete(id, outcome).unwrap();
}

#[test]
fn original_is_released_only_for_an_approved_response_and_its_owner() {
    let (_temp, mut store) = setup();
    let payload = json!({"content":"SECRET", "value":{"private":"SECRET"}});
    let id = store.enqueue(job(payload.clone())).unwrap();
    let pending = store.check(&id, "session-a").unwrap();
    assert_eq!(pending["status"], "pending");
    assert!(!pending.to_string().contains("SECRET"));
    assert_eq!(
        store.check(&id, "session-b").unwrap()["status"],
        "unavailable"
    );
    finish(&mut store, &id, &approved());
    assert_eq!(store.check(&id, "session-a").unwrap()["result"], payload);
    assert_eq!(
        store.check(&id, "session-b").unwrap()["status"],
        "unavailable"
    );

    let mut request = job(json!({"argument":"SECRET"}));
    request.direction = Direction::Request;
    let request_id = store.enqueue(request).unwrap();
    finish(&mut store, &request_id, &approved());
    let result = store.check(&request_id, "session-a").unwrap();
    assert_eq!(result["status"], "approved");
    assert!(result.get("result").is_none());
}

#[test]
fn dangerous_results_expose_only_the_separate_redacted_payload() {
    let (_temp, mut store) = setup();
    let id = store.enqueue(job(json!({"content":"SECRET"}))).unwrap();
    let mut outcome = approved();
    outcome.verdict = Some(Verdict::Dangerous);
    outcome.redacted = Some(json!({"content":"[redacted]"}));
    finish(&mut store, &id, &outcome);
    let result = store.check(&id, "session-a").unwrap();
    assert_eq!(result["status"], "dangerous");
    assert_eq!(result["redacted_available"], true);
    assert!(!result.to_string().contains("SECRET"));
    assert_eq!(
        store.read_redacted(&id, "session-a").unwrap()["result"],
        outcome.redacted.unwrap()
    );
    assert_eq!(
        store.read_redacted(&id, "session-b").unwrap()["status"],
        "unavailable"
    );
}

#[test]
fn incomplete_coverage_cannot_approve_or_offer_a_redacted_original() {
    let (_temp, mut store) = setup();
    for verdict in [Verdict::Approved, Verdict::Dangerous] {
        let id = store.enqueue(job(json!("SECRET"))).unwrap();
        let mut outcome = approved();
        outcome.verdict = Some(verdict);
        outcome.coverage.bytes_scanned = 0;
        outcome.redacted = Some(json!("SECRET"));
        finish(&mut store, &id, &outcome);
        let result = store.check(&id, "session-a").unwrap();
        assert_eq!(result["status"], "incomplete");
        assert!(!result.to_string().contains("SECRET"));
        assert_eq!(
            store.read_redacted(&id, "session-a").unwrap()["status"],
            "unavailable"
        );
    }
}

#[test]
fn failed_scanner_diagnostics_do_not_echo_sensitive_error_text() {
    let (_temp, mut store) = setup();
    let id = store.enqueue(job(json!("SECRET"))).unwrap();
    finish(
        &mut store,
        &id,
        &ScanOutcome::failed("SECRET backend output"),
    );
    let result = store.check(&id, "session-a").unwrap();
    assert_eq!(result["status"], "failed");
    assert!(!result.to_string().contains("SECRET"));
}

#[test]
fn claims_are_unique_and_cancellation_wins_over_late_completion() {
    let (_temp, mut store) = setup();
    let first = store.enqueue(job(json!("first"))).unwrap();
    let second = store.enqueue(job(json!("second"))).unwrap();
    assert_eq!(
        store.claim_next("config-a").unwrap().unwrap().scan_id,
        first
    );
    assert_eq!(
        store.claim_next("config-a").unwrap().unwrap().scan_id,
        second
    );
    assert!(store.claim_next("config-a").unwrap().is_none());
    assert_eq!(
        store.cancel(&first, "session-b").unwrap()["status"],
        "unavailable"
    );
    assert_eq!(
        store.cancel(&first, "session-a").unwrap()["status"],
        "cancelled"
    );
    store.complete(&first, &approved()).unwrap();
    assert_eq!(
        store.check(&first, "session-a").unwrap()["status"],
        "cancelled"
    );
    store.complete(&second, &approved()).unwrap();
    assert_eq!(
        store.check(&second, "session-a").unwrap()["result"],
        "second"
    );
}

#[test]
fn expired_work_is_never_claimed_or_released() {
    let (_temp, mut store) = setup();
    let mut input = job(json!("SECRET"));
    input.deadline_ms = now() - 1;
    let id = store.enqueue(input).unwrap();
    assert!(store.claim_next("config-a").unwrap().is_none());
    store.complete(&id, &approved()).unwrap();
    assert_eq!(store.check(&id, "session-a").unwrap()["status"], "expired");
}

#[test]
fn queued_work_receives_its_full_execution_budget_when_claimed() {
    let (temp, mut store) = setup();
    let id = store.enqueue(job(json!("queued"))).unwrap();
    let db = rusqlite::Connection::open(temp.path().join("store/jobs.sqlite3")).unwrap();
    db.execute(
        "UPDATE jobs SET created_ms=0,deadline_ms=60000 WHERE scan_id=?1",
        [&id],
    )
    .unwrap();

    assert_eq!(store.pending_count().unwrap(), 1);
    let claimed = store.claim_next("config-a").unwrap().unwrap();
    assert_eq!(claimed.scan_id, id);
    assert!(claimed.deadline_ms >= now() + 59_000);
}

#[test]
fn restart_requeues_only_unfinished_jobs_with_the_same_configuration() {
    let (temp, mut store) = setup();
    let running = store.enqueue(job(json!("running"))).unwrap();
    assert_eq!(
        store.claim_next("config-a").unwrap().unwrap().scan_id,
        running
    );
    let mut other = job(json!("old-config"));
    other.config_hash = "config-old".into();
    let obsolete = store.enqueue(other).unwrap();
    drop(store);
    let mut reopened = Store::open(&temp.path().join("store"), StoreLimits::default()).unwrap();
    reopened.recover("config-a").unwrap();
    assert_eq!(
        reopened.claim_next("config-a").unwrap().unwrap().scan_id,
        running
    );
    assert_eq!(
        reopened.check(&obsolete, "session-a").unwrap()["status"],
        "incomplete"
    );
    assert!(reopened.claim_next("config-a").unwrap().is_none());
}

#[test]
fn approved_results_survive_restart_without_rescanning_or_tool_execution() {
    let (temp, mut store) = setup();
    let id = store.enqueue(job(json!("approved"))).unwrap();
    finish(&mut store, &id, &approved());
    drop(store);
    let mut reopened = Store::open(&temp.path().join("store"), StoreLimits::default()).unwrap();
    reopened.recover("config-a").unwrap();
    assert!(reopened.claim_next("config-a").unwrap().is_none());
    assert_eq!(
        reopened.check(&id, "session-a").unwrap()["result"],
        "approved"
    );
}

#[test]
fn unchanged_payload_reuses_completed_result_for_same_policy() {
    let (_temp, mut store) = setup();
    let first = store.enqueue(job(json!("same content"))).unwrap();
    finish(&mut store, &first, &approved());

    let second = store.enqueue(job(json!("same content"))).unwrap();
    assert!(store.claim_next("config-a").unwrap().is_none());
    let result = store.check(&second, "session-a").unwrap();
    assert_eq!(result["status"], "approved");
    assert_eq!(result["cached"], true);
    assert_eq!(result["result"], "same content");
}

#[test]
fn unchanged_payload_reuses_result_across_session_stores() {
    let temp = tempfile::tempdir().unwrap();
    let cache = temp.path().join("shared-cache");
    let mut first_store = Store::open_with_cache(
        &temp.path().join("session-a"),
        &cache,
        StoreLimits::default(),
    )
    .unwrap();
    let first = first_store.enqueue(job(json!("shared content"))).unwrap();
    finish(&mut first_store, &first, &approved());
    drop(first_store);

    let mut second_store = Store::open_with_cache(
        &temp.path().join("session-b"),
        &cache,
        StoreLimits::default(),
    )
    .unwrap();
    let second = second_store.enqueue(job(json!("shared content"))).unwrap();
    assert!(second_store.claim_next("config-a").unwrap().is_none());
    let result = second_store.check(&second, "session-a").unwrap();
    assert_eq!(result["status"], "approved");
    assert_eq!(result["cached"], true);
    assert_eq!(result["result"], "shared content");
}

#[test]
fn changed_content_configuration_or_policy_is_scanned_again() {
    let (_temp, mut store) = setup();
    let first = store.enqueue(job(json!("same content"))).unwrap();
    finish(&mut store, &first, &approved());

    let changed_content = store.enqueue(job(json!("changed content"))).unwrap();
    assert_eq!(
        store.claim_next("config-a").unwrap().unwrap().scan_id,
        changed_content
    );
    store.complete(&changed_content, &approved()).unwrap();

    let mut changed_config = job(json!("same content"));
    changed_config.config_hash = "config-b".into();
    let changed_config = store.enqueue(changed_config).unwrap();
    assert_eq!(
        store.claim_next("config-b").unwrap().unwrap().scan_id,
        changed_config
    );

    let mut changed_policy = job(json!("same content"));
    changed_policy.policy_scope = Some("codex.tool_result".into());
    let changed_policy = store.enqueue(changed_policy).unwrap();
    assert_eq!(
        store.claim_next("config-a").unwrap().unwrap().scan_id,
        changed_policy
    );
}

#[test]
fn cached_dangerous_result_keeps_its_verified_redaction() {
    let (_temp, mut store) = setup();
    let first = store.enqueue(job(json!("dangerous content"))).unwrap();
    let mut outcome = approved();
    outcome.verdict = Some(Verdict::Dangerous);
    outcome.redacted = Some(json!("[redacted]"));
    finish(&mut store, &first, &outcome);

    let second = store.enqueue(job(json!("dangerous content"))).unwrap();
    assert!(store.claim_next("config-a").unwrap().is_none());
    let result = store.check(&second, "session-a").unwrap();
    assert_eq!(result["status"], "dangerous");
    assert_eq!(result["cached"], true);
    assert_eq!(
        store.read_redacted(&second, "session-a").unwrap()["result"],
        "[redacted]"
    );
}

#[test]
fn usage_accounting_migrates_existing_jobs_and_tracks_rollback_and_cleanup() {
    let (temp, mut store) = setup();
    let root = temp.path().join("store");
    let id = store.enqueue(job(json!("Unicode 🔒"))).unwrap();
    finish(&mut store, &id, &approved());
    drop(store);
    let db = rusqlite::Connection::open(root.join("jobs.sqlite3")).unwrap();
    db.execute_batch("DROP TRIGGER usage_insert; DROP TRIGGER usage_update; DROP TRIGGER usage_delete; DROP TABLE storage_usage;").unwrap();
    let mut reopened = Store::open(&root, StoreLimits::default()).unwrap();
    let used = || {
        db.query_row("SELECT bytes FROM storage_usage", [], |row| {
            row.get::<_, u64>(0)
        })
        .unwrap()
    };
    let sum = || {
        db.query_row("SELECT COALESCE(SUM(payload_bytes+redacted_bytes+length(CAST(COALESCE(outcome,'') AS BLOB))),0) FROM jobs", [], |row| row.get::<_, u64>(0)).unwrap()
    };
    assert_eq!(used(), sum());
    let before = used();
    db.execute_batch("BEGIN; UPDATE jobs SET outcome=NULL; ROLLBACK;")
        .unwrap();
    assert_eq!(used(), before);
    let next = reopened.enqueue(job(json!("next"))).unwrap();
    finish(&mut reopened, &next, &approved());
    assert_eq!(used(), sum());
    db.execute("UPDATE jobs SET expires_ms=0", []).unwrap();
    reopened.cleanup().unwrap();
    assert_eq!(used(), 0);
}

#[test]
fn one_process_exclusively_owns_the_store_and_unlocks_on_drop() {
    let (temp, store) = setup();
    let root = temp.path().join("store");
    assert!(Store::open(&root, StoreLimits::default()).is_err());
    drop(store);
    assert!(Store::open(&root, StoreLimits::default()).is_ok());
}

#[test]
fn payload_queue_and_storage_limits_reject_before_acceptance() {
    let temp = tempfile::tempdir().unwrap();
    let limits = StoreLimits {
        max_payload_bytes: 32,
        max_pending_jobs: 1,
        ..StoreLimits::default()
    };
    let mut store = Store::open(&temp.path().join("store"), limits).unwrap();
    assert!(store.enqueue(job(json!("x".repeat(40)))).is_err());
    let id = store.enqueue(job(json!("fits"))).unwrap();
    assert!(store.enqueue(job(json!("queue full"))).is_err());
    store.cancel(&id, "session-a").unwrap();
    assert!(store.enqueue(job(json!("queue free"))).is_ok());

    let mut tiny = Store::open(
        &temp.path().join("tiny"),
        StoreLimits {
            max_store_bytes: 2,
            ..StoreLimits::default()
        },
    )
    .unwrap();
    assert!(tiny.enqueue(job(json!("too large"))).is_err());
    assert_eq!(tiny.pending_count().unwrap(), 0);
}

#[test]
fn retention_deletes_original_redacted_and_metadata() {
    let (temp, mut store) = setup();
    let root = temp.path().join("store");
    let id = store.enqueue(job(json!("SECRET"))).unwrap();
    let mut outcome = approved();
    outcome.verdict = Some(Verdict::Dangerous);
    outcome.redacted = Some(json!("[redacted]"));
    finish(&mut store, &id, &outcome);
    let db = rusqlite::Connection::open(root.join("jobs.sqlite3")).unwrap();
    db.execute("UPDATE jobs SET expires_ms = 0", []).unwrap();
    store.cleanup().unwrap();
    assert!(!root.join(format!("{id}.original.json")).exists());
    assert!(!root.join(format!("{id}.redacted.json")).exists());
    assert_eq!(
        store.check(&id, "session-a").unwrap()["status"],
        "unavailable"
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn altered_originals_fail_integrity_checks_before_scan_and_before_release() {
    let (temp, mut store) = setup();
    let root = temp.path().join("store");
    let first = store.enqueue(job(json!("SECRET"))).unwrap();
    std::fs::write(root.join(format!("{first}.original.json")), b"\"tampered\"").unwrap();
    assert!(store.claim_next("config-a").is_err());
    assert_eq!(
        store.check(&first, "session-a").unwrap()["status"],
        "failed"
    );
    let second = store.enqueue(job(json!("safe"))).unwrap();
    finish(&mut store, &second, &approved());
    std::fs::write(
        root.join(format!("{second}.original.json")),
        b"\"tampered\"",
    )
    .unwrap();
    assert!(store.check(&second, "session-a").is_err());
}

#[test]
fn corrupt_scan_ids_cannot_address_files_outside_the_store() {
    let (_temp, mut store) = setup();
    for id in [
        "../outside",
        "/private/tmp/file",
        "",
        "A".repeat(32).as_str(),
    ] {
        assert_eq!(
            store.check(id, "session-a").unwrap()["status"],
            "unavailable"
        );
        assert_eq!(
            store.read_redacted(id, "session-a").unwrap()["status"],
            "unavailable"
        );
        assert_eq!(
            store.cancel(id, "session-a").unwrap()["status"],
            "unavailable"
        );
    }
}

#[test]
fn startup_removes_only_recognized_uncommitted_payload_files() {
    let (temp, store) = setup();
    let root = temp.path().join("store");
    let orphan = root.join(format!("{}.original.json", "a".repeat(32)));
    std::fs::write(&orphan, "private orphan").unwrap();
    let unknown = root.join("unrelated.txt");
    std::fs::write(&unknown, "leave alone").unwrap();
    drop(store);
    let mut reopened = Store::open(&root, StoreLimits::default()).unwrap();
    reopened.recover("config-a").unwrap();
    assert!(!orphan.exists());
    assert!(unknown.exists());
}

#[cfg(unix)]
#[test]
fn private_permissions_and_symlink_refusal_cover_root_database_and_payload() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (temp, mut store) = setup();
    let root = temp.path().join("store");
    let id = store.enqueue(job(json!("SECRET"))).unwrap();
    let original = root.join(format!("{id}.original.json"));
    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for path in [root.join("jobs.sqlite3"), original.clone()] {
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let outside = temp.path().join("outside");
    std::fs::write(&outside, "outside secret").unwrap();
    std::fs::remove_file(&original).unwrap();
    symlink(&outside, &original).unwrap();
    assert!(store.claim_next("config-a").is_err());
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "outside secret");
    let alias = temp.path().join("alias");
    symlink(&root, &alias).unwrap();
    assert!(Store::open(&alias, StoreLimits::default()).is_err());
    drop(store);
    std::fs::remove_file(root.join("jobs.sqlite3")).unwrap();
    symlink(&outside, root.join("jobs.sqlite3")).unwrap();
    assert!(Store::open(&root, StoreLimits::default()).is_err());
}

#[test]
fn concurrent_worker_claims_through_the_service_mutex_never_duplicate_jobs() {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    let (_temp, mut store) = setup();
    let ids: HashSet<_> = (0..16)
        .map(|n| store.enqueue(job(json!({"number":n}))).unwrap())
        .collect();
    let shared = Arc::new(Mutex::new(store));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                let mut claimed = Vec::new();
                while let Some(work) = shared.lock().unwrap().claim_next("config-a").unwrap() {
                    claimed.push(work.scan_id);
                }
                claimed
            })
        })
        .collect();
    let claimed: Vec<_> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();
    assert_eq!(claimed.len(), ids.len());
    assert_eq!(claimed.into_iter().collect::<HashSet<_>>(), ids);
}

#[test]
fn deadline_expiry_while_the_worker_runs_wins_over_its_late_verdict() {
    let (temp, mut store) = setup();
    let id = store.enqueue(job(json!("SECRET"))).unwrap();
    store.claim_next("config-a").unwrap().unwrap();
    let db = rusqlite::Connection::open(temp.path().join("store/jobs.sqlite3")).unwrap();
    db.execute("UPDATE jobs SET deadline_ms = 0", []).unwrap();
    store.complete(&id, &approved()).unwrap();
    let result = store.check(&id, "session-a").unwrap();
    assert_eq!(result["status"], "expired");
    assert!(!result.to_string().contains("SECRET"));
    assert_eq!(store.pending_count().unwrap(), 0);
}

#[test]
fn result_storage_exhaustion_fails_closed_without_a_derived_file() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let mut store = Store::open(
        &root,
        StoreLimits {
            max_store_bytes: 128,
            ..StoreLimits::default()
        },
    )
    .unwrap();
    let id = store.enqueue(job(json!("SECRET"))).unwrap();
    store.claim_next("config-a").unwrap().unwrap();
    let mut outcome = approved();
    outcome.verdict = Some(Verdict::Dangerous);
    outcome.redacted = Some(json!("[redacted]"));
    assert!(store.complete(&id, &outcome).is_err());
    assert_eq!(store.check(&id, "session-a").unwrap()["status"], "failed");
    assert_eq!(
        store.read_redacted(&id, "session-a").unwrap()["status"],
        "unavailable"
    );
    assert!(!root.join(format!("{id}.redacted.json")).exists());
}

#[test]
fn dangerous_request_never_offers_a_payload_and_redacted_responses_are_hash_checked() {
    let (temp, mut store) = setup();
    let mut input = job(json!("SECRET"));
    input.direction = Direction::Request;
    let request = store.enqueue(input).unwrap();
    let mut outcome = approved();
    outcome.verdict = Some(Verdict::Dangerous);
    outcome.redacted = Some(json!("[redacted]"));
    finish(&mut store, &request, &outcome);
    let result = store.check(&request, "session-a").unwrap();
    assert_eq!(result["redacted_available"], false);
    assert!(result.get("result").is_none());
    assert_eq!(
        store.read_redacted(&request, "session-a").unwrap()["status"],
        "unavailable"
    );

    let response = store.enqueue(job(json!("SECRET"))).unwrap();
    finish(&mut store, &response, &outcome);
    std::fs::write(
        temp.path()
            .join("store")
            .join(format!("{response}.redacted.json")),
        b"\"SECRET\"",
    )
    .unwrap();
    assert!(store.read_redacted(&response, "session-a").is_err());
}

#[test]
fn unicode_outcome_metadata_counts_bytes_for_subsequent_enqueue_and_completion() {
    use patronus_security_scanner::runtime::protocol::RuntimeFinding;
    let temp = tempfile::tempdir().unwrap();
    let payload = json!("SECRET");
    let payload_bytes = serde_json::to_vec(&payload).unwrap().len() as u64;
    let mut outcome = approved();
    outcome.verdict = Some(Verdict::Dangerous);
    outcome.findings.push(RuntimeFinding {
        field_id: 0,
        start_byte: 0,
        end_byte: 6,
        category: "dlp".into(),
        label: "🔒".repeat(200),
        level: Some("l1".into()),
        confidence: 1.0,
    });
    let outcome_bytes = serde_json::to_vec(&outcome).unwrap().len() as u64;
    let mut store = Store::open(
        &temp.path().join("store"),
        StoreLimits {
            // Exactly two originals and the first result fit; the first Unicode result
            // must not leave additional apparent capacity when SQL reads it back.
            max_store_bytes: 2 * payload_bytes + outcome_bytes,
            ..StoreLimits::default()
        },
    )
    .unwrap();
    let first = store.enqueue(job(payload.clone())).unwrap();
    let second = store.enqueue(job(payload.clone())).unwrap();
    finish(&mut store, &first, &outcome);
    assert!(store.enqueue(job(payload)).is_err());
    store.claim_next("config-a").unwrap().unwrap();
    assert!(store.complete(&second, &approved()).is_err());
    assert_eq!(
        store.check(&second, "session-a").unwrap()["status"],
        "failed"
    );
}

#[test]
fn changed_configuration_invalidates_previously_approved_completed_jobs() {
    let (temp, mut store) = setup();
    let id = store.enqueue(job(json!("SECRET"))).unwrap();
    finish(&mut store, &id, &approved());
    assert_eq!(store.check(&id, "session-a").unwrap()["status"], "approved");
    drop(store);
    let mut reopened = Store::open(&temp.path().join("store"), StoreLimits::default()).unwrap();
    reopened.recover("config-b").unwrap();
    let result = reopened.check(&id, "session-a").unwrap();
    assert_eq!(result["status"], "incomplete");
    assert!(result.get("result").is_none());
    assert!(!result.to_string().contains("SECRET"));
    assert!(reopened.claim_next("config-b").unwrap().is_none());
    reopened.recover("config-a").unwrap();
    assert_eq!(
        reopened.check(&id, "session-a").unwrap()["status"],
        "incomplete"
    );
}

#[test]
fn privacy_redaction_is_immediate_without_a_refinement_job() {
    use patronus_security_scanner::runtime::protocol::RuntimeFinding;
    for category in ["pii", "dlp"] {
        let (_temp, mut store) = setup();
        let id = store.enqueue(job(json!("SECRET"))).unwrap();
        let mut outcome = approved();
        outcome.verdict = Some(Verdict::Dangerous);
        outcome.redacted = Some(json!("[REDACTED]"));
        outcome.findings.push(RuntimeFinding {
            field_id: 0,
            start_byte: 0,
            end_byte: 6,
            category: category.into(),
            label: "sensitive_data".into(),
            level: Some("l1".into()),
            confidence: 1.0,
        });
        finish(&mut store, &id, &outcome);
        let redacted = store.request_redacted(&id, "session-a", 60_000).unwrap();
        assert_eq!(redacted["status"], "redacted");
        assert_eq!(redacted["result"], "[REDACTED]");
        assert_eq!(
            store.check(&id, "session-a").unwrap()["status"],
            "dangerous"
        );
        assert!(store.claim_next("config-a").unwrap().is_none());
        assert_eq!(
            store.request_redacted(&id, "session-b", 60_000).unwrap()["status"],
            "unavailable"
        );
    }
}

#[test]
fn local_fallback_notice_reaches_the_caller_but_is_not_replayed_from_cache() {
    let (_temp, mut store) = setup();
    let first = store.enqueue(job(json!("large tool output"))).unwrap();
    let mut outcome = approved();
    outcome.notice = Some(ScanNotice::api_usage_limit("local", Some(120)));
    finish(&mut store, &first, &outcome);
    let result = store.check(&first, "session-a").unwrap();
    assert_eq!(result["status"], "approved");
    assert_eq!(
        result["notice"],
        json!({"code":"api_usage_limit","fallback":"local","retry_after":120})
    );

    let second = store.enqueue(job(json!("large tool output"))).unwrap();
    let cached = store.check(&second, "session-a").unwrap();
    assert_eq!(cached["cached"], true);
    assert!(cached.get("notice").is_none());
}

#[test]
fn usage_limit_failure_exposes_only_its_fixed_reason() {
    let (_temp, mut store) = setup();
    let id = store.enqueue(job(json!("large tool output"))).unwrap();
    let mut outcome = ScanOutcome::failed("usage_limit_reached");
    outcome.notice = Some(ScanNotice::api_usage_limit("none", None));
    finish(&mut store, &id, &outcome);
    let result = store.check(&id, "session-a").unwrap();
    assert_eq!(result["status"], "failed");
    assert_eq!(result["reason"], "usage_limit_reached");
    assert_eq!(
        result["notice"],
        json!({"code":"api_usage_limit","fallback":"none"})
    );

    let other = store.enqueue(job(json!("other output"))).unwrap();
    finish(
        &mut store,
        &other,
        &ScanOutcome::failed("SECRET backend output"),
    );
    let hidden = store.check(&other, "session-a").unwrap();
    assert!(hidden.get("reason").is_none());
}

#[test]
fn authentication_failures_expose_their_fixed_reason() {
    let (_temp, mut store) = setup();
    for reason in [
        "authentication_missing",
        "authentication_expired",
        "authentication_rejected",
    ] {
        let id = store
            .enqueue(job(json!(format!("output {reason}"))))
            .unwrap();
        let mut outcome = ScanOutcome::failed(reason);
        outcome.notice = Some(ScanNotice::api_authentication(reason, "none"));
        finish(&mut store, &id, &outcome);
        let result = store.check(&id, "session-a").unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason"], reason);
        assert_eq!(
            result["notice"],
            json!({"code": format!("api_{reason}"), "fallback": "none"})
        );
    }
}

#[test]
fn fixed_failure_and_incomplete_codes_are_exposed() {
    let (_temp, mut store) = setup();
    for (status, reason) in [
        (JobStatus::Failed, "scan_timeout"),
        (JobStatus::Failed, "local_scanner_error"),
        (JobStatus::Failed, "api_unavailable"),
        (JobStatus::Incomplete, "incomplete_classification"),
    ] {
        let id = store
            .enqueue(job(json!(format!("output {reason}"))))
            .unwrap();
        let mut outcome = ScanOutcome::failed(reason);
        outcome.status = status;
        finish(&mut store, &id, &outcome);
        let result = store.check(&id, "session-a").unwrap();
        assert_eq!(result["reason"], reason, "{result}");
    }
}
