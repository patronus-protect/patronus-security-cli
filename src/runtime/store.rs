//! Durable scan jobs. A process lock and the service mutex serialize all writers.
use super::protocol::{Direction, JobStatus, ScanOutcome, Verdict};
use super::result_cache::ResultCache;
use super::RuntimeResult;
use fs2::FileExt;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct StoreLimits {
    pub max_payload_bytes: usize,
    pub max_store_bytes: u64,
    pub max_pending_jobs: usize,
    pub retention_seconds: u64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: 10_485_760,
            max_store_bytes: 536_870_912,
            max_pending_jobs: 64,
            retention_seconds: 30 * 86_400,
        }
    }
}

pub struct NewJob {
    pub policy_scope: Option<String>,
    pub session_hash: String,
    pub direction: Direction,
    pub tool: String,
    pub call_id: String,
    pub payload: Value,
    pub config_hash: String,
    pub deadline_ms: i64,
}

pub struct JobWork {
    pub policy_scope: Option<String>,
    pub scan_id: String,
    pub direction: Direction,
    pub payload: Value,
    pub deadline_ms: i64,
    pub refinement: Option<ScanOutcome>,
}

#[derive(Debug, thiserror::Error)]
pub enum CompletionError {
    #[error("runtime result exceeds storage limit")]
    Capacity,
    #[error("{0}")]
    Storage(String),
}

impl From<String> for CompletionError {
    fn from(error: String) -> Self {
        Self::Storage(error)
    }
}

pub struct Store {
    db: Connection,
    root: PathBuf,
    limits: StoreLimits,
    cache: ResultCache,
    // File locks are released by closing the file, including after a crash.
    _lock: File,
}

struct StoredJob {
    direction: String,
    status: String,
    payload_hash: String,
    redacted_hash: Option<String>,
    outcome: Option<String>,
    cached: bool,
}

impl Store {
    pub fn open(root: &Path, limits: StoreLimits) -> RuntimeResult<Self> {
        Self::open_with_cache(root, &root.join("result-cache"), limits)
    }

    pub fn open_with_cache(
        root: &Path,
        cache_root: &Path,
        limits: StoreLimits,
    ) -> RuntimeResult<Self> {
        if limits.retention_seconds == 0
            || limits.max_payload_bytes == 0
            || limits.max_pending_jobs == 0
        {
            return Err("invalid store limits".into());
        }
        private_directory(root)?;
        let cache = ResultCache::open(cache_root, limits.max_payload_bytes)?;
        let lock = private_file(&root.join(".lock"))?;
        lock.try_lock_exclusive()
            .map_err(|_| "runtime store is already in use")?;
        let database_path = root.join("jobs.sqlite3");
        let _database_file = private_file(&database_path)?;
        // SQLite opens these paths itself; never allow pre-existing symlinks.
        for suffix in ["-journal", "-wal", "-shm"] {
            let path = root.join(format!("jobs.sqlite3{suffix}"));
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    private_file(&path)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("runtime storage unavailable".into()),
            }
        }
        let db = sql(Connection::open(&database_path))?;
        sql(db.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",
        ))?;
        let version: i64 = sql(db.query_row("PRAGMA user_version", [], |r| r.get(0)))?;
        if version != 0 && version != 1 && version != 2 && version != 3 {
            return Err("unsupported runtime store version".into());
        }
        sql(db.execute_batch(
            "CREATE TABLE IF NOT EXISTS jobs (
                scan_id TEXT PRIMARY KEY, session_hash TEXT NOT NULL,
                direction TEXT NOT NULL, tool TEXT NOT NULL, call_id TEXT NOT NULL,
                config_hash TEXT NOT NULL, payload_hash TEXT NOT NULL,
                payload_bytes INTEGER NOT NULL, redacted_hash TEXT,
                redacted_bytes INTEGER NOT NULL DEFAULT 0, outcome TEXT,
                status TEXT NOT NULL, deadline_ms INTEGER NOT NULL,
                expires_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS jobs_expiry ON jobs(expires_ms);
             CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status, created_ms);
             CREATE TABLE IF NOT EXISTS redaction_jobs (
                 parent_id TEXT PRIMARY KEY, child_id TEXT NOT NULL UNIQUE
             );
             CREATE TABLE IF NOT EXISTS storage_usage (
                 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                 bytes INTEGER NOT NULL CHECK(bytes>=0)
             );
             INSERT OR REPLACE INTO storage_usage SELECT 1,
                 COALESCE(SUM(payload_bytes+redacted_bytes+length(CAST(COALESCE(outcome,'') AS BLOB))),0) FROM jobs;
             CREATE TRIGGER IF NOT EXISTS usage_insert AFTER INSERT ON jobs BEGIN
                 UPDATE storage_usage SET bytes=bytes+NEW.payload_bytes+NEW.redacted_bytes+length(CAST(COALESCE(NEW.outcome,'') AS BLOB));
             END;
             CREATE TRIGGER IF NOT EXISTS usage_update AFTER UPDATE OF payload_bytes,redacted_bytes,outcome ON jobs BEGIN
                 UPDATE storage_usage SET bytes=bytes+NEW.payload_bytes+NEW.redacted_bytes+length(CAST(COALESCE(NEW.outcome,'') AS BLOB))
                     -OLD.payload_bytes-OLD.redacted_bytes-length(CAST(COALESCE(OLD.outcome,'') AS BLOB));
             END;
             CREATE TRIGGER IF NOT EXISTS usage_delete AFTER DELETE ON jobs BEGIN
                 UPDATE storage_usage SET bytes=bytes-OLD.payload_bytes-OLD.redacted_bytes-length(CAST(COALESCE(OLD.outcome,'') AS BLOB));
             END;
",
        ))?;
        if version < 2 {
            sql(db.execute_batch(
                "ALTER TABLE jobs ADD COLUMN policy_scope TEXT; PRAGMA user_version=2;",
            ))?;
        }
        if version < 3 {
            sql(db.execute_batch(
                "ALTER TABLE jobs ADD COLUMN cached INTEGER NOT NULL DEFAULT 0; PRAGMA user_version=3;",
            ))?;
        }
        Ok(Self {
            db,
            root: root.to_path_buf(),
            limits,
            cache,
            _lock: lock,
        })
    }

    pub fn enqueue(&mut self, job: NewJob) -> RuntimeResult<String> {
        self.cleanup()?;
        if [&job.session_hash, &job.tool, &job.call_id, &job.config_hash]
            .iter()
            .any(|s| s.is_empty() || s.len() > 2048)
        {
            return Err("invalid job metadata".into());
        }
        let payload = encode(&job.payload)?;
        if payload.len() > self.limits.max_payload_bytes {
            return Err("payload exceeds configured limit".into());
        }
        let payload_hash = digest(&payload);
        let direction = match job.direction {
            Direction::Request => "request",
            Direction::Response => "response",
        };
        let cache_key = ResultCache::key(
            &job.config_hash,
            &payload_hash,
            direction,
            job.policy_scope.as_deref(),
        );
        let cached = if job.tool == "redaction" {
            None
        } else {
            self.cache.load(&cache_key, now())?
        };
        let cached = cached
            .map(|(outcome, redacted)| -> RuntimeResult<_> {
                let reusable = outcome.status == JobStatus::Completed
                    && complete_coverage(&outcome)
                    && matches!(
                        outcome.verdict,
                        Some(Verdict::Approved | Verdict::Dangerous)
                    )
                    && (outcome.verdict != Some(Verdict::Approved) || outcome.findings.is_empty());
                if !reusable {
                    return Ok(None);
                }
                let metadata = String::from_utf8(encode(&outcome)?)
                    .map_err(|_| "invalid scan metadata".to_string())?;
                let redacted = redacted.as_ref().map(encode).transpose()?;
                let redacted_hash = redacted.as_deref().map(digest);
                Ok(Some((metadata, redacted, redacted_hash)))
            })
            .transpose()?
            .flatten();
        if cached.is_none() && self.pending_count()? >= self.limits.max_pending_jobs {
            return Err("runtime queue is full".into());
        }
        let id = rand::random::<[u8; 16]>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let path = self.payload_path(&id, "original")?;
        let redacted_path = self.payload_path(&id, "redacted")?;
        let cached_redacted = cached.as_ref().and_then(|(_, bytes, _)| bytes.as_ref());
        let cached_metadata_bytes = cached.as_ref().map_or(0, |(value, _, _)| value.len());
        self.capacity(
            payload
                .len()
                .saturating_add(cached_metadata_bytes)
                .saturating_add(cached_redacted.map_or(0, Vec::len)),
        )?;
        write_private(&path, &payload)?;
        if let Some(bytes) = cached_redacted {
            write_private(&redacted_path, bytes)?;
        }
        let now = now();
        let expires = now.saturating_add(
            self.limits
                .retention_seconds
                .saturating_mul(1000)
                .min(i64::MAX as u64) as i64,
        );
        let result = (|| {
            let tx = sql(self.db.transaction())?;
            let (status, outcome, redacted_hash, redacted_bytes, cache_hit) = match &cached {
                Some((outcome, redacted, redacted_hash)) => (
                    "completed",
                    Some(outcome.as_str()),
                    redacted_hash.as_deref(),
                    redacted.as_ref().map_or(0, Vec::len) as i64,
                    1,
                ),
                None => ("queued", None, None, 0, 0),
            };
            sql(tx.execute(
                "INSERT INTO jobs (scan_id,session_hash,direction,tool,call_id,config_hash,payload_hash,payload_bytes,status,deadline_ms,expires_ms,created_ms,policy_scope,outcome,redacted_hash,redacted_bytes,cached)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![id, job.session_hash, direction, job.tool, job.call_id, job.config_hash,
                    payload_hash, payload.len() as i64, status, job.deadline_ms, expires, now,
                    job.policy_scope, outcome, redacted_hash, redacted_bytes, cache_hit],
            ))?;
            sql(tx.commit())
        })();
        if result.is_err() {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(redacted_path);
        }
        result?;
        Ok(id)
    }

    pub fn claim_next(&mut self, config_hash: &str) -> RuntimeResult<Option<JobWork>> {
        self.cleanup()?;
        let tx = sql(self.db.transaction())?;
        let next: Option<(String, String, i64, String, Option<String>)> = sql(tx.query_row(
            "SELECT scan_id,payload_hash,deadline_ms,direction,policy_scope FROM jobs WHERE status='queued' AND config_hash=?1 ORDER BY created_ms,rowid LIMIT 1",
            [config_hash], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).optional())?;
        if let Some((id, hash, deadline_ms, direction, policy_scope)) = next {
            let direction = match direction.as_str() {
                "request" => Direction::Request,
                "response" => Direction::Response,
                _ => return Err("invalid stored scan direction".into()),
            };
            sql(tx.execute("UPDATE jobs SET status='running' WHERE scan_id=?1", [&id]))?;
            sql(tx.commit())?;
            match self.read_payload(&id, "original", &hash) {
                Ok(payload) => Ok(Some(JobWork {
                    policy_scope,
                    refinement: self.refinement_original(&id)?,
                    scan_id: id,
                    direction,
                    payload,
                    deadline_ms,
                })),
                Err(error) => {
                    sql(self
                        .db
                        .execute("UPDATE jobs SET status='failed' WHERE scan_id=?1", [&id]))?;
                    Err(error)
                }
            }
        } else {
            sql(tx.commit())?;
            Ok(None)
        }
    }

    pub fn complete(
        &mut self,
        scan_id: &str,
        outcome: &ScanOutcome,
    ) -> Result<(), CompletionError> {
        self.cleanup()?;
        if !valid_id(scan_id) {
            return Err(CompletionError::Storage("invalid scan identifier".into()));
        }
        let stored: Option<(String, String, String, Option<String>, i64, String)> = sql(self
            .db
            .query_row(
                "SELECT direction,config_hash,payload_hash,policy_scope,expires_ms,tool FROM jobs WHERE scan_id=?1 AND status='running'",
                [scan_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .optional())?;
        let Some((direction, config_hash, payload_hash, policy_scope, expires_ms, tool)) = stored
        else {
            return Ok(());
        };
        let mut outcome = outcome.clone();
        // Backend error strings are not part of the public protocol or persisted metadata.
        outcome.reason = None;
        let mut redacted = outcome.redacted.take();
        if outcome.status == JobStatus::Completed
            && (!complete_coverage(&outcome)
                || outcome.verdict.is_none()
                || (outcome.verdict == Some(Verdict::Approved) && !outcome.findings.is_empty()))
        {
            outcome.status = JobStatus::Incomplete;
            outcome.verdict = None;
        }
        if matches!(outcome.status, JobStatus::Queued | JobStatus::Running) {
            outcome = ScanOutcome::failed("invalid scanner state");
            outcome.reason = None;
        }
        if direction != "response"
            || outcome.status != JobStatus::Completed
            || outcome.verdict != Some(Verdict::Dangerous)
        {
            redacted = None;
        }
        let metadata = encode(&outcome)?;
        let redacted_value = redacted;
        let redacted = redacted_value.as_ref().map(encode).transpose()?;
        let redacted_size = redacted.as_ref().map_or(0, Vec::len);
        if redacted_size > self.limits.max_payload_bytes
            || !self.fits_capacity(metadata.len().saturating_add(redacted_size))?
        {
            sql(self.db.execute(
                "UPDATE jobs SET status='failed' WHERE scan_id=?1",
                [scan_id],
            ))?;
            return Err(CompletionError::Capacity);
        }
        let redacted_path = self.payload_path(scan_id, "redacted")?;
        let redacted_hash = if let Some(bytes) = redacted {
            write_private(&redacted_path, &bytes)?;
            Some(digest(&bytes))
        } else {
            None
        };
        let status = state_name(outcome.status);
        let result = sql(self.db.execute(
            "UPDATE jobs SET status=?2,outcome=?3,redacted_hash=?4,redacted_bytes=?5 WHERE scan_id=?1 AND status='running' AND deadline_ms>?6 AND expires_ms>?6",
            params![scan_id, status, String::from_utf8(metadata).map_err(|_| "invalid scan metadata".to_string())?, redacted_hash, redacted_size as i64, now()],
        ));
        if !matches!(result, Ok(1)) && redacted_hash.is_some() {
            let _ = fs::remove_file(redacted_path);
        }
        let updated = result.map_err(CompletionError::Storage)?;
        if updated == 1
            && tool != "redaction"
            && outcome.status == JobStatus::Completed
            && complete_coverage(&outcome)
            && matches!(
                outcome.verdict,
                Some(Verdict::Approved | Verdict::Dangerous)
            )
        {
            let key = ResultCache::key(
                &config_hash,
                &payload_hash,
                &direction,
                policy_scope.as_deref(),
            );
            let _ = self
                .cache
                .store(&key, expires_ms, &outcome, redacted_value.as_ref());
        }
        Ok(())
    }

    pub fn check(&mut self, scan_id: &str, session_hash: &str) -> RuntimeResult<Value> {
        self.cleanup()?;
        let Some(job) = self.lookup(scan_id, session_hash)? else {
            return Ok(unavailable());
        };
        let outcome = job.outcome.as_deref().map(decode_outcome).transpose()?;
        let status = external_status(&job.status, outcome.as_ref());
        let redacted_available =
            status == "dangerous" && job.direction == "response" && job.redacted_hash.is_some();
        let mut result = json!({"scan_id":scan_id, "status":status, "job_status":job.status, "cached":job.cached,
            "findings":outcome.as_ref().map(|o| &o.findings).cloned().unwrap_or_default(),
            "coverage":outcome.as_ref().map(|o| &o.coverage), "redacted_available":redacted_available});
        if status == "approved" && job.direction == "response" {
            result["result"] = self.read_payload(scan_id, "original", &job.payload_hash)?;
        }
        Ok(result)
    }

    pub fn read_redacted(&mut self, scan_id: &str, session_hash: &str) -> RuntimeResult<Value> {
        self.cleanup()?;
        let Some(job) = self.lookup(scan_id, session_hash)? else {
            return Ok(unavailable());
        };
        let outcome = job.outcome.as_deref().map(decode_outcome).transpose()?;
        if job.direction != "response"
            || external_status(&job.status, outcome.as_ref()) != "dangerous"
        {
            return Ok(unavailable());
        }
        let Some(hash) = job.redacted_hash else {
            return Ok(unavailable());
        };
        Ok(
            json!({"scan_id":scan_id,"status":"redacted","result":self.read_payload(scan_id,"redacted",&hash)?}),
        )
    }

    /// Schedule at most one private refinement job; the public scan stays dangerous.
    pub fn request_redacted(
        &mut self,
        scan_id: &str,
        session_hash: &str,
        timeout_ms: u64,
    ) -> RuntimeResult<Value> {
        let status = self.check(scan_id, session_hash)?;
        if status["status"] != "dangerous" || status["redacted_available"] != true {
            return Ok(unavailable());
        }
        // Privacy spans are already masked by the completed scan. Refinement
        // only narrows injection regions; do not queue another worker for PII/DLP.
        if status["findings"].as_array().is_some_and(|findings| {
            !findings.is_empty()
                && findings
                    .iter()
                    .all(|finding| matches!(finding["category"].as_str(), Some("pii" | "dlp")))
        }) {
            return self.read_redacted(scan_id, session_hash);
        }
        let child: Option<String> = sql(self
            .db
            .query_row(
                "SELECT child_id FROM redaction_jobs WHERE parent_id=?1",
                [scan_id],
                |r| r.get(0),
            )
            .optional())?;
        if let Some(child) = child {
            let state = self.check(&child, session_hash)?;
            if state["status"] == "pending" {
                return Ok(json!({"scan_id":scan_id,"status":"pending"}));
            }
            let mut refined = self.read_redacted(&child, session_hash)?;
            if refined["status"] == "redacted" {
                refined["scan_id"] = json!(scan_id);
                return Ok(refined);
            }
            return self.read_redacted(scan_id, session_hash);
        }
        // Internal child IDs are never exported or accepted as a second refinement root.
        let internal: bool = sql(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM redaction_jobs WHERE child_id=?1)",
            [scan_id],
            |r| r.get(0),
        ))?;
        if internal {
            return self.read_redacted(scan_id, session_hash);
        }
        let job = self
            .lookup(scan_id, session_hash)?
            .ok_or("scan unavailable")?;
        let (config_hash, expires, policy_scope): (String, i64, Option<String>) =
            sql(self.db.query_row(
                "SELECT config_hash,expires_ms,policy_scope FROM jobs WHERE scan_id=?1",
                [scan_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ))?;
        let payload = self.read_payload(scan_id, "original", &job.payload_hash)?;
        let child = match self.enqueue(NewJob {
            policy_scope,
            session_hash: session_hash.into(),
            direction: Direction::Response,
            tool: "redaction".into(),
            call_id: scan_id.into(),
            payload,
            config_hash,
            deadline_ms: now()
                .saturating_add(timeout_ms.min(60_000) as i64)
                .min(expires),
        }) {
            Ok(child) => child,
            Err(_) => return self.read_redacted(scan_id, session_hash),
        };
        sql(self.db.execute(
            "INSERT INTO redaction_jobs(parent_id,child_id) VALUES (?1,?2)",
            params![scan_id, child],
        ))?;
        // Refinement must not extend retention of the duplicated original bytes.
        sql(self.db.execute(
            "UPDATE jobs SET expires_ms=?2 WHERE scan_id=?1",
            params![child, expires],
        ))?;
        Ok(json!({"scan_id":scan_id,"status":"pending"}))
    }

    fn refinement_original(&self, child: &str) -> RuntimeResult<Option<ScanOutcome>> {
        let parent: Option<String> = sql(self
            .db
            .query_row(
                "SELECT parent_id FROM redaction_jobs WHERE child_id=?1",
                [child],
                |r| r.get(0),
            )
            .optional())?;
        let Some(parent) = parent else {
            return Ok(None);
        };
        let stored: Option<(String, String)> = sql(self
            .db
            .query_row(
                "SELECT outcome,redacted_hash FROM jobs WHERE scan_id=?1 AND status='completed'",
                [&parent],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional())?;
        let Some((metadata, hash)) = stored else {
            return Ok(Some(ScanOutcome::failed("redaction source expired")));
        };
        let mut outcome = decode_outcome(&metadata)?;
        outcome.redacted = Some(self.read_payload(&parent, "redacted", &hash)?);
        Ok(Some(outcome))
    }

    pub fn cancel(&mut self, scan_id: &str, session_hash: &str) -> RuntimeResult<Value> {
        self.cleanup()?;
        if !valid_id(scan_id) {
            return Ok(unavailable());
        }
        sql(self.db.execute(
            "UPDATE jobs SET status='cancelled' WHERE scan_id=?1 AND session_hash=?2 AND status IN ('queued','running')",
            params![scan_id, session_hash],
        ))?;
        // Cancellation reports state only; it must not become an alternative payload reader.
        let Some(job) = self.lookup(scan_id, session_hash)? else {
            return Ok(unavailable());
        };
        let outcome = job.outcome.as_deref().map(decode_outcome).transpose()?;
        Ok(
            json!({"scan_id":scan_id,"status":external_status(&job.status,outcome.as_ref()),"job_status":job.status}),
        )
    }

    pub fn recover(&mut self, config_hash: &str) -> RuntimeResult<()> {
        self.cleanup()?;
        let tx = sql(self.db.transaction())?;
        sql(tx.execute("UPDATE jobs SET status='incomplete' WHERE config_hash<>?1 AND status IN ('queued','running','completed')", [config_hash]))?;
        sql(tx.execute(
            "UPDATE jobs SET status='queued' WHERE config_hash=?1 AND status='running'",
            [config_hash],
        ))?;
        sql(tx.commit())?;
        // A crash between file fsync and SQLite commit can leave an orphan payload.
        for entry in disk(fs::read_dir(&self.root))? {
            let entry = disk(entry)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some((id, kind)) = name.split_once('.') else {
                continue;
            };
            if !valid_id(id) || !matches!(kind, "original.json" | "redacted.json") {
                continue;
            }
            let exists: bool = sql(self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM jobs WHERE scan_id=?1 AND (?2='original.json' OR redacted_hash IS NOT NULL))",
                params![id,kind], |r| r.get(0),
            ))?;
            if !exists {
                disk(fs::remove_file(entry.path()))?;
            }
        }
        sync_directory(&self.root)
    }

    pub fn cleanup(&mut self) -> RuntimeResult<()> {
        let now = now();
        sql(self.db.execute("UPDATE jobs SET status='expired' WHERE deadline_ms<=?1 AND status IN ('queued','running')", [now]))?;
        let expired: Vec<String> = {
            let mut stmt = sql(self
                .db
                .prepare("SELECT scan_id FROM jobs WHERE expires_ms<=?1"))?;
            let rows = sql(stmt.query_map([now], |r| r.get(0)))?;
            sql(rows.collect())?
        };
        if expired.is_empty() {
            return Ok(());
        }
        for id in &expired {
            for kind in ["original", "redacted"] {
                match fs::remove_file(self.payload_path(id, kind)?) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err("runtime cleanup failed".into()),
                }
            }
        }
        let tx = sql(self.db.transaction())?;
        for id in expired {
            sql(tx.execute("DELETE FROM jobs WHERE scan_id=?1", [id]))?;
        }
        sql(tx.execute(
            "DELETE FROM redaction_jobs WHERE child_id NOT IN (SELECT scan_id FROM jobs)",
            [],
        ))?;
        sql(tx.commit())?;
        sync_directory(&self.root)
    }

    pub fn pending_count(&self) -> RuntimeResult<usize> {
        sql(self.db.query_row("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running') AND deadline_ms>?1 AND expires_ms>?1", [now()], |r| r.get(0)))
    }

    fn lookup(&self, id: &str, owner: &str) -> RuntimeResult<Option<StoredJob>> {
        if !valid_id(id) {
            return Ok(None);
        }
        sql(self.db.query_row(
            "SELECT direction,status,payload_hash,redacted_hash,outcome,cached FROM jobs WHERE scan_id=?1 AND session_hash=?2",
            params![id,owner], |r| Ok(StoredJob {direction:r.get(0)?,status:r.get(1)?,payload_hash:r.get(2)?,redacted_hash:r.get(3)?,outcome:r.get(4)?,cached:r.get::<_,i64>(5)? != 0}),
        ).optional())
    }

    fn capacity(&self, additional: usize) -> RuntimeResult<()> {
        if !self.fits_capacity(additional)? {
            Err("runtime storage limit reached".into())
        } else {
            Ok(())
        }
    }

    fn fits_capacity(&self, additional: usize) -> RuntimeResult<bool> {
        let used: u64 = sql(self.db.query_row(
            "SELECT bytes FROM storage_usage WHERE singleton=1",
            [],
            |r| r.get(0),
        ))?;
        Ok(used.saturating_add(additional as u64) <= self.limits.max_store_bytes)
    }

    fn payload_path(&self, id: &str, kind: &str) -> RuntimeResult<PathBuf> {
        if !valid_id(id) {
            return Err("invalid stored scan identifier".into());
        }
        Ok(self.root.join(format!("{id}.{kind}.json")))
    }

    fn read_payload(&self, id: &str, kind: &str, hash: &str) -> RuntimeResult<Value> {
        let file = checked_open(&self.payload_path(id, kind)?)?;
        let mut bytes = Vec::new();
        disk(
            file.take((self.limits.max_payload_bytes as u64).saturating_add(1))
                .read_to_end(&mut bytes),
        )?;
        if bytes.len() > self.limits.max_payload_bytes || digest(&bytes) != hash {
            return Err("stored payload integrity check failed".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| "stored payload is invalid".into())
    }
}

fn complete_coverage(outcome: &ScanOutcome) -> bool {
    let c = &outcome.coverage;
    c.complete && c.fields_scanned == c.fields_total && c.bytes_scanned == c.bytes_total
}

fn external_status<'a>(state: &'a str, outcome: Option<&ScanOutcome>) -> &'a str {
    match state {
        "queued" | "running" => "pending",
        "completed" => match outcome {
            Some(o) if o.status == JobStatus::Completed && complete_coverage(o) => {
                match o.verdict {
                    Some(Verdict::Approved) if o.findings.is_empty() => "approved",
                    Some(Verdict::Dangerous) => "dangerous",
                    _ => "incomplete",
                }
            }
            _ => "incomplete",
        },
        "failed" | "incomplete" | "cancelled" | "expired" => state,
        _ => "failed",
    }
}

fn state_name(state: JobStatus) -> &'static str {
    match state {
        JobStatus::Queued => "queued",
        JobStatus::Running => "running",
        JobStatus::Completed => "completed",
        JobStatus::Failed => "failed",
        JobStatus::Incomplete => "incomplete",
        JobStatus::Cancelled => "cancelled",
        JobStatus::Expired => "expired",
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn unavailable() -> Value {
    json!({"status":"unavailable"})
}
fn encode(value: &impl serde::Serialize) -> RuntimeResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| "invalid runtime data".into())
}
fn decode_outcome(text: &str) -> RuntimeResult<ScanOutcome> {
    serde_json::from_str(text).map_err(|_| "stored scan metadata is invalid".into())
}
fn sql<T>(result: rusqlite::Result<T>) -> RuntimeResult<T> {
    result.map_err(|_| "runtime database unavailable".into())
}
fn disk<T>(result: std::io::Result<T>) -> RuntimeResult<T> {
    result.map_err(|_| "runtime storage unavailable".into())
}

fn private_directory(path: &Path) -> RuntimeResult<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        disk(builder.create(path))?;
    }
    let meta = disk(fs::symlink_metadata(path))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("runtime directory is not a private directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        disk(fs::set_permissions(path, fs::Permissions::from_mode(0o700)))?;
    }
    Ok(())
}

fn new_private_file(path: &Path) -> RuntimeResult<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    disk(options.open(path))
}

fn private_file(path: &Path) -> RuntimeResult<File> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let file = checked_open(path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                disk(file.set_permissions(fs::Permissions::from_mode(0o600)))?;
            }
            Ok(file)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => new_private_file(path),
        Err(_) => Err("runtime storage unavailable".into()),
    }
}

fn checked_open(path: &Path) -> RuntimeResult<File> {
    let before = disk(fs::symlink_metadata(path))?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err("runtime file is not a private regular file".into());
    }
    let file = disk(File::open(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let after = disk(file.metadata())?;
        if before.dev() != after.dev() || before.ino() != after.ino() || after.nlink() != 1 {
            return Err("runtime file identity changed".into());
        }
    }
    Ok(file)
}

fn write_private(path: &Path, bytes: &[u8]) -> RuntimeResult<()> {
    let mut file = new_private_file(path)?;
    let result = (|| {
        disk(file.write_all(bytes).and_then(|_| file.sync_all()))?;
        sync_directory(path.parent().ok_or("invalid runtime payload path")?)
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn sync_directory(root: &Path) -> RuntimeResult<()> {
    #[cfg(test)]
    if FAIL_DIRECTORY_SYNC.with(|fail| fail.replace(false)) {
        return Err("runtime storage unavailable".into());
    }
    #[cfg(unix)]
    {
        disk(File::open(root).and_then(|dir| dir.sync_all()))?;
    }
    let _ = root;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAIL_DIRECTORY_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::protocol::PayloadCoverage;

    #[test]
    fn directory_sync_failure_rolls_back_original_and_redacted_payloads() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(temp.path(), StoreLimits::default()).unwrap();
        let input = || NewJob {
            policy_scope: None,
            session_hash: "session-a".into(),
            direction: Direction::Response,
            tool: "document".into(),
            call_id: "call-1".into(),
            payload: json!("SECRET"),
            config_hash: "config-a".into(),
            deadline_ms: now() + 60_000,
        };
        FAIL_DIRECTORY_SYNC.with(|fail| fail.set(true));
        assert!(store.enqueue(input()).is_err());
        assert_eq!(store.pending_count().unwrap(), 0);
        assert!(!fs::read_dir(temp.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".original.json")
        }));

        let id = store.enqueue(input()).unwrap();
        store.claim_next("config-a").unwrap().unwrap();
        let outcome = ScanOutcome {
            status: JobStatus::Completed,
            verdict: Some(Verdict::Dangerous),
            findings: vec![],
            coverage: PayloadCoverage {
                complete: true,
                ..PayloadCoverage::default()
            },
            redacted: Some(json!("[redacted]")),
            reason: None,
        };
        FAIL_DIRECTORY_SYNC.with(|fail| fail.set(true));
        assert!(store.complete(&id, &outcome).is_err());
        assert!(!store.payload_path(&id, "redacted").unwrap().exists());
        let receipt = store.check(&id, "session-a").unwrap();
        assert_eq!(receipt["status"], "pending");
        assert_eq!(receipt["redacted_available"], false);
        // A retry must succeed without a stale file colliding with create_new.
        store.complete(&id, &outcome).unwrap();
        assert_eq!(
            store.read_redacted(&id, "session-a").unwrap()["result"],
            "[redacted]"
        );
    }
}
