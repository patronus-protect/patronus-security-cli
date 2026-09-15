use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rand::Rng;
use serde::Serialize;

use crate::ark::FinalClassification;
use crate::chunk::ChunkRecord;
use crate::config::Config;
use crate::dashboard;
use crate::discovery::FileRecord;
use crate::error::{IoContext, Result, ScannerError};
use crate::report::{markdown, FailureRecord, Report};
use crate::target::{ScanTarget, TargetKind};

#[derive(Debug, Serialize)]
struct Manifest<'a> {
    schema: &'static str,
    run_id: &'a str,
    status: crate::report::ScanStatus,
    target_kind: TargetKind,
    scan_root: String,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    scanner_version: &'static str,
    ark_version: &'static str,
    artifact_hashes: std::collections::BTreeMap<String, String>,
    attestation: crate::dashboard::RunAttestation,
    authentication: String,
}

pub struct RunOutput {
    pub run_id: String,
    pub run_dir: PathBuf,
    started_at: DateTime<Utc>,
    include_chunk_content: bool,
    write_progress_events: bool,
}

#[derive(Serialize)]
struct ChunkArtifact<'a> {
    #[serde(flatten)]
    chunk: &'a ChunkRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<&'a str>,
}

impl RunOutput {
    pub fn create(
        output_root: &Path,
        include_chunk_content: bool,
        write_progress_events: bool,
    ) -> Result<Self> {
        let dashboard_root = crate::dashboard::workspace_root(output_root);
        crate::dashboard::ensure_directory(&dashboard_root)?;
        crate::dashboard::ensure_directory(output_root)?;
        let now = Utc::now();
        let suffix: u32 = rand::rng().random();
        let run_id = format!("{}-{suffix:08x}", now.format("%Y%m%dT%H%M%SZ"));
        let run_dir = output_root.join(&run_id);
        std::fs::create_dir(&run_dir).at(&run_dir)?;
        for name in [
            "files.jsonl",
            "chunks.jsonl",
            "classifications.jsonl",
            "failures.jsonl",
        ] {
            File::create(run_dir.join(name)).at(run_dir.join(name))?;
        }
        if write_progress_events {
            File::create(run_dir.join("progress.jsonl")).at(run_dir.join("progress.jsonl"))?;
        }
        Ok(Self {
            run_id,
            run_dir,
            started_at: now,
            include_chunk_content,
            write_progress_events,
        })
    }

    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    pub fn progress_path(&self) -> Option<PathBuf> {
        self.write_progress_events
            .then(|| self.run_dir.join("progress.jsonl"))
    }

    pub fn write_config(&self, config: &Config) -> Result<()> {
        atomic_write(
            &self.run_dir.join("effective-config.toml"),
            config.redacted_toml()?.as_bytes(),
        )
    }

    pub fn file(&self, record: &FileRecord) -> Result<()> {
        append_json(&self.run_dir.join("files.jsonl"), record)
    }
    pub fn chunk(&self, record: &ChunkRecord, content: &str) -> Result<()> {
        append_json(
            &self.run_dir.join("chunks.jsonl"),
            &ChunkArtifact {
                chunk: record,
                content: self.include_chunk_content.then_some(content),
            },
        )
    }
    pub fn classification(&self, record: &FinalClassification) -> Result<()> {
        append_json(&self.run_dir.join("classifications.jsonl"), record)
    }
    pub fn failure(&self, record: &FailureRecord) -> Result<()> {
        append_json(&self.run_dir.join("failures.jsonl"), record)
    }

    pub fn finalize(&self, target: &ScanTarget, report: &Report) -> Result<()> {
        atomic_json(&self.run_dir.join("findings.json"), &report.findings)?;
        atomic_json(&self.run_dir.join("report.json"), report)?;
        atomic_write(&self.run_dir.join("report.md"), markdown(report).as_bytes())?;
        let output_root = self.run_dir.parent().unwrap_or(&self.run_dir);
        let workspace_root = dashboard::workspace_root(output_root);
        let index_href = if workspace_root == output_root {
            "../index.html"
        } else {
            "../../index.html"
        };
        atomic_write(
            &self.run_dir.join("report.html"),
            dashboard::render_report_with_index(report, index_href).as_bytes(),
        )?;
        let mut hashes = std::collections::BTreeMap::new();
        for name in [
            "effective-config.toml",
            "files.jsonl",
            "chunks.jsonl",
            "classifications.jsonl",
            "findings.json",
            "failures.jsonl",
            "report.json",
            "report.md",
            "report.html",
        ] {
            let bytes = std::fs::read(self.run_dir.join(name)).at(self.run_dir.join(name))?;
            hashes.insert(
                name.into(),
                format!("blake3:{}", blake3::hash(&bytes).to_hex()),
            );
        }
        if self.write_progress_events {
            let name = "progress.jsonl";
            let bytes = std::fs::read(self.run_dir.join(name)).at(self.run_dir.join(name))?;
            hashes.insert(
                name.into(),
                format!("blake3:{}", blake3::hash(&bytes).to_hex()),
            );
        }
        let report_hash = hashes
            .get("report.json")
            .ok_or_else(|| ScannerError::Output("missing report hash".into()))?;
        let (attestation, authentication) = dashboard::attest_run(
            &workspace_root,
            &self.run_id,
            &target.root,
            report_hash,
            report.status,
        )?;
        let manifest = Manifest {
            schema: "patronus.security-scanner.manifest.v1",
            run_id: &self.run_id,
            status: report.status,
            target_kind: target.kind,
            scan_root: attestation.scan_root.clone(),
            started_at: self.started_at,
            completed_at: report.completed_at,
            scanner_version: crate::VERSION,
            ark_version: crate::ARK_VERSION,
            artifact_hashes: hashes,
            attestation,
            authentication,
        };
        atomic_json(&self.run_dir.join("manifest.json"), &manifest)?;
        atomic_write(
            &self.run_dir.join("COMPLETE"),
            b"patronus.security-scanner.complete.v1\n",
        )?;
        dashboard::prune_completed_reports(&workspace_root, output_root, 2)
    }
}

pub fn output_root(target: &ScanTarget, configured: &Path) -> PathBuf {
    if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        target.root.join(configured)
    }
}

fn append_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let file = OpenOptions::new().append(true).open(path).at(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| ScannerError::Output(error.to_string()))?;
    writer.write_all(b"\n").at(path)?;
    writer.flush().at(path)
}

fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| ScannerError::Output(error.to_string()))?;
    atomic_write(path, &bytes)
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ScannerError::Output("invalid output file name".into()))?;
    let suffix: u64 = rand::rng().random();
    let temporary = path.with_file_name(format!(".{file_name}.{suffix:016x}.tmp"));
    {
        let file = File::create(&temporary).at(&temporary)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(bytes).at(&temporary)?;
        writer.flush().at(&temporary)?;
        writer.get_ref().sync_all().at(&temporary)?;
    }
    if let Err(source) = crate::atomic_file::replace(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(ScannerError::Io {
            path: path.to_path_buf(),
            source,
        });
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent).at(parent)?.sync_all().at(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::atomic_write;
    use std::sync::{Arc, Barrier};

    #[test]
    fn concurrent_atomic_writes_never_mix_or_remove_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.html");
        atomic_write(&path, b"initial").unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let workers = [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .map(|contents| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    atomic_write(&path, contents).unwrap();
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        let result = std::fs::read(&path).unwrap();
        assert!(result == b"first" || result == b"second");
        assert!(!dir.path().read_dir().unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }
}
