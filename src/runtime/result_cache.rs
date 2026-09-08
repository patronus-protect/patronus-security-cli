use super::protocol::ScanOutcome;
use super::RuntimeResult;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SCHEMA: &str = "patronus.runtime.result-cache.v1";

#[derive(Serialize, Deserialize)]
struct Entry {
    schema: String,
    expires_ms: i64,
    outcome: ScanOutcome,
    redacted: Option<Value>,
}

pub struct ResultCache {
    root: PathBuf,
    max_entry_bytes: usize,
}

impl ResultCache {
    pub fn open(root: &Path, max_payload_bytes: usize) -> RuntimeResult<Self> {
        private_directory(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            max_entry_bytes: max_payload_bytes.saturating_mul(2),
        })
    }

    pub fn key(
        config_hash: &str,
        payload_hash: &str,
        direction: &str,
        policy_scope: Option<&str>,
    ) -> String {
        blake3::hash(
            format!(
                "{config_hash}\0{payload_hash}\0{direction}\0{}",
                policy_scope.unwrap_or("")
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string()
    }

    pub fn load(
        &self,
        key: &str,
        now_ms: i64,
    ) -> RuntimeResult<Option<(ScanOutcome, Option<Value>)>> {
        let path = self.path(key)?;
        let file = match checked_open(&path) {
            Ok(file) => file,
            Err(error) if error == "cache entry missing" => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take((self.max_entry_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| "runtime cache unavailable".to_string())?;
        if bytes.len() > self.max_entry_bytes {
            return Err("runtime cache entry exceeds limit".into());
        }
        let entry: Entry = serde_json::from_slice(&bytes)
            .map_err(|_| "runtime cache entry is invalid".to_string())?;
        if entry.schema != SCHEMA {
            return Err("runtime cache entry is invalid".into());
        }
        if entry.expires_ms <= now_ms {
            let _ = fs::remove_file(path);
            return Ok(None);
        }
        Ok(Some((entry.outcome, entry.redacted)))
    }

    pub fn store(
        &self,
        key: &str,
        expires_ms: i64,
        outcome: &ScanOutcome,
        redacted: Option<&Value>,
    ) -> RuntimeResult<()> {
        let path = self.path(key)?;
        let bytes = serde_json::to_vec(&Entry {
            schema: SCHEMA.into(),
            expires_ms,
            outcome: outcome.clone(),
            redacted: redacted.cloned(),
        })
        .map_err(|_| "runtime cache entry is invalid".to_string())?;
        if bytes.len() > self.max_entry_bytes {
            return Ok(());
        }
        let temporary = self
            .root
            .join(format!(".{key}.{:016x}.tmp", rand::random::<u64>()));
        let mut file = new_private_file(&temporary)?;
        let result = (|| {
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "runtime cache unavailable".to_string())?;
            crate::atomic_file::replace(&temporary, &path)
                .map_err(|_| "runtime cache unavailable".to_string())?;
            File::open(&self.root)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| "runtime cache unavailable".to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn path(&self, key: &str) -> RuntimeResult<PathBuf> {
        if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid runtime cache key".into());
        }
        Ok(self.root.join(format!("{key}.json")))
    }
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
        builder
            .create(path)
            .map_err(|_| "runtime cache unavailable".to_string())?;
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "runtime cache unavailable".to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("runtime cache is not a private directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "runtime cache unavailable".to_string())?;
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
    options
        .open(path)
        .map_err(|_| "runtime cache unavailable".to_string())
}

fn checked_open(path: &Path) -> RuntimeResult<File> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("cache entry missing".into())
        }
        Err(_) => return Err("runtime cache unavailable".into()),
    };
    if !before.is_file() || before.file_type().is_symlink() {
        return Err("runtime cache entry is not a private regular file".into());
    }
    let file = File::open(path).map_err(|_| "runtime cache unavailable".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let after = file
            .metadata()
            .map_err(|_| "runtime cache unavailable".to_string())?;
        if before.dev() != after.dev() || before.ino() != after.ino() || after.nlink() != 1 {
            return Err("runtime cache file identity changed".into());
        }
    }
    Ok(file)
}
