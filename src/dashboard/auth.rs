use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::dashboard::ensure_directory;
use crate::error::{IoContext, Result, ScannerError};
use crate::protocol_event::ProtocolEvent;
use crate::report::ScanStatus;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunAttestation {
    pub workspace_id: String,
    pub run_id: String,
    pub scan_root: String,
    pub scan_root_id: String,
    pub report_hash: String,
    pub status: ScanStatus,
    pub scanner_version: String,
    pub ark_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolAttestation {
    pub workspace_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub previous_record_hash: Option<String>,
    pub event_hash: String,
}

pub fn attest_run(
    dashboard_root: &Path,
    run_id: &str,
    scan_root: &Path,
    report_hash: &str,
    status: ScanStatus,
) -> Result<(RunAttestation, String)> {
    ensure_directory(dashboard_root)?;
    let canonical_scan = std::fs::canonicalize(scan_root).at(scan_root)?;
    let attestation = RunAttestation {
        workspace_id: workspace_id(dashboard_root)?,
        run_id: run_id.into(),
        scan_root: canonical_scan.display().to_string(),
        scan_root_id: native_path_id(&canonical_scan),
        report_hash: report_hash.into(),
        status,
        scanner_version: crate::VERSION.into(),
        ark_version: crate::ARK_VERSION.into(),
    };
    let authentication = authenticate(&attestation)?;
    Ok((attestation, authentication))
}

pub(crate) fn verify_attestation(
    dashboard_root: &Path,
    attestation: &RunAttestation,
    authentication: &str,
) -> Result<bool> {
    Ok(attestation.workspace_id == workspace_id(dashboard_root)?
        && authentication == authenticate(attestation)?)
}

pub(crate) fn attest_protocol_event(
    dashboard_root: &Path,
    event: &ProtocolEvent,
    sequence: u64,
    previous_record_hash: Option<String>,
) -> Result<(ProtocolAttestation, String)> {
    ensure_directory(dashboard_root)?;
    let attestation = ProtocolAttestation {
        workspace_id: workspace_id(dashboard_root)?,
        session_id: event.session_id.clone(),
        sequence,
        previous_record_hash,
        event_hash: protocol_event_hash(event)?,
    };
    let authentication = authenticate_value(&attestation)?;
    Ok((attestation, authentication))
}

pub(crate) fn verify_protocol_attestation(
    dashboard_root: &Path,
    event: &ProtocolEvent,
    attestation: &ProtocolAttestation,
    authentication: &str,
) -> Result<bool> {
    Ok(attestation.workspace_id == workspace_id(dashboard_root)?
        && attestation.session_id == event.session_id
        && attestation.event_hash == protocol_event_hash(event)?
        && authentication == authenticate_value(attestation)?)
}

pub fn provision_dashboard_key() -> Result<()> {
    let root = key_root()?;
    ensure_directory(&root)?;
    #[cfg(unix)]
    set_mode_if_needed(&root, 0o700)?;
    let _ = load_or_create_key(false)?;
    #[cfg(unix)]
    set_mode_if_needed(&root.join("key.v1"), 0o600)?;
    Ok(())
}

#[cfg(unix)]
fn set_mode_if_needed(path: &Path, expected: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path).at(path)?;
    if metadata.permissions().mode() & 0o777 != expected {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(expected)).at(path)?;
    }
    Ok(())
}

fn authenticate(attestation: &RunAttestation) -> Result<String> {
    authenticate_value(attestation)
}

fn authenticate_value(value: &impl Serialize) -> Result<String> {
    let key = dashboard_key()?;
    let bytes =
        serde_json::to_vec(value).map_err(|error| ScannerError::Output(error.to_string()))?;
    Ok(format!(
        "blake3:{}",
        blake3::keyed_hash(&key, &bytes).to_hex()
    ))
}

fn dashboard_key() -> Result<[u8; 32]> {
    load_or_create_key(true)
}

fn load_or_create_key(validate_permissions: bool) -> Result<[u8; 32]> {
    let root = key_root()?;
    #[cfg(unix)]
    let root_missing = std::fs::symlink_metadata(&root)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
    #[cfg(not(unix))]
    let _ = validate_permissions;
    ensure_directory(&root)?;
    #[cfg(unix)]
    if root_missing {
        set_mode_if_needed(&root, 0o700)?;
    } else if validate_permissions {
        require_mode(&root, 0o700)?;
    }
    let path = root.join("key.v1");
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(ScannerError::Output(
                "refusing unsafe dashboard authentication key".into(),
            ))
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    file.write_all(&key).at(&path)?;
                    file.sync_all().at(&path)?;
                    return Ok(key);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(ScannerError::Io { path, source }),
            }
        }
        Err(source) => return Err(ScannerError::Io { path, source }),
    }
    #[cfg(unix)]
    if validate_permissions {
        require_mode(&path, 0o600)?;
    }
    let bytes = std::fs::read(&path).at(&path)?;
    bytes
        .try_into()
        .map_err(|_| ScannerError::Output("invalid dashboard authentication key".into()))
}

#[cfg(unix)]
fn require_mode(path: &Path, expected: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let actual = std::fs::symlink_metadata(path)
        .at(path)?
        .permissions()
        .mode()
        & 0o777;
    if actual != expected {
        return Err(ScannerError::Output(format!(
            "unsafe dashboard authentication permissions on {}: expected {expected:o}, found {actual:o}",
            path.display()
        )));
    }
    Ok(())
}

fn workspace_id(dashboard_root: &Path) -> Result<String> {
    let canonical = std::fs::canonicalize(dashboard_root).at(dashboard_root)?;
    Ok(native_path_id(&canonical))
}

fn native_path_id(path: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hasher.update(b"unix\0");
        hasher.update(path.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        hasher.update(b"windows-utf16le\0");
        for unit in path.as_os_str().encode_wide() {
            hasher.update(&unit.to_le_bytes());
        }
    }
    format!("blake3:{}", hasher.finalize().to_hex())
}

fn protocol_event_hash(event: &ProtocolEvent) -> Result<String> {
    let bytes =
        serde_json::to_vec(event).map_err(|error| ScannerError::Output(error.to_string()))?;
    Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    use super::native_path_id;

    #[test]
    fn native_identity_preserves_non_utf8_path_bytes() {
        let first = std::path::PathBuf::from(OsString::from_vec(vec![0x80]));
        let second = std::path::PathBuf::from(OsString::from_vec(vec![0x81]));

        assert_ne!(native_path_id(&first), native_path_id(&second));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_identity_preserves_non_utf8_path_bytes() {
        use super::workspace_id;

        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join(OsString::from_vec(vec![0x80]));
        let second = directory.path().join(OsString::from_vec(vec![0x81]));
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();

        assert_ne!(
            workspace_id(&first).unwrap(),
            workspace_id(&second).unwrap()
        );
    }
}

fn key_root() -> Result<std::path::PathBuf> {
    directories::ProjectDirs::from("com", "Patronus", "patronus-security-scanner")
        .map(|dirs| dirs.data_local_dir().join("dashboard-auth"))
        .ok_or_else(|| ScannerError::Output("cannot resolve scanner data directory".into()))
}
