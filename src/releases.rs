//! Public release artifacts, with bounded downloads and checksummed extraction.
use crate::error::{Result, ScannerError};
use serde_json::Value;
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
pub const REPOSITORY: &str = "patronus-protect/patronus-security-cli";
fn fail(message: &str) -> ScannerError {
    ScannerError::Integration(message.into())
}
fn get(url: &str, limit: u64) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new()
        .redirects(5)
        .timeout(Duration::from_secs(180))
        .build();
    let mut request = agent
        .get(url)
        .set("Accept", "application/vnd.github+json")
        .set("User-Agent", "patronus-security-scanner");
    let token = std::env::var("GH_TOKEN")
        .ok()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok());
    if let Some(token) = token.as_deref() {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let response = request.call().map_err(|_| {
        fail("Release not available. Publish matching artifacts and .blake3 checksums, set GH_TOKEN for a private repository, or provide a local release source.")
    })?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail("Release download failed"))?;
    if bytes.len() as u64 > limit {
        return Err(fail("Release artifact exceeds size limit"));
    }
    Ok(bytes)
}
fn latest() -> Result<Value> {
    serde_json::from_slice(&get(
        &format!("https://api.github.com/repos/{REPOSITORY}/releases/latest"),
        1_048_576,
    )?)
    .map_err(|_| fail("Invalid release metadata"))
}
fn asset(release: &Value, name: &str, limit: u64) -> Result<Vec<u8>> {
    let entry = release["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|v| v["name"] == name))
        .ok_or_else(|| fail("Matching release artifact unavailable"))?;
    let url = entry["browser_download_url"]
        .as_str()
        .ok_or_else(|| fail("Invalid release artifact"))?;
    if !url.starts_with(&format!(
        "https://github.com/{REPOSITORY}/releases/download/"
    )) {
        return Err(fail("Untrusted release artifact origin"));
    }
    get(url, limit)
}
fn verified_asset(release: &Value, name: &str, limit: u64) -> Result<Vec<u8>> {
    let checksum = asset(release, &format!("{name}.blake3"), 4096)?;
    let expected = std::str::from_utf8(&checksum)
        .ok()
        .and_then(|s| s.split_whitespace().next())
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| fail("Invalid artifact checksum"))?;
    let bytes = asset(release, name, limit)?;
    verify(&bytes, expected)?;
    Ok(bytes)
}
fn verify(bytes: &[u8], expected: &str) -> Result<()> {
    if blake3::hash(bytes).to_hex().as_str() != expected.to_ascii_lowercase() {
        return Err(fail(
            "Release integrity check failed; installation unchanged",
        ));
    }
    Ok(())
}
fn version(release: &Value) -> Result<String> {
    let version = release["tag_name"]
        .as_str()
        .unwrap_or("")
        .trim_start_matches('v');
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    {
        return Err(fail("Invalid release version"));
    }
    Ok(version.into())
}
fn target() -> Result<&'static str> {
    match (std::env::consts::OS,std::env::consts::ARCH){
        ("macos","aarch64")=>Ok("aarch64-apple-darwin"),("macos","x86_64")=>Ok("x86_64-apple-darwin"),
        ("linux","x86_64")=>Ok("x86_64-unknown-linux-gnu"),
        _=>Err(fail("Automatic release installation is supported on macOS and Linux; use your platform installer"))
    }
}
fn extract(bytes: Vec<u8>, root: &Path) -> Result<()> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|_| fail("Invalid release archive"))?;
    if zip.len() > 4096 {
        return Err(fail("Too many release files"));
    }
    let mut total = 0;
    for index in 0..zip.len() {
        let mut file = zip
            .by_index(index)
            .map_err(|_| fail("Invalid archive entry"))?;
        let path = file
            .enclosed_name()
            .ok_or_else(|| fail("Unsafe archive path"))?;
        if file.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
            return Err(fail("Release symlinks are not accepted"));
        }
        total += file.size();
        if total > 500 * 1024 * 1024 {
            return Err(fail("Expanded release too large"));
        }
        let target = root.join(path);
        if file.is_dir() {
            std::fs::create_dir_all(target).map_err(|_| fail("Cannot extract release"))?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|_| fail("Cannot extract release"))?;
        }
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target)
            .map_err(|_| fail("Duplicate or unsafe release entry"))?;
        std::io::copy(&mut file, &mut output).map_err(|_| fail("Release extraction failed"))?;
    }
    Ok(())
}
pub fn plugin_source(host: &str) -> Result<PathBuf> {
    if !["codex", "claude", "deepseek"].contains(&host) {
        return Err(fail("Unknown plugin host"));
    }
    let release = latest()?;
    let version = version(&release)?;
    let root = crate::config::user_root()?
        .join("releases")
        .join(format!("{version}-{host}-{:016x}", rand::random::<u64>()));
    crate::dashboard::ensure_directory(&root)?;
    if host == "deepseek" {
        let name = format!("patronus-deepseek-security-{version}.tgz");
        let bytes = verified_asset(&release, &name, 30 * 1024 * 1024)?;
        let path = root.join(name);
        crate::output::atomic_write(&path, &bytes)?;
        return Ok(path);
    }
    let name = format!("patronus-security-{host}-{version}.zip");
    extract(verified_asset(&release, &name, 30 * 1024 * 1024)?, &root)?;
    Ok(root)
}
pub fn standalone_install() -> bool {
    let Ok(current) = std::env::current_exe() else {
        return false;
    };
    let Some(home) = directories::BaseDirs::new() else {
        return false;
    };
    let local = home.home_dir().join(".local/bin/patronus-security-scanner");
    current == local
        && std::fs::symlink_metadata(&current)
            .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
}
pub fn update_cli() -> Result<()> {
    if !standalone_install() {
        return Err(fail("Use the original installer for this executable"));
    }
    let release = latest()?;
    let version = version(&release)?;
    let name = format!("patronus-security-scanner-{version}-{}.zip", target()?);
    let root = crate::config::user_root()?
        .join("releases")
        .join(format!("{version}-cli-{:016x}", rand::random::<u64>()));
    crate::dashboard::ensure_directory(&root)?;
    extract(verified_asset(&release, &name, 250 * 1024 * 1024)?, &root)?;
    replace_binary(
        &root.join("patronus-security-scanner"),
        &std::env::current_exe().map_err(|_| fail("Cannot resolve CLI"))?,
    )?;
    println!("CLI updated to {version}. Restart the dashboard and active agent sessions.");
    Ok(())
}
fn replace_binary(source: &Path, target: &Path) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| fail("Invalid installation path"))?;
    let next = parent.join(format!(".patronus-update-{:016x}", rand::random::<u64>()));
    let result = (|| {
        let mut source =
            std::fs::File::open(source).map_err(|_| fail("Missing release executable"))?;
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&next)
            .map_err(|_| fail("Cannot stage update"))?;
        std::io::copy(&mut source, &mut out).map_err(|_| fail("Cannot write update"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            out.set_permissions(std::fs::Permissions::from_mode(0o755))
                .map_err(|_| fail("Cannot set executable permissions"))?;
        }
        out.sync_all().map_err(|_| fail("Cannot persist update"))?;
        drop(out);
        let check = std::process::Command::new(&next)
            .arg("version")
            .output()
            .map_err(|_| fail("Downloaded executable cannot run"))?;
        if !check.status.success() {
            return Err(fail(
                "Downloaded executable failed validation; installation unchanged",
            ));
        }
        crate::atomic_file::replace(&next, target)
            .map_err(|_| fail("Cannot replace CLI; installation unchanged"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(next);
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_mismatch_preserves_failure() {
        assert!(verify(b"content", &"0".repeat(64)).is_err());
        assert!(verify(b"content", blake3::hash(b"content").to_hex().as_str()).is_ok());
    }
    #[test]
    fn invalid_version_is_not_a_path() {
        assert!(version(&serde_json::json!({"tag_name":"../../bad"})).is_err());
    }
    #[test]
    fn archive_traversal_is_rejected() {
        use std::io::Write;
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        z.start_file("../escape", zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(b"bad").unwrap();
        let data = z.finish().unwrap().into_inner();
        let dir = tempfile::tempdir().unwrap();
        assert!(extract(data, dir.path()).is_err());
    }
}
