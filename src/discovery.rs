use std::path::{Path, PathBuf};

use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use serde::Serialize;

use crate::config::Config;
use crate::error::{Result, ScannerError};
use crate::target::{display_path, ScanTarget};

#[derive(Debug, Clone, Serialize)]
pub struct FileRecord {
    pub schema: &'static str,
    pub path: String,
    pub size_bytes: u64,
    pub eligible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    #[serde(skip)]
    pub absolute_path: PathBuf,
}

#[derive(Debug)]
pub struct Discovery {
    pub files: Vec<FileRecord>,
    pub eligible_bytes: u64,
    pub eligible_files: usize,
    pub skipped_files: usize,
}

pub fn discover(
    target: &ScanTarget,
    config: &Config,
    includes: &[String],
    active_output: &Path,
) -> Result<Discovery> {
    let native_plugin_roots = installed_native_plugin_roots();
    if let Some(file) = &target.explicit_file {
        let metadata = std::fs::symlink_metadata(file).map_err(|source| ScannerError::Io {
            path: file.clone(),
            source,
        })?;
        let reason = safety_reason(
            file,
            &metadata,
            &target.root,
            active_output,
            config,
            &native_plugin_roots,
        );
        return Ok(summarize(vec![record(
            file,
            &target.root,
            metadata.len(),
            reason,
        )]));
    }

    let mut overrides = OverrideBuilder::new(&target.root);
    for pattern in &config.ignore.patterns {
        overrides
            .add(&format!("!{pattern}"))
            .map_err(|error| ScannerError::Config {
                source_name: "ignore.patterns".into(),
                message: error.to_string(),
            })?;
    }
    for pattern in includes {
        overrides
            .add(pattern)
            .map_err(|error| ScannerError::Config {
                source_name: "--include".into(),
                message: error.to_string(),
            })?;
    }
    let overrides = overrides.build().map_err(|error| ScannerError::Config {
        source_name: "ignore patterns".into(),
        message: error.to_string(),
    })?;

    let mut builder = WalkBuilder::new(&target.root);
    builder
        .hidden(!config.scan.include_hidden)
        .follow_links(config.scan.follow_symlinks)
        .git_ignore(config.scan.respect_gitignore)
        .ignore(config.scan.respect_ignore_files)
        .parents(false)
        .overrides(overrides);

    let mut files = Vec::new();
    for entry in builder.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                files.push(FileRecord {
                    schema: "patronus.security-scanner.file.v1",
                    path: "<discovery-error>".into(),
                    size_bytes: 0,
                    eligible: false,
                    skip_reason: Some(format!("discovery_error: {error}")),
                    absolute_path: target.root.clone(),
                });
                continue;
            }
        };
        if entry.path() == target.root {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) => {
                files.push(record(
                    entry.path(),
                    &target.root,
                    0,
                    Some(format!("metadata_error: {error}")),
                ));
                continue;
            }
        };
        if metadata.is_dir() {
            continue;
        }
        let reason = safety_reason(
            entry.path(),
            &metadata,
            &target.root,
            active_output,
            config,
            &native_plugin_roots,
        );
        files.push(record(entry.path(), &target.root, metadata.len(), reason));
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(summarize(files))
}

fn safety_reason(
    path: &Path,
    metadata: &std::fs::Metadata,
    root: &Path,
    active_output: &Path,
    config: &Config,
    native_plugin_roots: &[PathBuf],
) -> Option<String> {
    if metadata.file_type().is_symlink() {
        return Some("symlink".into());
    }
    if !metadata.is_file() {
        return Some("non_regular_file".into());
    }
    if metadata.len() > config.scan.max_file_bytes {
        return Some("oversized".into());
    }
    let canonical = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => return Some("canonicalization_failed".into()),
    };
    if !canonical.starts_with(root) {
        return Some("outside_scan_root".into());
    }
    if canonical.starts_with(active_output) || display_path(root, &canonical).starts_with(".git/") {
        return Some("hard_exclusion".into());
    }
    if is_native_plugin_artifact(&canonical, native_plugin_roots) {
        return Some("system_hard_exclusion: patronus_native_plugin_artifact".into());
    }
    None
}

fn installed_native_plugin_roots() -> Vec<PathBuf> {
    let Some(base_dirs) = directories::BaseDirs::new() else {
        return Vec::new();
    };
    let home = base_dirs.home_dir();
    let codex_home = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".codex"));
    let dsh_home = std::env::var_os("DSH_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".dsh"));

    let mut roots = Vec::new();
    add_existing_root(
        &mut roots,
        codex_home.join("plugins/cache/patronus-local/patronus-security"),
    );
    add_existing_root(
        &mut roots,
        home.join(".claude/plugins/cache/patronus-local/patronus-security"),
    );
    if let Ok(profiles) = std::fs::read_dir(dsh_home.join("profiles")) {
        for profile in profiles.flatten() {
            add_existing_root(
                &mut roots,
                profile
                    .path()
                    .join("node_modules/@patronus/deepseek-security"),
            );
        }
    }
    roots
}

fn add_existing_root(roots: &mut Vec<PathBuf>, path: PathBuf) {
    if path.is_dir() {
        let Ok(canonical) = std::fs::canonicalize(path) else {
            return;
        };
        roots.push(canonical);
    }
}

fn is_native_plugin_artifact(path: &Path, installed_roots: &[PathBuf]) -> bool {
    installed_roots.iter().any(|root| path.starts_with(root))
}

fn record(path: &Path, root: &Path, size_bytes: u64, reason: Option<String>) -> FileRecord {
    FileRecord {
        schema: "patronus.security-scanner.file.v1",
        path: display_path(root, path),
        size_bytes,
        eligible: reason.is_none(),
        skip_reason: reason,
        absolute_path: path.to_path_buf(),
    }
}

fn summarize(files: Vec<FileRecord>) -> Discovery {
    Discovery {
        eligible_bytes: files
            .iter()
            .filter(|file| file.eligible)
            .map(|file| file.size_bytes)
            .sum(),
        eligible_files: files.iter().filter(|file| file.eligible).count(),
        skipped_files: files.iter().filter(|file| !file.eligible).count(),
        files,
    }
}

#[cfg(test)]
mod tests {
    use super::is_native_plugin_artifact;
    use std::path::PathBuf;

    #[test]
    fn installed_native_plugin_root_does_not_hide_similarly_named_paths() {
        let installed = PathBuf::from("/host/plugins/cache/patronus-local/patronus-security");
        assert!(is_native_plugin_artifact(
            &installed.join("0.1.0/scripts/patronus.mjs"),
            std::slice::from_ref(&installed),
        ));
        assert!(!is_native_plugin_artifact(
            PathBuf::from("/repo/patronus/plugin/file.txt").as_path(),
            std::slice::from_ref(&installed),
        ));
        assert!(!is_native_plugin_artifact(
            PathBuf::from("/host/plugins/cache/patronus-local/other/file.txt").as_path(),
            &[installed],
        ));
    }
}
