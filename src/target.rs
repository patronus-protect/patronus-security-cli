use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, ScannerError};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Repo,
    Directory,
    File,
}

#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub kind: TargetKind,
    pub root: PathBuf,
    pub explicit_file: Option<PathBuf>,
}

impl ScanTarget {
    pub fn resolve(kind: TargetKind, input: &Path) -> Result<Self> {
        if kind == TargetKind::File {
            let original = if input.is_absolute() {
                input.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|source| ScannerError::Io {
                        path: PathBuf::from("."),
                        source,
                    })?
                    .join(input)
            };
            let metadata =
                std::fs::symlink_metadata(&original).map_err(|source| ScannerError::Io {
                    path: original.clone(),
                    source,
                })?;
            if metadata.file_type().is_symlink() {
                let parent = original.parent().unwrap_or(Path::new("."));
                let root = std::fs::canonicalize(parent).map_err(|source| ScannerError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
                return Ok(Self {
                    kind,
                    root,
                    explicit_file: Some(original),
                });
            }
        }
        let canonical = std::fs::canonicalize(input).map_err(|source| ScannerError::Io {
            path: input.to_path_buf(),
            source,
        })?;
        match kind {
            TargetKind::Repo => {
                let start = if canonical.is_file() {
                    canonical.parent().unwrap_or(&canonical)
                } else {
                    &canonical
                };
                let root = find_repo_root(start).ok_or_else(|| ScannerError::Target {
                    path: input.to_path_buf(),
                    message: "no ancestor contains a .git directory or worktree file".into(),
                })?;
                Ok(Self {
                    kind,
                    root,
                    explicit_file: None,
                })
            }
            TargetKind::Directory if canonical.is_dir() => Ok(Self {
                kind,
                root: canonical,
                explicit_file: None,
            }),
            TargetKind::File if canonical.is_file() => {
                let root = canonical.parent().unwrap_or(Path::new(".")).to_path_buf();
                Ok(Self {
                    kind,
                    root,
                    explicit_file: Some(canonical),
                })
            }
            _ => Err(ScannerError::Target {
                path: input.to_path_buf(),
                message: format!(
                    "expected a {}",
                    if kind == TargetKind::File {
                        "regular file"
                    } else {
                        "directory"
                    }
                ),
            }),
        }
    }
}

pub fn find_repo_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|path| {
            let git = path.join(".git");
            git.is_dir() || git.is_file()
        })
        .map(Path::to_path_buf)
}

pub fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
