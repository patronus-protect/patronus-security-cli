mod claude;
mod codex;
mod deepseek;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::Serialize;

use crate::cli::{
    IntegrationAction, IntegrationArgs, IntegrationHost, IntegrationScope, OutputFormat,
};
use crate::error::{Result, ScannerError};

pub fn execute(mut args: IntegrationArgs) -> Result<()> {
    if args.source.is_none()
        && (args.action == IntegrationAction::Install
            || (args.host == IntegrationHost::Deepseek && args.action == IntegrationAction::Update))
    {
        let marker = if args.host == IntegrationHost::Codex {
            ".agents/plugins/marketplace.json"
        } else {
            ".claude-plugin/marketplace.json"
        };
        let local =
            std::env::current_dir().is_ok_and(|p| p.ancestors().any(|a| a.join(marker).is_file()));
        if args.host == IntegrationHost::Deepseek || !local {
            args.source = Some(crate::releases::plugin_source(args.host.as_str())?);
        }
    }

    if args.source.is_some()
        && !matches!(
            args.action,
            IntegrationAction::Install | IntegrationAction::Update
        )
    {
        return Err(ScannerError::Integration(
            "--source is supported only during install/update".into(),
        ));
    }
    if args.profile.is_some() && args.host != IntegrationHost::Deepseek {
        return Err(ScannerError::Integration(
            "--profile is supported only for DeepSeek".into(),
        ));
    }
    if args.keep_data
        && (args.host != IntegrationHost::Claude || args.action != IntegrationAction::Uninstall)
    {
        return Err(ScannerError::Integration(
            "--keep-data is supported only for Claude uninstall".into(),
        ));
    }
    if args.action == IntegrationAction::Install {
        crate::dashboard::provision_dashboard_key()?;
    }
    match args.host {
        IntegrationHost::Codex => codex::execute(args),
        IntegrationHost::Claude => claude::execute(args),
        IntegrationHost::Deepseek => deepseek::execute(args),
    }
}

#[derive(Debug, Serialize)]
pub(super) struct IntegrationStatus {
    schema: &'static str,
    host: &'static str,
    scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    installed: Option<bool>,
    enabled: Option<bool>,
    reachable: bool,
    ready: bool,
    state: &'static str,
    message: &'static str,
    commands: StatusCommands,
}

pub(super) struct StatusObservation {
    pub installed: Option<bool>,
    pub enabled: Option<bool>,
    pub reachable: bool,
    pub ready: bool,
    pub state: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Serialize)]
struct StatusCommands {
    status: String,
    enable: String,
    disable: String,
    uninstall: String,
}

impl IntegrationStatus {
    pub(super) fn new(
        host: IntegrationHost,
        scope: IntegrationScope,
        profile: Option<&str>,
        observation: StatusObservation,
    ) -> Self {
        let host_name = host.as_str();
        let options = match host {
            IntegrationHost::Codex => String::new(),
            IntegrationHost::Claude => format!(" --scope {}", scope.as_str()),
            IntegrationHost::Deepseek => {
                format!(" --profile {}", profile.unwrap_or("headless"))
            }
        };
        let command = |action: &str| {
            format!("patronus-security-scanner integration {host_name} {action}{options}")
        };
        Self {
            schema: "patronus.integration.status.v1",
            host: host_name,
            scope: scope.as_str(),
            profile: profile.map(str::to_owned),
            installed: observation.installed,
            enabled: observation.enabled,
            reachable: observation.reachable,
            ready: observation.ready,
            state: observation.state,
            message: observation.message,
            commands: StatusCommands {
                status: format!("{} --format json", command("status")),
                enable: command("enable"),
                disable: command("disable"),
                uninstall: command("uninstall"),
            },
        }
    }

    pub(super) fn print(&self, format: OutputFormat) -> Result<()> {
        if format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::to_string(self).map_err(|error| {
                    ScannerError::Integration(format!(
                        "could not encode integration status: {error}"
                    ))
                })?
            );
            return Ok(());
        }
        let flag = |value: Option<bool>| match value {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unknown",
        };
        println!("Patronus {} integration: {}", self.host, self.state);
        println!("Installed: {}", flag(self.installed));
        println!("Enabled: {}", flag(self.enabled));
        println!(
            "Host reachable: {}",
            if self.reachable { "yes" } else { "no" }
        );
        println!("Ready: {}", if self.ready { "yes" } else { "no" });
        println!("{}", self.message);
        println!("Status: {}", self.commands.status);
        println!("Enable: {}", self.commands.enable);
        println!("Disable: {}", self.commands.disable);
        println!("Uninstall: {}", self.commands.uninstall);
        Ok(())
    }
}

impl IntegrationHost {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Deepseek => "deepseek",
        }
    }
}

fn executable(env_name: &str, fallback: &str) -> PathBuf {
    std::env::var_os(env_name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(fallback))
}

fn run(program: &Path, args: &[&str]) -> Result<Output> {
    Command::new(program).args(args).output().map_err(|error| {
        ScannerError::Integration(format!("could not run {}: {error}", program.display()))
    })
}

fn require_success(program: &Path, args: &[&str]) -> Result<()> {
    let output = run(program, args)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(ScannerError::Integration(format!(
        "{} {} failed{}",
        program.display(),
        args.join(" "),
        if stderr.is_empty() {
            String::new()
        } else {
            format!(": {stderr}")
        }
    )))
}

fn discover_root(start: &Path, marker: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|candidate| candidate.join(marker).is_file())
        .map(Path::to_path_buf)
}

fn atomic_write(path: &Path, original: &[u8], contents: &[u8]) -> Result<()> {
    use fs2::FileExt;
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        ScannerError::Integration(format!("{} has no parent directory", path.display()))
    })?;
    std::fs::create_dir_all(parent).map_err(|source| ScannerError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let lock_path = parent.join(format!(
        ".{}.patronus-lifecycle.lock",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| ScannerError::Io {
            path: lock_path.clone(),
            source,
        })?;
    lock.lock_exclusive().map_err(|source| ScannerError::Io {
        path: lock_path,
        source,
    })?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|source| ScannerError::Io {
                path: temporary.clone(),
                source,
            })?;
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|source| ScannerError::Io {
                path: temporary.clone(),
                source,
            })?;
        match std::fs::read(path) {
            Ok(current) if current != original => {
                return Err(ScannerError::Integration(format!(
                    "{} changed while it was being updated",
                    path.display()
                )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !original.is_empty() => {
                return Err(ScannerError::Integration(format!(
                    "{} changed while it was being updated",
                    path.display()
                )))
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(ScannerError::Io {
                    path: path.to_path_buf(),
                    source: error,
                })
            }
            _ => {}
        }
        crate::atomic_file::replace(&temporary, path).map_err(|source| ScannerError::Io {
            path: path.to_path_buf(),
            source,
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::atomic_write;

    #[test]
    fn concurrent_lifecycle_updates_cannot_both_replace_the_same_version() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.toml");
        std::fs::write(&path, b"original").unwrap();
        let first_path = path.clone();
        let second_path = path.clone();
        let first = std::thread::spawn(move || atomic_write(&first_path, b"original", b"first"));
        let second = std::thread::spawn(move || atomic_write(&second_path, b"original", b"second"));
        let outcomes = [
            first.join().unwrap().is_ok(),
            second.join().unwrap().is_ok(),
        ];
        assert_eq!(outcomes.into_iter().filter(|success| *success).count(), 1);
        let contents = std::fs::read(path).unwrap();
        assert!(contents == b"first" || contents == b"second");
    }
}
