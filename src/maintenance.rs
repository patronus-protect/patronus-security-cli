use crate::{
    cli::{
        IntegrationAction, IntegrationArgs, IntegrationHost, IntegrationScope, MaintenanceCommand,
    },
    error::{Result, ScannerError},
};

pub fn cargo_install() -> bool {
    fn detect() -> Result<bool> {
        let root = std::env::var_os("CARGO_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| directories::BaseDirs::new().map(|dirs| dirs.home_dir().join(".cargo")))
            .ok_or_else(|| invalid("Cargo home unavailable"))?;
        let installed = root.join("bin").join(format!(
            "patronus-security-scanner{}",
            std::env::consts::EXE_SUFFIX
        ));
        let current = std::env::current_exe().map_err(|e| invalid(&e.to_string()))?;
        Ok(
            std::fs::canonicalize(&installed).ok() == std::fs::canonicalize(current).ok()
                && installed.is_file(),
        )
    }
    detect().unwrap_or(false)
}

pub fn execute(command: MaintenanceCommand) -> Result<()> {
    let cargo = cargo_install();
    if !cargo && !crate::releases::standalone_install() {
        return Err(invalid("This executable is not the Cargo-installed CLI. Update or remove it through its original installer. No files were removed."));
    }
    match command {
        MaintenanceCommand::Update if !cargo => crate::releases::update_cli(),
        MaintenanceCommand::Update => run_cargo(&[
            "install",
            "--git",
            "https://github.com/patronus-protect/patronus-security-cli",
            "--locked",
            "--force",
            "patronus-security-scanner",
        ]),
        MaintenanceCommand::Uninstall { all, yes } => {
            if !yes {
                return Err(invalid("Uninstall requires --yes. Local reports, settings and credentials are preserved."));
            }
            if all {
                let mut failed = vec![];
                for host in [
                    IntegrationHost::Codex,
                    IntegrationHost::Claude,
                    IntegrationHost::Deepseek,
                ] {
                    if let Err(error) = crate::integrations::execute(IntegrationArgs {
                        host,
                        action: IntegrationAction::Uninstall,
                        source: None,
                        scope: IntegrationScope::User,
                        profile: None,
                        keep_data: false,
                    }) {
                        failed.push(format!("{}: {error}", host.as_str()));
                    }
                }
                if !failed.is_empty() {
                    return Err(invalid(&format!(
                        "CLI retained because plugin removal failed: {}",
                        failed.join("; ")
                    )));
                }
            }
            if cargo {
                run_cargo(&["uninstall", "patronus-security-scanner"])
            } else {
                let current =
                    std::env::current_exe().map_err(|_| invalid("Cannot resolve CLI path"))?;
                std::fs::remove_file(current).map_err(|_| invalid("Cannot remove CLI"))
            }
        }
    }
}

fn run_cargo(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("cargo")
        .args(args)
        .status()
        .map_err(|e| invalid(&e.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(invalid(
            "Cargo operation failed; inspect the CLI terminal output",
        ))
    }
}
fn invalid(message: &str) -> ScannerError {
    ScannerError::Integration(message.into())
}
