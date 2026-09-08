use crate::{
    cli::PolicyCommand,
    config::Config,
    error::{Result, ScannerError},
};
use std::path::Path;

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| invalid(&e.to_string()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err(invalid("Expected a regular JSON file of at most 1 MiB"));
    }
    serde_json::from_slice(&std::fs::read(path).map_err(|e| invalid(&e.to_string()))?)
        .map_err(|e| invalid(&e.to_string()))
}

pub fn save(config: &Config) -> Result<()> {
    config.validate()?;
    let root = crate::config::user_root()?;
    crate::dashboard::ensure_directory(&root)?;
    let bytes = toml::to_string_pretty(config).map_err(|e| invalid(&e.to_string()))?;
    crate::output::atomic_write(&root.join("config.toml"), bytes.as_bytes())?;
    crate::dashboard::rebuild_index(&root, &root.join("output"))?;
    println!("Settings saved. Restart agent sessions to activate them; reload index.html.");
    Ok(())
}

pub fn import_config(path: &Path) -> Result<()> {
    let config: Config = read(path)?;
    save(&config)
}

pub fn policy(command: PolicyCommand) -> Result<i32> {
    let mut config = Config::load(None, None)?;
    match command {
        PolicyCommand::Show => println!(
            "{}",
            serde_json::to_string_pretty(&crate::plugin_policies::resolved(&config))
                .map_err(|e| invalid(&e.to_string()))?
        ),
        PolicyCommand::Rules => println!(
            "{}",
            serde_json::to_string_pretty(&crate::policy::rules())
                .map_err(|e| invalid(&e.to_string()))?
        ),
        PolicyCommand::Validate { path } => {
            config.plugin_policies = read(&path)?;
            config.validate()?;
            println!("Plugin policies are valid.");
        }
        PolicyCommand::Import { path } => {
            config.plugin_policies = read(&path)?;
            save(&config)?;
        }
        PolicyCommand::Check { path } => {
            let check: crate::policy::Check = read(&path)?;
            let outcome = crate::policy::check(&config, check)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&outcome).map_err(|e| invalid(&e.to_string()))?
            );
            return Ok(if !outcome.coverage.complete {
                2
            } else if outcome.findings.is_empty() {
                0
            } else {
                1
            });
        }
    }
    Ok(0)
}

fn invalid(message: &str) -> ScannerError {
    ScannerError::Config {
        source_name: "local settings".into(),
        message: message.into(),
    }
}
