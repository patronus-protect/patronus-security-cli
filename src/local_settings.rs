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
    let bytes = toml::to_string_pretty(&without_default_cascade(config))
        .map_err(|e| invalid(&e.to_string()))?;
    crate::output::atomic_write(&root.join("config.toml"), bytes.as_bytes())?;
    let page = crate::dashboard::render_dashboard_shell(&root);
    crate::output::atomic_write(&root.join("index.html"), page.as_bytes())?;
    println!("Settings saved. Restart agent sessions to activate them; reload index.html.");
    Ok(())
}

pub fn import_config(path: &Path) -> Result<()> {
    let mut config: Config = read(path)?;
    config.migrate_legacy();
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
            for profile in config.plugin_policies.values_mut() {
                profile.migrate_legacy();
            }
            config.validate()?;
            println!("Plugin policies are valid.");
        }
        PolicyCommand::Import { path } => {
            config.plugin_policies = read(&path)?;
            for profile in config.plugin_policies.values_mut() {
                profile.migrate_legacy();
                profile.add_missing_rules();
            }
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

/// The saved settings keep only cascade cuts that differ from the compiled
/// defaults. Loading merges the defaults back field by field, so a release that
/// recalibrates a default cut reaches users who never changed it.
fn without_default_cascade(config: &Config) -> Config {
    let mut saved = config.clone();
    let Ok(defaults) = toml::from_str::<Config>(crate::config::DEFAULTS) else {
        return saved;
    };
    saved.analysis.cascade.retain(|category, cuts| {
        let Some(default) = defaults.analysis.cascade.get(category) else {
            return true;
        };
        let keep = |own: Option<f64>, base: Option<f64>| own.filter(|value| Some(*value) != base);
        cuts.detect_threshold = keep(cuts.detect_threshold, default.detect_threshold);
        cuts.clear_threshold = keep(cuts.clear_threshold, default.clear_threshold);
        cuts.l1_detect_threshold = keep(cuts.l1_detect_threshold, default.l1_detect_threshold);
        cuts.l1_clear_threshold = keep(cuts.l1_clear_threshold, default.l1_clear_threshold);
        cuts.l1_clear_enabled = cuts
            .l1_clear_enabled
            .filter(|value| Some(*value) != default.l1_clear_enabled);
        *cuts != crate::analysis_config::CascadeCuts::default()
    });
    saved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_settings_keep_only_cascade_cuts_that_differ_from_the_defaults() {
        let mut config: Config = toml::from_str(crate::config::DEFAULTS).unwrap();
        config
            .analysis
            .cascade
            .get_mut("jailbreak")
            .unwrap()
            .l1_detect_threshold = Some(7.0);
        let saved = without_default_cascade(&config);
        assert_eq!(
            saved.analysis.cascade.len(),
            1,
            "{:?}",
            saved.analysis.cascade
        );
        let jailbreak = &saved.analysis.cascade["jailbreak"];
        assert_eq!(jailbreak.l1_detect_threshold, Some(7.0));
        assert_eq!(
            jailbreak.clear_threshold, None,
            "the default clear cut is not frozen"
        );
    }
}
