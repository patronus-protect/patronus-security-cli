use crate::{
    ark::ArkAnalyzer,
    config::Config,
    error::{Result, ScannerError},
};
use std::path::PathBuf;

pub fn default_directory() -> Result<PathBuf> {
    let home = directories::BaseDirs::new()
        .ok_or_else(|| ScannerError::Output("Home directory unavailable".into()))?;
    #[cfg(target_os = "macos")]
    let root = home
        .home_dir()
        .join("Library/Application Support/com.patronus.desktop");
    #[cfg(not(target_os = "macos"))]
    let root = home.data_local_dir().join("com.patronus.desktop");
    Ok(root.join("patronus-ark/models"))
}
/// The pre-execution shell command check (Ark cat-shell-risk-commander, ~4.4 MB) always runs
/// locally, also when text scans use the API.
pub fn prepare_shell(config: &mut Config) -> Result<()> {
    if config.ark.model_dir.is_none() {
        config.ark.model_dir = Some(default_directory()?);
    }
    let model_dir = config.ark.model_dir.clone().unwrap();
    if !crate::shell_check::assets_present(&model_dir) {
        eprintln!("Downloading the shell command model…");
        crate::shell_check::download_assets(&model_dir).map_err(ScannerError::Ark)?;
    }
    Ok(())
}
pub fn prepare(config: &mut Config) -> Result<()> {
    if config.ark.model_dir.is_none() {
        config.ark.model_dir = Some(default_directory()?);
    }
    // A plugin surface with Wolf needs Wolf Edge even when the global level is L1.
    if config.plugin_policies.values().any(|profile| profile.wolf) {
        config.ark.max_level = "l3".into();
        if !config.ark.categories.iter().any(|c| c == "injection") {
            config.ark.categories.push("injection".into());
        }
    }
    eprintln!(
        "Checking local Ark models in {}…",
        config.ark.model_dir.as_ref().unwrap().display()
    );
    prepare_shell(config)?;
    if ArkAnalyzer::policy_assets_ready(&config.ark, &config.analysis)? {
        eprintln!("Required models are present. No download needed.");
        return Ok(());
    }
    eprintln!("Required model assets are missing. Downloading missing files…");
    ArkAnalyzer::prepare_policy_assets(&config.ark, &config.analysis)?;
    eprintln!("Required models are ready.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(path: PathBuf, level: &str) -> crate::config::ArkConfig {
        crate::config::ArkConfig {
            categories: vec!["injection".into()],
            max_level: level.into(),
            model_dir: Some(path),
            download_files: false,
            queue_capacity: 256,
        }
    }
    #[test]
    fn l1_needs_no_model_download() {
        let root = tempfile::tempdir().unwrap();
        assert!(ArkAnalyzer::policy_assets_ready(
            &config(root.path().into(), "l1"),
            &Default::default()
        )
        .unwrap());
    }
    #[test]
    fn empty_model_folder_is_not_ready_for_wolf_at_l3() {
        let root = tempfile::tempdir().unwrap();
        assert!(!ArkAnalyzer::policy_assets_ready(
            &config(root.path().into(), "l3"),
            &Default::default()
        )
        .unwrap());
    }
}
