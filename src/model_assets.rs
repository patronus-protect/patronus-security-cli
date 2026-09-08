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
pub fn prepare(config: &mut Config) -> Result<()> {
    if config.ark.model_dir.is_none() {
        config.ark.model_dir = Some(default_directory()?);
    }
    for profile in config.plugin_policies.values() {
        for (category, assessment) in [
            ("prompt_injection", &profile.injection),
            ("threat", &profile.threat),
        ] {
            if !assessment.enabled {
                continue;
            }
            if !config.ark.categories.iter().any(|c| c == category) {
                config.ark.categories.push(category.into());
            }
            let level = config
                .analysis
                .level(category, &config.ark)
                .max(&assessment.max_level)
                .to_string();
            config
                .analysis
                .category_levels
                .insert(category.into(), level);
        }
    }
    eprintln!(
        "Checking local Ark models in {}…",
        config.ark.model_dir.as_ref().unwrap().display()
    );
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
            categories: vec!["prompt_injection".into()],
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
    fn empty_model_folder_is_not_ready_for_l2() {
        let root = tempfile::tempdir().unwrap();
        assert!(!ArkAnalyzer::policy_assets_ready(
            &config(root.path().into(), "l2"),
            &Default::default()
        )
        .unwrap());
    }
}
