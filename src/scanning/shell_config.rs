//! Local Cat configuration, shared by the CLI, dashboard and runtime hosts.
use patronus_ark::detectors::shell::{policies::ShellPolicies, ShellPolicyConfig};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AskBehavior {
    #[default]
    Low,
    Ask,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShellPolicy {
    pub ask_behavior: AskBehavior,
    pub cedar_policies: BTreeMap<String, String>,
    pub policy_dirs: Vec<PathBuf>,
    pub allowlist: BTreeMap<String, String>,
    pub rules: BTreeMap<String, bool>,
}
impl ShellPolicy {
    pub fn compile(&self) -> Result<ShellPolicyConfig, String> {
        if self.cedar_policies.len() > 64
            || self.policy_dirs.len() > 16
            || self
                .cedar_policies
                .iter()
                .any(|(name, source)| name.is_empty() || name.len() > 128 || source.len() > 65536)
            || self.policy_dirs.iter().any(|p| !p.is_absolute())
        {
            return Err(
                "Cedar policies require names, bounded sources and absolute policy directories"
                    .into(),
            );
        }
        if self.allowlist.values().any(|v| v != "ask")
            || self.rules.keys().any(|id| !id.starts_with("cat."))
        {
            return Err("Cat rules require cat.<policy id>; allowlist values must be ask".into());
        }
        let mut config = ShellPolicyConfig::load(&self.policy_dirs, &self.allowlist)?;
        config
            .user_policies
            .extend(self.cedar_policies.values().cloned());
        // Validate source and schema even before the model has been prepared.
        if !config.user_policies.is_empty() {
            ShellPolicies::none().configure(&ShellPolicyConfig {
                user_policies: config.user_policies.clone(),
                ..Default::default()
            })?;
        }
        Ok(config)
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShellSettings {
    pub default: ShellPolicy,
    /// A host override is a complete shell policy; absent hosts inherit default.
    pub hosts: BTreeMap<String, ShellPolicy>,
}
impl ShellSettings {
    pub fn validate(&self, model_dir: Option<&std::path::Path>) -> Result<(), String> {
        if self
            .hosts
            .keys()
            .any(|h| !crate::plugin_policies::HOSTS.contains(&h.as_str()))
        {
            return Err("Unknown shell host".into());
        }
        for policy in std::iter::once(&self.default).chain(self.hosts.values()) {
            let config = policy.compile()?;
            if !policy.allowlist.is_empty() {
                let root = model_dir
                    .ok_or("Prepare the pinned shell model before configuring its allowlist")?;
                let pipeline = patronus_ark::detectors::shell::ShellRiskPipeline::from_config(
                    &patronus_ark::detectors::shell::ShellConfig::new(
                        crate::shell_check::bundle_dir(root),
                    ),
                )?;
                pipeline.configure(&config)?;
            }
        }
        Ok(())
    }
}
