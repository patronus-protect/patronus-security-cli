//! Policies for the three text surfaces of each supported plugin.
use crate::{config::Config, policy::rules};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HOSTS: [&str; 4] = ["claude", "codex", "deepseek", "cursor"];
pub const SURFACES: [&str; 3] = ["user_input", "tool_result", "mcp_result"];

/// A model assessment of profiles saved before Ark Core 0.1.18. Read once by
/// [`Profile::migrate_legacy`] and never written.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub enabled: bool,
    pub max_level: String,
    #[serde(default, skip_serializing)]
    pub min_confidence: Option<f64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii_mode: Option<patronus_ark_core::native::ScoreMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dlp_mode: Option<patronus_ark_core::native::ScoreMode>,
    pub l1_rules: BTreeMap<String, bool>,
    /// Wolf Defender Edge (L3) for `injection` on this surface, where the
    /// cascade escalates.
    #[serde(default)]
    pub wolf: bool,
    #[serde(default, skip_serializing)]
    pub injection: Option<Assessment>,
    #[serde(default, skip_serializing)]
    pub threat: Option<Assessment>,
}

pub fn valid_scope(scope: &str) -> bool {
    scope
        .split_once('.')
        .is_some_and(|(host, surface)| HOSTS.contains(&host) && SURFACES.contains(&surface))
}
impl Profile {
    pub fn validate(&self) -> std::result::Result<(), String> {
        let catalog = rules();
        if self.l1_rules.len() != catalog.len()
            || catalog.iter().any(|r| !self.l1_rules.contains_key(&r.id))
        {
            return Err("Plugin policy must specify on/off for every known L1 rule".into());
        }
        Ok(())
    }
    /// Profiles saved before an Ark update lack rules the new catalog added. They get the rule's
    /// default instead of failing validation; unknown rule IDs still fail.
    pub fn add_missing_rules(&mut self) {
        for rule in rules() {
            self.l1_rules.entry(rule.id).or_insert(rule.default_enabled);
        }
    }

    /// Profiles saved before Ark Core 0.1.18 assessed injection and threat
    /// with L2/L3 models. Injection's model stage becomes Wolf Edge; the threat
    /// model no longer exists (its classes run as L1 categories).
    pub fn migrate_legacy(&mut self) {
        if self
            .injection
            .take()
            .is_some_and(|assessment| assessment.enabled)
        {
            self.wolf = true;
        }
        self.threat = None;
    }

    /// Seed previously unconfigured scopes from the user's current settings.
    pub fn current(config: &Config, surface: &str) -> Self {
        let category_enabled = |category: &str| config.ark.categories.iter().any(|c| c == category);
        Self {
            pii_mode: None,
            dlp_mode: None,
            l1_rules: rules()
                .into_iter()
                .map(|r| {
                    let enabled = category_enabled(&r.category)
                        && (surface != "user_input"
                            || r.category != "pii"
                            || config.analysis.user_prompt_pii)
                        && *config
                            .analysis
                            .l1_rules
                            .get(&r.id)
                            .unwrap_or(&r.default_enabled);
                    (r.id, enabled)
                })
                .collect(),
            wolf: config.ark.max_level == "l3" && category_enabled("injection"),
            injection: None,
            threat: None,
        }
    }
    /// The configuration one plugin surface scans with: the global categories,
    /// L1 models and cuts, this profile's rules and modes, and Wolf when on.
    pub fn apply(&self, base: &Config) -> Config {
        let mut config = base.clone();
        config.plugin_policies.clear();
        config.ark.max_level =
            if self.wolf && config.ark.categories.iter().any(|c| c == "injection") {
                "l3"
            } else {
                "l1"
            }
            .into();
        config.analysis = crate::analysis_config::AnalysisConfig {
            pii_mode: self.pii_mode.unwrap_or(base.analysis.pii_mode),
            dlp_mode: self.dlp_mode.unwrap_or(base.analysis.dlp_mode),
            l1_rules: self.l1_rules.clone(),
            l1_models: base.analysis.l1_models.clone(),
            cascade: base.analysis.cascade.clone(),
            l1_detectors: base.analysis.l1_detectors.clone(),
            // Profiles gate PII on user input through their rules.
            user_prompt_pii: true,
            ..Default::default()
        };
        config
    }
}

pub fn resolved(config: &Config) -> BTreeMap<String, Profile> {
    HOSTS
        .into_iter()
        .flat_map(|host| {
            SURFACES.into_iter().map(move |surface| {
                let scope = format!("{host}.{surface}");
                let profile = config
                    .plugin_policies
                    .get(&scope)
                    .cloned()
                    .unwrap_or_else(|| Profile::current(config, surface));
                (scope, profile)
            })
        })
        .collect()
}
