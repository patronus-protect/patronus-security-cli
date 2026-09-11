//! Policies for the three text surfaces of each supported plugin.
use crate::{config::Config, policy::rules};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HOSTS: [&str; 3] = ["claude", "codex", "deepseek"];
pub const SURFACES: [&str; 3] = ["user_input", "tool_result", "mcp_result"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub enabled: bool,
    pub max_level: String,
    /// Accepted only to migrate older configurations. Ark owns classifier
    /// thresholds, so this value is never serialized or applied.
    #[serde(default, skip_serializing)]
    pub min_confidence: Option<f64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub l1_rules: BTreeMap<String, bool>,
    pub injection: Assessment,
    pub threat: Assessment,
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
        for assessment in [&self.injection, &self.threat] {
            if !["l2", "l3"].contains(&assessment.max_level.as_str())
                || assessment
                    .min_confidence
                    .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
            {
                return Err("Assessment requires L2 or L3".into());
            }
        }
        Ok(())
    }
    /// Seed previously unconfigured scopes from the user's current settings.
    pub fn current(config: &Config, surface: &str) -> Self {
        let category_enabled = |category: &str| {
            config
                .ark
                .categories
                .iter()
                .any(|c| c == category || c == "injection" && category == "prompt_injection")
        };
        let assessment = |category: &str| {
            let level = config.analysis.level(category, &config.ark);
            Assessment {
                enabled: category_enabled(category) && level != "l1",
                max_level: if level == "l1" { "l2" } else { level }.into(),
                min_confidence: None,
            }
        };
        Self {
            l1_rules: rules()
                .into_iter()
                .map(|r| {
                    let enabled = category_enabled(&r.category)
                        && config.analysis.l1.get(&r.category) != Some(&false)
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
            injection: assessment("prompt_injection"),
            threat: assessment("threat"),
        }
    }
    pub fn l1_categories(&self) -> Vec<String> {
        let inventory = rules();
        let mut categories: Vec<String> = ["pii", "dlp", "prompt_injection"]
            .into_iter()
            .filter(|category| {
                inventory.iter().any(|rule| {
                    rule.category == *category && self.l1_rules.get(&rule.id) == Some(&true)
                })
            })
            .map(String::from)
            .collect();
        // Keep one gated-off L1 pipeline to produce a complete, explicit no-match
        // classification when the user has disabled every rule.
        if categories.is_empty() {
            categories.push("pii".into());
        }
        categories
    }
    pub fn apply(&self, base: &Config) -> Config {
        let mut config = base.clone();
        config.plugin_policies.clear();
        config.ark.categories = self.l1_categories();
        config.ark.max_level = "l1".into();
        config.analysis = crate::analysis_config::AnalysisConfig {
            l1_rules: self.l1_rules.clone(),
            user_prompt_pii: true,
            ..Default::default()
        };
        for (category, rule) in [
            ("prompt_injection", &self.injection),
            ("threat", &self.threat),
        ] {
            if rule.enabled {
                if !config.ark.categories.iter().any(|c| c == category) {
                    config.ark.categories.push(category.into());
                }
                config
                    .analysis
                    .category_levels
                    .insert(category.into(), rule.max_level.clone());
            }
        }
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

/// Scoped model policies consume Ark's calibrated candidate decision. The
/// scanner never applies a second confidence threshold.
pub fn assess(mut outcome: crate::ark::AnalysisOutcome) -> crate::ark::AnalysisOutcome {
    for result in &mut outcome.classifications {
        if !["l2", "l3"].contains(&result.level.as_str())
            || !["prompt_injection", "threat"].contains(&result.category.as_str())
        {
            continue;
        }
        let Some(candidate) = result
            .decision
            .as_ref()
            .and_then(|decision| decision.get("decision_candidate"))
            .and_then(|candidate| {
                serde_json::from_value::<patronus_ark::DecisionCandidate>(candidate.clone()).ok()
            })
        else {
            continue;
        };
        result.source = candidate.source;
        result.label = candidate.class_name;
        result.confidence = candidate.confidence.clamp(0.0, 1.0);
        result.matched = candidate.accepted;
        if !result.matched {
            result.evidence.clear()
        }
    }
    outcome
}
