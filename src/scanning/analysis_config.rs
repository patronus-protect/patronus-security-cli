use std::collections::{BTreeMap, HashMap};

use patronus_ark_core::cascade::{CascadeConfig, ModuleConfig};
use patronus_ark_core::detectors::text::L1ModelConfig;
use serde::{Deserialize, Serialize};

use crate::config::{is_attack_class, scan_category, ArkConfig};

/// Execution policy layered over the enabled Ark Core categories.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisConfig {
    pub pii_mode: patronus_ark_core::native::ScoreMode,
    pub dlp_mode: patronus_ark_core::native::ScoreMode,
    /// Ark Core's built-in L1 model per attack class; unset means on.
    pub l1_models: BTreeMap<String, bool>,
    /// Cascade cuts per category; unset cuts keep Ark Core's calibrated defaults.
    pub cascade: BTreeMap<String, CascadeCuts>,
    pub l1_detectors: BTreeMap<String, bool>,
    pub l1_rules: BTreeMap<String, bool>,
    pub user_prompt_pii: bool,
    /// Switch L1 off so Wolf answers every `injection` input (performance probe).
    #[serde(skip)]
    pub skip_l1: bool,
    /// Per-category levels before Ark Core 0.1.18; read once by
    /// [`crate::config::Config::migrate_legacy`] and never written.
    #[serde(rename = "category_levels", skip_serializing)]
    pub legacy_category_levels: BTreeMap<String, String>,
    #[serde(rename = "l1", skip_serializing)]
    pub legacy_l1: BTreeMap<String, bool>,
    #[serde(rename = "confidence", skip_serializing)]
    pub legacy_confidence: BTreeMap<String, f64>,
}

/// One category's cascade cuts (Ark Core `cascade.modules.<category>`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CascadeCuts {
    /// The rules' detect cut on their probability (`0.0..=1.0`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detect_threshold: Option<f64>,
    /// The rules' clear cut; off by default, so undetected input escalates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clear_threshold: Option<f64>,
    /// The L1 model's detect cut on its logit; default: its 0.1 % FPR cut.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l1_detect_threshold: Option<f64>,
    /// The L1 model's clear cut on its logit; default: its 1 % FPR cut.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l1_clear_threshold: Option<f64>,
    /// `false` switches the L1 model's clear cut off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l1_clear_enabled: Option<bool>,
}

/// Ark Core's native producers (`native:<name>` model gates).
pub const L1_DETECTORS: &[&str] = &[
    "pii",
    "dlp",
    "threat_l1",
    "injection_rule_catalog",
    "injection_structural",
    "cross_tool_instruction",
    "instruction_leak",
    "encoded_instruction",
    "multi_turn_escalation",
    "guardrail_tamper",
    "tool_output_instruction",
    "hidden_html_instruction",
    "unicode_confusable",
    "zero_width_obfuscation",
    "agentic_control_abuse",
    "binary_smuggling",
    "instruction_override",
    "jailbreak_framing",
    "covert_instruction",
    "instruction_boundary",
    "authority_escalation",
    "tool_call_injection",
    "output_manipulation",
    "sensitive_material",
    "secret_transfer",
    "mcp_runtime_risk",
    "mcp_policy",
    "destructive_operation",
];

/// The built-in L1 model of an attack class (Ark Core `BUILTIN_L1_MODELS`).
pub fn builtin_l1_model(category: &str) -> Option<&'static str> {
    use patronus_ark_core::SecurityCategory as Ark;
    let parsed = category.parse::<Ark>().ok()?;
    Ark::ATTACK_CLASSES.contains(&parsed).then(|| match parsed {
        Ark::Injection => "instruction_injection",
        other => other.as_str(),
    })
}

impl AnalysisConfig {
    pub fn l1_model_enabled(&self, category: &str) -> bool {
        builtin_l1_model(category).is_some() && self.l1_models.get(category) != Some(&false)
    }

    /// The Ark Core cascade for `categories`: every attack class with its
    /// built-in L1 model (unless switched off) and the configured cuts.
    pub fn cascade_config(&self, categories: &[String]) -> CascadeConfig {
        let mut modules = HashMap::new();
        for category in categories {
            let Ok(parsed) = scan_category(category) else {
                continue;
            };
            let cuts = self.cascade.get(category).cloned().unwrap_or_default();
            let l1_model = self
                .l1_model_enabled(category)
                .then(|| builtin_l1_model(category))
                .flatten()
                .map(|name| {
                    let mut model = L1ModelConfig::builtin(name);
                    model.detect_threshold = cuts.l1_detect_threshold;
                    model.clear_threshold = cuts.l1_clear_threshold;
                    model.clear_enabled = cuts.l1_clear_enabled.unwrap_or(true);
                    model
                });
            modules.insert(
                parsed,
                ModuleConfig {
                    detect_threshold: cuts.detect_threshold,
                    clear_threshold: cuts.clear_threshold,
                    l1_model,
                },
            );
        }
        CascadeConfig { modules }
    }

    pub fn validate(&self, _ark: &ArkConfig) -> Result<(), String> {
        for category in self.l1_models.keys() {
            if !is_attack_class(category) {
                return Err(format!(
                    "analysis.l1_models.{category}: L1 models exist only for attack classes"
                ));
            }
        }
        for (category, cuts) in &self.cascade {
            scan_category(category).map_err(|error| format!("analysis.cascade: {error}"))?;
            for (name, value) in [
                ("detect_threshold", cuts.detect_threshold),
                ("clear_threshold", cuts.clear_threshold),
            ] {
                if value.is_some_and(|value| !(0.0..=1.0).contains(&value)) {
                    return Err(format!(
                        "analysis.cascade.{category}.{name} must be between 0 and 1"
                    ));
                }
            }
            if let (Some(detect), Some(clear)) = (cuts.detect_threshold, cuts.clear_threshold) {
                if clear > detect {
                    return Err(format!(
                        "analysis.cascade.{category}.clear_threshold must not exceed detect_threshold"
                    ));
                }
            }
            if [cuts.l1_detect_threshold, cuts.l1_clear_threshold]
                .iter()
                .flatten()
                .any(|value| !value.is_finite())
            {
                return Err(format!(
                    "analysis.cascade.{category}: L1 model cuts must be finite"
                ));
            }
            if (cuts.l1_detect_threshold.is_some()
                || cuts.l1_clear_threshold.is_some()
                || cuts.l1_clear_enabled.is_some())
                && !is_attack_class(category)
            {
                return Err(format!(
                    "analysis.cascade.{category}: L1 model cuts exist only for attack classes"
                ));
            }
        }
        let catalog = crate::policy::rules();
        for id in self.l1_rules.keys() {
            if !catalog.iter().any(|rule| rule.id == *id) {
                return Err(format!("unknown L1 rule {id:?}"));
            }
        }
        for detector in self.l1_detectors.keys() {
            if !L1_DETECTORS.contains(&detector.as_str()) {
                return Err(format!("unknown L1 detector {detector:?}"));
            }
        }
        Ok(())
    }
}
