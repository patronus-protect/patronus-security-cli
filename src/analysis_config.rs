use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::ArkConfig;

/// Execution policy layered over the enabled Ark categories.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisConfig {
    pub category_levels: BTreeMap<String, String>,
    pub l1: BTreeMap<String, bool>,
    pub l1_detectors: BTreeMap<String, bool>,
    pub l1_rules: BTreeMap<String, bool>,
    pub user_prompt_pii: bool,
    pub confidence: BTreeMap<String, f64>,
}

pub const L1_DETECTORS: &[&str] = &[
    "pii",
    "dlp",
    "injection_l1",
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

impl AnalysisConfig {
    pub fn level<'a>(&'a self, category: &str, ark: &'a ArkConfig) -> &'a str {
        self.category_levels
            .get(category)
            .map(String::as_str)
            .unwrap_or(&ark.max_level)
    }

    pub fn validate(&self, ark: &ArkConfig) -> Result<(), String> {
        for category in self.category_levels.keys().chain(self.l1.keys()) {
            if !["prompt_injection", "pii", "dlp", "threat"].contains(&category.as_str()) {
                return Err(format!(
                    "unknown analysis category {category:?}; use canonical names"
                ));
            }
        }
        if self
            .category_levels
            .values()
            .any(|level| !["l1", "l2", "l3"].contains(&level.as_str()))
        {
            return Err("category levels must be l1, l2, or l3".into());
        }
        for (category, threshold) in &self.confidence {
            if !["prompt_injection", "threat"].contains(&category.as_str())
                || !threshold.is_finite()
                || !(0.0..=1.0).contains(threshold)
            {
                return Err(
                    "Confidence rules require Injection/Threat and values between 0 and 1".into(),
                );
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
        for category in &ark.categories {
            let category = if category == "injection" {
                "prompt_injection"
            } else {
                category
            };
            if self.level(category, ark) == "l1"
                && (category == "threat" || self.l1.get(category) == Some(&false))
            {
                return Err(format!(
                    "{category} has no active L1 stage; choose L2/L3 or remove the category"
                ));
            }
        }
        Ok(())
    }
}
