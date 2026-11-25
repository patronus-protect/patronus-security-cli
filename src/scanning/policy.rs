//! Local analysis policies use Ark's own execution gates.
use crate::{
    ark::{AnalysisOutcome, ChunkInput, ContentAnalyzer},
    config::Config,
    error::Result,
};
use patronus_ark_core::detectors::{dlp::dlp::DLP_PATTERNS, pii::pii::PII_PATTERNS};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub category: String,
    pub description: String,
    pub default_enabled: bool,
    #[serde(default = "all_modes")]
    pub modes: Vec<String>,
}

/// PII/DLP inventory comes directly from the pinned Ark Core dependency.
/// Injection metadata uses its canonical gate IDs (several patterns share one
/// rule), each under the attack class it reports to; threat rules
/// (`ark.threat.*`) carry their class too. Snapshot source: patronus-ark-core
/// 0.1.18, detectors/injection/rules/rule_categories.json and
/// detectors/threat/rules.json, MIT OR Apache-2.0. Refresh both snapshots when
/// upgrading the pinned dependency.
fn all_modes() -> Vec<String> {
    ["strict", "balanced", "recall"]
        .into_iter()
        .map(String::from)
        .collect()
}

pub fn rules() -> Vec<Rule> {
    let mut rules: Vec<Rule> = serde_json::from_str(include_str!("l1_injection_rules.json"))
        .expect("embedded Ark rule metadata");
    rules.extend(
        serde_json::from_str::<Vec<Rule>>(include_str!("l1_threat_rules.json"))
            .expect("embedded Ark threat rule metadata"),
    );
    for p in PII_PATTERNS {
        rules.push(Rule {
            modes: if p.scored_only {
                vec!["balanced".into(), "recall".into()]
            } else {
                all_modes()
            },
            id: p.name.into(),
            category: "pii".into(),
            description: p.entity_group.replace('_', " "),
            default_enabled: true,
        });
    }
    for p in DLP_PATTERNS {
        rules.push(Rule {
            modes: all_modes(),
            id: p.name.into(),
            category: "dlp".into(),
            description: p.entity_group.replace('_', " "),
            default_enabled: false,
        });
    }
    // Detectors that left `dlp` in Ark Core 0.1.18: risky operations report
    // under `unsafe_action`, secret transfers under `exfiltration`.
    for (id, category, description) in [
        (
            "dlp_sensitive_material",
            "unsafe_action",
            "Sensitive material",
        ),
        ("dlp_secret_transfer", "exfiltration", "Secret transfer"),
        ("dlp_mcp_runtime_risk", "unsafe_action", "MCP runtime risk"),
        (
            "dlp_mcp_policy",
            "unsafe_action",
            "MCP risk indicators in text",
        ),
        (
            "dlp_destructive_operation",
            "unsafe_action",
            "Destructive operation in text",
        ),
    ] {
        rules.push(Rule {
            modes: all_modes(),
            id: id.into(),
            category: category.into(),
            description: description.into(),
            default_enabled: false,
        });
    }
    let defaults = patronus_ark_core::cascade::ScanGateMatrix::default();
    for rule in &mut rules {
        rule.default_enabled = defaults.allows_rule(&rule.id);
    }
    rules.sort_by(|a, b| (&a.category, &a.id).cmp(&(&b.category, &b.id)));
    rules
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    UserInput,
    ToolResult,
    McpResult,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    #[serde(default)]
    pub host: Option<String>,
    pub surface: Surface,
    pub text: String,
}

struct Prompt<'a>(&'a dyn ContentAnalyzer);
struct Scoped<'a>(&'a dyn ContentAnalyzer, String);
impl ContentAnalyzer for Scoped<'_> {
    fn prepare(&mut self) -> Result<()> {
        Ok(())
    }
    fn analyze(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        self.0.analyze_scoped(input, &self.1)
    }
}
impl ContentAnalyzer for Prompt<'_> {
    fn prepare(&mut self) -> Result<()> {
        Ok(())
    }
    fn analyze(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        self.0.analyze_user_prompt(input)
    }
}
/// Exercise exactly the same scanner and text projection as plugin runtime jobs.
pub fn check(config: &Config, check: Check) -> Result<crate::runtime::protocol::ScanOutcome> {
    config.validate()?;
    let mut analyzer = crate::inference::Inference::new(config)?;
    analyzer.prepare()?;
    let prompt = Prompt(&analyzer);
    let surface = match check.surface {
        Surface::UserInput => "user_input",
        Surface::ToolResult => "tool_result",
        Surface::McpResult => "mcp_result",
    };
    let scoped = check
        .host
        .map(|host| Scoped(&analyzer, format!("{host}.{surface}")));
    let selected: &dyn ContentAnalyzer = if let Some(scoped) = &scoped {
        scoped
    } else {
        match check.surface {
            Surface::UserInput => &prompt,
            Surface::ToolResult | Surface::McpResult => &analyzer,
        }
    };
    Ok(crate::runtime::payload::analyze_payload(
        selected,
        &serde_json::json!(check.text),
        &config.chunking,
        std::time::Instant::now()
            + std::time::Duration::from_millis(config.runtime.scan_timeout_ms),
    ))
}
