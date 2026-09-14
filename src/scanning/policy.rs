//! Local analysis policies use Ark's own execution gates.
use crate::{
    ark::{AnalysisOutcome, ChunkInput, ContentAnalyzer},
    config::Config,
    error::Result,
};
use patronus_ark::detectors::{dlp::dlp::DLP_PATTERNS, pii::pii::PII_PATTERNS};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub category: String,
    pub description: String,
    pub default_enabled: bool,
}

/// PII/DLP inventory comes directly from the pinned Ark dependency. Injection
/// metadata uses its canonical gate IDs (several patterns share one rule).
/// Snapshot source: patronus-ark 0.1.7, detectors/injection/rules/*.json,
/// GPL-3.0-only. Refresh the metadata when upgrading the pinned dependency.
pub fn rules() -> Vec<Rule> {
    let mut rules: Vec<Rule> = serde_json::from_str(include_str!("l1_injection_rules.json"))
        .expect("embedded Ark rule metadata");
    for p in PII_PATTERNS {
        rules.push(Rule {
            id: p.name.into(),
            category: "pii".into(),
            description: p.entity_group.replace('_', " "),
            default_enabled: true,
        });
    }
    for p in DLP_PATTERNS {
        rules.push(Rule {
            id: p.name.into(),
            category: "dlp".into(),
            description: p.entity_group.replace('_', " "),
            default_enabled: false,
        });
    }
    for (id, description) in [
        ("dlp_sensitive_material", "Sensitive material"),
        ("dlp_secret_transfer", "Secret transfer"),
        ("dlp_mcp_runtime_risk", "MCP runtime risk"),
        ("dlp_mcp_policy", "MCP risk indicators in text"),
        ("dlp_destructive_operation", "Destructive operation in text"),
    ] {
        rules.push(Rule {
            id: id.into(),
            category: "dlp".into(),
            description: description.into(),
            default_enabled: false,
        });
    }
    let defaults = patronus_ark::ScanGateMatrix::default();
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
