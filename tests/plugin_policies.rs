use patronus_security_scanner::{
    ark::{AnalysisOutcome, FinalClassification},
    config::{Config, DEFAULTS},
    plugin_policies::{self, Profile},
    policy::{self, Check, Surface},
    runtime::protocol::Verdict,
};

#[test]
fn per_plugin_surface_rules_change_real_scans_without_affecting_other_scopes() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.ark.categories = vec!["pii".into()];
    config.analysis.user_prompt_pii = true;
    let enabled = Profile::current(&config, "tool_result");
    let mut disabled = enabled.clone();
    disabled.l1_rules.insert("pii_email".into(), false);
    config
        .plugin_policies
        .insert("codex.tool_result".into(), disabled.clone());
    config
        .plugin_policies
        .insert("claude.user_input".into(), disabled);
    config
        .plugin_policies
        .insert("deepseek.mcp_result".into(), enabled);
    for (host, surface, verdict) in [
        ("codex", Surface::ToolResult, Verdict::Approved),
        ("claude", Surface::UserInput, Verdict::Approved),
        ("deepseek", Surface::McpResult, Verdict::Dangerous),
        ("codex", Surface::McpResult, Verdict::Dangerous),
    ] {
        let result = policy::check(
            &config,
            Check {
                host: Some(host.into()),
                surface,
                text: "alice@example.com".into(),
            },
        )
        .unwrap();
        assert!(result.coverage.complete, "{result:?}");
        assert_eq!(result.verdict, Some(verdict));
    }
}

fn classification(category: &str, level: &str, confidence: f64) -> FinalClassification {
    FinalClassification {
        schema: "test",
        run_id: "test".into(),
        chunk_id: "c".into(),
        file_id: "f".into(),
        path: "text".into(),
        category: category.into(),
        source: "fixture".into(),
        level: level.into(),
        terminal: true,
        matched: true,
        label: "unsafe".into(),
        confidence,
        decision: None,
        evidence: vec![],
        duration_ms: 0,
        warnings: vec![],
    }
}
#[test]
fn confidence_boundary_only_filters_injection_and_threat_models() {
    let thresholds = [("prompt_injection".into(), 0.8), ("threat".into(), 0.8)].into();
    let outcome = AnalysisOutcome {
        classifications: vec![
            classification("prompt_injection", "l1", 0.7),
            classification("prompt_injection", "l2", 0.79),
            classification("prompt_injection", "l3", 0.8),
            classification("threat", "l2", 0.79),
            classification("threat", "l3", 0.9),
            classification("pii", "l2", 0.1),
            classification("dlp", "l3", 0.1),
        ],
        failures: vec!["incomplete model".into()],
        degraded: true,
    };
    let result = plugin_policies::assess(outcome, &thresholds);
    assert_eq!(
        result
            .classifications
            .iter()
            .map(|c| c.matched)
            .collect::<Vec<_>>(),
        vec![true, false, true, false, true, true, true]
    );
    assert!(result.degraded);
    assert_eq!(result.failures.len(), 1);
}
#[test]
fn profiles_reject_unknown_scope_rule_and_invalid_confidence() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    let mut profile = Profile::current(&config, "tool_result");
    profile.threat.min_confidence = 1.1;
    assert!(profile.validate().is_err());
    profile.threat.min_confidence = 0.8;
    profile.l1_rules.insert("not-a-rule".into(), true);
    assert!(profile.validate().is_err());
    config
        .plugin_policies
        .insert("unknown.tool_result".into(), profile);
    assert!(config.validate().is_err());
}

#[test]
fn frozen_config_preserves_boolean_rules_with_secret_names() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.plugin_policies.insert(
        "codex.tool_result".into(),
        Profile::current(&config, "tool_result"),
    );
    let restored: Config = toml::from_str(&config.redacted_toml().unwrap()).unwrap();
    assert_eq!(
        restored.plugin_policies["codex.tool_result"].l1_rules,
        config.plugin_policies["codex.tool_result"].l1_rules
    );
    restored.validate().unwrap();
}
