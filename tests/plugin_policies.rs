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
fn scoped_model_policy_uses_arks_decision_candidate_without_rethresholding() {
    let mut rejected = classification("prompt_injection", "l2", 0.99);
    rejected.decision = Some(serde_json::json!({
        "final_result": {"class_name": "benign", "confidence": 0.0, "source": "default"},
        "decision_candidate": {
            "source": "l2", "class_name": "injection", "confidence": 0.97,
            "acceptance_threshold": 0.99, "accepted": false, "evidence": null
        }
    }));
    let mut accepted = classification("threat", "l3", 0.1);
    accepted.decision = Some(serde_json::json!({
        "final_result": {"class_name": "malware", "confidence": 0.91, "source": "l3"},
        "decision_candidate": {
            "source": "l3", "class_name": "malware", "confidence": 0.91,
            "acceptance_threshold": 0.9, "accepted": true, "evidence": null
        }
    }));
    let outcome = AnalysisOutcome {
        classifications: vec![rejected, accepted, classification("pii", "l2", 0.1)],
        failures: vec!["incomplete model".into()],
        degraded: true,
        notice: None,
    };
    let result = plugin_policies::assess(outcome);
    assert_eq!(
        result
            .classifications
            .iter()
            .map(|c| (c.matched, c.label.as_str(), c.confidence, c.source.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (false, "injection", 0.97, "l2"),
            (true, "malware", 0.91, "l3"),
            (true, "unsafe", 0.1, "fixture"),
        ]
    );
    assert!(result.degraded);
    assert_eq!(result.failures.len(), 1);
}
#[test]
fn profiles_reject_unknown_scope_rule_and_invalid_confidence() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    let mut profile = Profile::current(&config, "tool_result");
    profile.threat.min_confidence = Some(1.1);
    assert!(profile.validate().is_err());
    profile.threat.min_confidence = None;
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
    let mut profile = Profile::current(&config, "tool_result");
    profile.injection.min_confidence = Some(0.73);
    config
        .plugin_policies
        .insert("codex.tool_result".into(), profile);
    let serialized = config.redacted_toml().unwrap();
    assert!(!serialized.contains("min_confidence"));
    let restored: Config = toml::from_str(&serialized).unwrap();
    assert_eq!(
        restored.plugin_policies["codex.tool_result"].l1_rules,
        config.plugin_policies["codex.tool_result"].l1_rules
    );
    restored.validate().unwrap();
}
