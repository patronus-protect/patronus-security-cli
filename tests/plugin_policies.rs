use patronus_security_scanner::{
    config::{Config, DEFAULTS},
    plugin_policies::Profile,
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

#[test]
fn wolf_switch_selects_l3_only_where_injection_is_scanned() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    let mut profile = Profile::current(&config, "tool_result");
    assert!(!profile.wolf, "L1 by default");
    assert_eq!(profile.apply(&config).ark.max_level, "l1");
    profile.wolf = true;
    let applied = profile.apply(&config);
    assert_eq!(applied.ark.max_level, "l3");
    assert_eq!(applied.ark.categories, config.ark.categories);
    applied.validate().unwrap();
    config.ark.categories.retain(|c| c != "injection");
    assert_eq!(
        profile.apply(&config).ark.max_level,
        "l1",
        "Wolf only answers injection"
    );
    config.ark.max_level = "l3".into();
    config.ark.categories.push("injection".into());
    assert!(
        Profile::current(&config, "mcp_result").wolf,
        "scopes inherit the global L3"
    );
}
#[test]
fn profiles_reject_unknown_scope_and_rule() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    let mut profile = Profile::current(&config, "tool_result");
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
    profile.injection = Some(
        serde_json::from_value(
            serde_json::json!({"enabled": true, "max_level": "l2", "min_confidence": 0.73}),
        )
        .unwrap(),
    );
    config
        .plugin_policies
        .insert("codex.tool_result".into(), profile);
    let serialized = config.redacted_toml().unwrap();
    assert!(!serialized.contains("min_confidence"));
    assert!(
        !serialized.contains("max_level = \"l2\""),
        "legacy assessments are not written"
    );
    let restored: Config = toml::from_str(&serialized).unwrap();
    assert_eq!(
        restored.plugin_policies["codex.tool_result"].l1_rules,
        config.plugin_policies["codex.tool_result"].l1_rules
    );
    restored.validate().unwrap();
}

#[test]
fn profiles_saved_before_an_ark_update_get_new_rules_at_their_default() {
    let config: Config = toml::from_str(DEFAULTS).unwrap();
    let mut saved = Profile::current(&config, "tool_result");
    // A profile from before Ark 0.1.10 does not know the governance rules.
    saved
        .l1_rules
        .retain(|id, _| !id.starts_with("ark.injection.governance."));
    assert!(saved.validate().is_err());
    saved.add_missing_rules();
    saved.validate().unwrap();
    assert!(saved.l1_rules["ark.injection.governance.direct_admin_grant"]);
    // Unknown rules still fail: migration only adds what the catalog defines.
    saved.l1_rules.insert("ark.injection.unknown".into(), true);
    assert!(saved.validate().is_err());
}
