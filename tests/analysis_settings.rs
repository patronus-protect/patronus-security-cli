use patronus_security_scanner::{
    ark::{ArkAnalyzer, ChunkInput, ContentAnalyzer},
    config::{Config, DEFAULTS},
    plugin_settings::PluginSettings,
};

#[test]
fn validates_categories_levels_and_l1_options_without_loading_models() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.validate().unwrap();
    config.ark.categories.push("unsafe_action".into());
    config.validate().unwrap();
    config.ark.categories.push("threat".into());
    assert!(
        config.validate().is_err(),
        "old names are migrated on load, not accepted"
    );
    config.ark.categories.pop();
    config.ark.max_level = "l2".into();
    assert!(config.validate().is_err(), "Ark Core has no L2");
    config.ark.max_level = "l3".into();
    config.validate().unwrap();
    config.analysis.l1_models.insert("pii".into(), false);
    assert!(
        config.validate().is_err(),
        "L1 models exist only for attack classes"
    );
    config.analysis.l1_models.clear();
    config.analysis.l1_models.insert("jailbreak".into(), false);
    config.validate().unwrap();
    config.analysis.l1_detectors.insert("typo".into(), false);
    assert!(config.validate().is_err());
}

#[test]
fn legacy_categories_levels_and_profiles_migrate_to_ark_core() {
    let mut config: Config = toml::from_str(&format!(
        "{DEFAULTS}\n[analysis.category_levels]\nprompt_injection = \"l2\"\n[analysis.confidence]\nthreat = 0.5\n"
    ).replace("[analysis.cascade]\n# injection = { l1_clear_threshold = -2.0 }\n", ""))
    .unwrap();
    config.ark.categories = vec!["prompt_injection".into(), "dlp".into(), "threat".into()];
    let mut profile =
        patronus_security_scanner::plugin_policies::Profile::current(&config, "tool_result");
    profile.injection = Some(
        serde_json::from_value(serde_json::json!({"enabled": true, "max_level": "l2"})).unwrap(),
    );
    profile.threat = Some(
        serde_json::from_value(serde_json::json!({"enabled": true, "max_level": "l3"})).unwrap(),
    );
    config
        .plugin_policies
        .insert("codex.tool_result".into(), profile);
    config.migrate_legacy();
    assert_eq!(
        config.ark.categories,
        [
            "injection",
            "jailbreak",
            "prompt_extraction",
            "tool_poisoning",
            "dlp",
            "unsafe_action",
            "harmful_content",
            "exfiltration",
            "toxic_language"
        ]
    );
    assert_eq!(
        config.ark.max_level, "l3",
        "an injection model level becomes Wolf"
    );
    let profile = &config.plugin_policies["codex.tool_result"];
    assert!(profile.wolf && profile.injection.is_none() && profile.threat.is_none());
    config.validate().unwrap();
    let saved = toml::to_string(&config).unwrap();
    for legacy in [
        "category_levels",
        "confidence",
        "prompt_injection",
        "threat =",
    ] {
        assert!(!saved.contains(legacy), "{legacy} is not written back");
    }
    // The 0.1.16 injection producer switch maps to Ark Core's injection producers.
    config
        .analysis
        .l1_detectors
        .insert("injection_l1".into(), false);
    config.migrate_legacy();
    assert_eq!(config.analysis.l1_detectors.get("injection_l1"), None);
    assert!(!config.analysis.l1_detectors["injection_rule_catalog"]);
    assert!(!config.analysis.l1_detectors["injection_structural"]);
    config.validate().unwrap();
    // Idempotent.
    let before = config.ark.categories.clone();
    config.migrate_legacy();
    assert_eq!(config.ark.categories, before);
}

#[test]
fn l1_detector_switch_reaches_ark_and_never_claims_clean_without_a_detector() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.ark.categories = vec!["pii".into()];
    let input = ChunkInput {
        input_tokens: None,
        run_id: "test",
        chunk_id: "chunk",
        file_id: "file",
        path: "text",
        content: "Contact alice@example.org",
    };
    let mut enabled = ArkAnalyzer::with_policy(&config.ark, &config.analysis, false).unwrap();
    enabled.prepare().unwrap();
    assert!(enabled
        .analyze(input.clone())
        .unwrap()
        .classifications
        .iter()
        .any(|c| c.matched));
    config.analysis.l1_detectors.insert("pii".into(), false);
    let mut disabled = ArkAnalyzer::with_policy(&config.ark, &config.analysis, false).unwrap();
    disabled.prepare().unwrap();
    let result = disabled.analyze(input).unwrap();
    assert!(!result.failures.is_empty());
    assert!(result.classifications.is_empty());
}

#[test]
fn user_prompt_pii_is_opt_in() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.analysis.user_prompt_pii = true;
    let mut scanner = ArkAnalyzer::with_policy(&config.ark, &config.analysis, false).unwrap();
    scanner.prepare().unwrap();
    let result = scanner
        .analyze_user_prompt(ChunkInput {
            input_tokens: None,
            run_id: "test",
            chunk_id: "chunk",
            file_id: "file",
            path: "text",
            content: "Contact alice@example.org",
        })
        .unwrap();
    assert!(result
        .classifications
        .iter()
        .any(|c| c.category == "pii" && c.matched));
}

#[test]
fn plugin_settings_round_trip_and_reject_unknown_hosts() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plugins.json");
    let mut settings = PluginSettings::default();
    settings.hooks.mcp_result = false;
    settings
        .disabled_chats
        .get_mut("codex")
        .unwrap()
        .push("chat-a".into());
    settings.write(&path).unwrap();
    let loaded = PluginSettings::load(&path).unwrap();
    assert!(!loaded.hooks.mcp_result);
    assert_eq!(loaded.disabled_chats["codex"], vec!["chat-a"]);
    assert!(loaded.disabled_chats["claude"].is_empty());
    settings.disabled_chats.insert("unknown".into(), vec![]);
    assert!(settings.write(&path).is_err());
}

#[test]
fn cli_pauses_and_resumes_only_the_selected_chat() {
    let root = tempfile::tempdir().unwrap();
    for chat in ["chat-a", "chat-b"] {
        assert_cmd::Command::cargo_bin("patronus-security-scanner")
            .unwrap()
            .env("PATRONUS_DATA_DIR", root.path())
            .args(["plugins", "pause", "codex", chat])
            .assert()
            .success();
    }
    assert_cmd::Command::cargo_bin("patronus-security-scanner")
        .unwrap()
        .env("PATRONUS_DATA_DIR", root.path())
        .args(["plugins", "resume", "codex", "chat-a"])
        .assert()
        .success();
    let settings = PluginSettings::load(&root.path().join("plugins.json")).unwrap();
    assert_eq!(settings.disabled_chats["codex"], vec!["chat-b"]);
    assert!(settings.disabled_chats["claude"].is_empty());
}
