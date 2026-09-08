use patronus_security_scanner::{
    ark::{ArkAnalyzer, ChunkInput, ContentAnalyzer},
    config::{Config, DEFAULTS},
    plugin_settings::PluginSettings,
};

#[test]
fn validates_category_levels_and_l1_options_without_loading_models() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.ark.categories.push("threat".into());
    assert!(config.validate().is_err());
    config
        .analysis
        .category_levels
        .insert("threat".into(), "l2".into());
    config.validate().unwrap();
    config.analysis.l1.insert("pii".into(), false);
    assert!(config.validate().is_err());
    config
        .analysis
        .category_levels
        .insert("pii".into(), "l3".into());
    config.validate().unwrap();
    config.analysis.l1_detectors.insert("typo".into(), false);
    assert!(config.validate().is_err());
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
