use patronus_ark::ScoreMode;
use patronus_security_scanner::{
    config::{Config, DEFAULTS},
    plugin_policies::Profile,
    policy,
    runtime::protocol::Verdict,
    scanning::shell_config::{AskBehavior, ShellPolicy},
};

const CEDAR: &str = r#"@id("user.no_kubectl_delete") @decision("block") @title("No kubectl deletes")
forbid (principal, action == Action::"segment", resource)
when { context.program == "kubectl" && context.verb == "DELETE" };"#;

#[test]
fn modes_round_trip_inherit_and_override_without_losing_profiles() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.analysis.pii_mode = ScoreMode::Recall;
    config.analysis.dlp_mode = ScoreMode::Balanced;
    let mut profile = Profile::current(&config, "tool_result");
    assert_eq!(profile.apply(&config).analysis.pii_mode, ScoreMode::Recall);
    profile.pii_mode = Some(ScoreMode::Strict);
    config
        .plugin_policies
        .insert("codex.tool_result".into(), profile);
    let loaded: Config = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
    loaded.validate().unwrap();
    let applied = loaded.plugin_policies["codex.tool_result"].apply(&loaded);
    assert_eq!(applied.analysis.pii_mode, ScoreMode::Strict);
    assert_eq!(applied.analysis.dlp_mode, ScoreMode::Balanced);
    let rule = policy::rules()
        .into_iter()
        .find(|r| r.id == "pii_aadhaar_in_context_free")
        .unwrap();
    assert_eq!(rule.modes, vec!["balanced", "recall"]);
}

#[test]
fn custom_cedar_and_host_settings_validate_before_save() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    assert_eq!(config.shell.default.ask_behavior, AskBehavior::Low);
    let mut policy = ShellPolicy {
        ask_behavior: AskBehavior::Ask,
        ..Default::default()
    };
    policy
        .cedar_policies
        .insert("kubectl.cedar".into(), CEDAR.into());
    config.shell.hosts.insert("claude".into(), policy);
    config.validate().unwrap();
    let round_trip: Config = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
    assert_eq!(
        round_trip.shell.hosts["claude"].ask_behavior,
        AskBehavior::Ask
    );
    config
        .shell
        .hosts
        .get_mut("claude")
        .unwrap()
        .cedar_policies
        .insert("invalid.cedar".into(), "not cedar".into());
    assert!(config.validate().is_err());
}

#[test]
fn api_never_silently_discards_a_scoring_mode() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    patronus_security_scanner::api_client::validate_modes(&config).unwrap();
    config.analysis.dlp_mode = ScoreMode::Recall;
    assert!(patronus_security_scanner::api_client::validate_modes(&config).is_err());
}

#[test]
fn pii_scored_mode_changes_real_detection_and_rule_gates_still_apply() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.ark.categories = vec!["pii".into()];
    config.ark.max_level = "l1".into();
    config.analysis.user_prompt_pii = true;
    for rule in policy::rules() {
        config.analysis.l1_rules.insert(rule.id, false);
    }
    config
        .analysis
        .l1_rules
        .insert("pii_aadhaar_in_context_free".into(), true);
    let check = |c: &Config| {
        policy::check(
            c,
            policy::Check {
                host: None,
                surface: policy::Surface::ToolResult,
                text: "2345 6789 0124".into(),
            },
        )
        .unwrap()
    };
    assert_eq!(check(&config).verdict, Some(Verdict::Approved));
    config.analysis.pii_mode = ScoreMode::Recall;
    assert_eq!(check(&config).verdict, Some(Verdict::Dangerous));
    config
        .analysis
        .l1_rules
        .insert("pii_aadhaar_in_context_free".into(), false);
    assert_eq!(check(&config).verdict, Some(Verdict::Approved));
}

#[test]
#[ignore = "requires pinned K26 assets in PATRONUS_K26_TEST_MODEL_DIR"]
fn k26_ask_mapping_and_custom_cedar_reach_the_actual_runtime() {
    use patronus_security_scanner::shell_check::ShellCheck;
    let root = std::path::PathBuf::from(std::env::var_os("PATRONUS_K26_TEST_MODEL_DIR").unwrap());
    let low = ShellCheck::new(Some(root.clone()));
    assert_eq!(low.check("npm install").risk, Some("low"));
    let mut policy = ShellPolicy {
        ask_behavior: AskBehavior::Ask,
        ..Default::default()
    };
    policy.cedar_policies.insert(
        "kubectl.cedar".into(),
        CEDAR.replace(
            r#"context.program == "kubectl" && context.verb == "DELETE""#,
            r#"context.program == "pwd""#,
        ),
    );
    let ask = ShellCheck::new(Some(root)).with_policy(policy);
    assert_eq!(ask.check("npm install").risk, Some("medium"));
    assert_eq!(ask.check("kubectl delete pod scratch").risk, Some("medium"));
    assert_eq!(low.check("pwd").status, "approved");
    assert_eq!(ask.check("pwd").risk, Some("medium"));
    assert!(ask.explain("pwd")["cat"]["policies"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["id"] == "user.no_kubectl_delete"));
}

#[test]
#[ignore = "requires pinned K26 assets in PATRONUS_K26_TEST_MODEL_DIR"]
fn runtime_selects_the_shell_host_override_without_changing_the_default() {
    use patronus_security_scanner::runtime::{protocol::RpcRequest, service::Runtime};
    let root = tempfile::tempdir().unwrap();
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.ark.max_level = "l1".into();
    config.ark.categories = vec!["pii".into()];
    config.ark.model_dir = Some(std::path::PathBuf::from(
        std::env::var_os("PATRONUS_K26_TEST_MODEL_DIR").unwrap(),
    ));
    config.shell.hosts.insert(
        "claude".into(),
        ShellPolicy {
            ask_behavior: AskBehavior::Ask,
            ..Default::default()
        },
    );
    let runtime = Runtime::start(config, root.path()).unwrap();
    for (host, risk) in [
        ("codex", "low"),
        ("claude", "medium"),
        ("cursor", "low"),
        ("deepseek", "low"),
    ] {
        let reply=runtime.handle(RpcRequest{id:host.into(),method:"check_command".into(),params:serde_json::json!({"host":host,"session":"session-012345678901234567890123456789","tool":"Bash","call_id":"test","command":"npm install"})});
        assert_eq!(reply["result"]["risk"], risk, "{reply}");
    }
}
