use patronus_security_scanner::config::{Config, ProviderMode, DEFAULTS};

#[test]
fn compiled_defaults_are_valid_and_runnable() {
    let config: Config = toml::from_str(DEFAULTS).expect("defaults parse");
    config.validate().expect("defaults validate");
    assert_eq!(config.schema_version, 1);
    assert_eq!(config.provider.mode, ProviderMode::Local);
    assert_eq!(config.ark.max_level, "l1");
    assert!(!config.ark.download_files);
}

#[test]
fn cloud_providers_are_explicit_and_validated() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.provider.mode = ProviderMode::Hybrid;
    config.validate().expect("hybrid uses the fixed API origin");
    config.provider.mode = ProviderMode::Api;
    config.validate().expect("API provider is valid");
    config.provider.api_base_url = "https://api.patronus.example".into();
    assert!(config.validate().is_err());
}

#[test]
fn unknown_keys_are_rejected() {
    let text = DEFAULTS.replace("schema_version = 1", "schema_version = 1\nunknown = true");
    assert!(toml::from_str::<Config>(&text).is_err());
}

#[test]
fn invalid_chunk_overlap_is_rejected() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.chunking.overlap_bytes = config.chunking.target_bytes;
    assert!(config.validate().is_err());
}

#[test]
fn redaction_hides_secret_like_keys_recursively() {
    let config: Config = toml::from_str(DEFAULTS).unwrap();
    let printed = config.redacted_toml().unwrap();
    assert!(!printed.contains("PATRONUS_SUPPORT_TOKEN"));
}

#[test]
fn model_backed_threat_category_is_a_valid_explicit_selection() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.ark.categories = vec!["threat".into()];
    config.ark.max_level = "l2".into();
    config.validate().expect("threat selection is supported");
}
