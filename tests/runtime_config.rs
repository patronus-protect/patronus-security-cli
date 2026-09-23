use patronus_security_scanner::config::{Config, DEFAULTS};

#[test]
fn response_wait_defaults_to_500_and_accepts_300() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    assert_eq!(config.runtime.response_wait_ms, 1000);
    config.runtime.response_wait_ms = 300;
    config.validate().unwrap();
    config.runtime.response_wait_ms = config.runtime.scan_timeout_ms + 1;
    assert!(config.validate().is_err());
}

#[test]
fn runtime_limits_must_be_bounded_and_scan_categories_nonempty() {
    let mut config: Config = toml::from_str(DEFAULTS).unwrap();
    config.runtime.max_pending_jobs = 0;
    assert!(config.validate().is_err());
    config.runtime.max_pending_jobs = 64;
    config.ark.categories.clear();
    assert!(config.validate().is_err());
}
