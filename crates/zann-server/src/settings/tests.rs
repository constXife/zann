use super::*;
use crate::config::{AuthMode, InternalRegistration};
use std::sync::Mutex;
use uuid::Uuid;

static ENV_LOCK: Mutex<()> = Mutex::new(());
const TEST_SMK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn clear_auth_env() {
    env::remove_var("ZANN_AUTH_MODE");
    env::remove_var("ZANN_AUTH_INTERNAL_ENABLED");
    env::remove_var("ZANN_AUTH_INTERNAL_REGISTRATION");
    env::remove_var("ZANN_AUTH_OIDC_ENABLED");
    env::remove_var("ZANN_CONFIG_PATH");
}

fn clear_pepper_env() {
    env::remove_var("ZANN_PASSWORD_PEPPER");
    env::remove_var("ZANN_PASSWORD_PEPPER_FILE");
    env::remove_var("ZANN_TOKEN_PEPPER");
    env::remove_var("ZANN_TOKEN_PEPPER_FILE");
}

fn clear_metrics_env() {
    env::remove_var("ZANN_ENV");
    env::remove_var("ZANN_ALLOW_METRICS_DEBUG");
    env::remove_var("ZANN_METRICS_ENABLED");
    env::remove_var("ZANN_METRICS_ENDPOINT");
    env::remove_var("ZANN_METRICS_PROFILE");
    env::remove_var("ZANN_SMK");
}

fn set_policy_config_path() {
    let policy_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policies.default.yaml");
    let config_path =
        std::env::temp_dir().join(format!("zann-test-config-{}.yaml", Uuid::new_v4()));
    let contents = format!("policy:\n  file: {}\n", policy_path.display());
    std::fs::write(&config_path, contents).expect("write config");
    env::set_var("ZANN_CONFIG_PATH", config_path);
}

fn set_config_with_metrics(metrics_yaml: &str) {
    let policy_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policies.default.yaml");
    let config_path =
        std::env::temp_dir().join(format!("zann-test-config-{}.yaml", Uuid::new_v4()));
    let contents = format!(
        "policy:\n  file: {}\n{}\n",
        policy_path.display(),
        metrics_yaml.trim_end()
    );
    std::fs::write(&config_path, contents).expect("write config");
    env::set_var("ZANN_CONFIG_PATH", config_path);
}

fn set_config_with_tracing(tracing_yaml: &str) {
    let policy_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policies.default.yaml");
    let config_path =
        std::env::temp_dir().join(format!("zann-test-config-{}.yaml", Uuid::new_v4()));
    let contents = format!(
        "policy:\n  file: {}\n{}\n",
        policy_path.display(),
        tracing_yaml.trim_end()
    );
    std::fs::write(&config_path, contents).expect("write config");
    env::set_var("ZANN_CONFIG_PATH", config_path);
}

fn set_config_with_auth(auth_yaml: &str) {
    let policy_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policies.default.yaml");
    let config_path =
        std::env::temp_dir().join(format!("zann-test-config-{}.yaml", Uuid::new_v4()));
    let contents = format!(
        "policy:\n  file: {}\n{}\n",
        policy_path.display(),
        auth_yaml.trim_end()
    );
    std::fs::write(&config_path, contents).expect("write config");
    env::set_var("ZANN_CONFIG_PATH", config_path);
}

#[test]
fn default_auth_config_is_internal_open() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    clear_auth_env();
    clear_metrics_env();
    set_policy_config_path();

    let settings = Settings::from_env_with_options(false).expect("settings");
    assert!(matches!(settings.config.auth.mode, AuthMode::Internal));
    assert!(matches!(
        settings.config.auth.internal.registration,
        InternalRegistration::Open
    ));
    assert!(!settings.config.auth.oidc.enabled);
}

#[test]
fn auth_env_overrides_apply() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    clear_auth_env();
    clear_pepper_env();
    clear_metrics_env();
    set_policy_config_path();
    env::set_var("ZANN_AUTH_MODE", "oidc");
    env::set_var("ZANN_AUTH_INTERNAL_ENABLED", "false");
    env::set_var("ZANN_AUTH_INTERNAL_REGISTRATION", "disabled");
    env::set_var("ZANN_AUTH_OIDC_ENABLED", "true");

    let settings = Settings::from_env_with_options(false).expect("settings");
    assert!(matches!(settings.config.auth.mode, AuthMode::Oidc));
    assert!(!settings.config.auth.internal.enabled);
    assert!(matches!(
        settings.config.auth.internal.registration,
        InternalRegistration::Disabled
    ));
    assert!(settings.config.auth.oidc.enabled);
}

#[test]
fn internal_auth_requires_password_pepper() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    clear_auth_env();
    clear_pepper_env();
    clear_metrics_env();
    set_policy_config_path();
    env::set_var("ZANN_TOKEN_PEPPER", "test-token-pepper");
    env::set_var("ZANN_SMK", TEST_SMK);

    let settings = Settings::from_env_with_options(true).expect("settings");
    let missing = preflight(&settings).expect_err("preflight should fail");
    assert!(missing
        .iter()
        .any(|value| value.contains("ZANN_PASSWORD_PEPPER or ZANN_PASSWORD_PEPPER_FILE")));
}

#[test]
fn oidc_only_allows_missing_password_pepper() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    clear_auth_env();
    clear_pepper_env();
    clear_metrics_env();
    set_config_with_auth(
        r#"auth:
  mode: oidc
  internal:
    enabled: false
  oidc:
    enabled: true
"#,
    );
    env::set_var("ZANN_TOKEN_PEPPER", "test-token-pepper");
    env::set_var("ZANN_SMK", TEST_SMK);

    let settings = Settings::from_env_with_options(true).expect("settings");
    assert!(settings.password_pepper.is_empty());
    assert_eq!(settings.token_pepper, "test-token-pepper");
    assert!(preflight(&settings).is_ok());
}

#[test]
fn oidc_only_requires_token_pepper() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    clear_auth_env();
    clear_pepper_env();
    clear_metrics_env();
    set_config_with_auth(
        r#"auth:
  mode: oidc
  internal:
    enabled: false
  oidc:
    enabled: true
"#,
    );
    env::set_var("ZANN_SMK", TEST_SMK);

    let settings = Settings::from_env_with_options(true).expect("settings");
    let missing = preflight(&settings).expect_err("preflight should fail");
    assert!(missing
        .iter()
        .any(|value| value.contains("ZANN_TOKEN_PEPPER or ZANN_TOKEN_PEPPER_FILE")));
}
#[test]
fn metrics_enabled_requires_profile() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    clear_auth_env();
    clear_metrics_env();
    env::set_var("ZANN_SMK", TEST_SMK);
    set_config_with_metrics("metrics:\n  enabled: true\n");

    let settings = Settings::from_env_with_options(false).expect("settings");
    let missing = preflight(&settings).expect_err("preflight should fail");
    assert!(missing
        .iter()
        .any(|value| { value.contains("metrics.profile must be set when metrics.enabled=true") }));
}

#[test]
fn metrics_profile_prod_allowed_in_production() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    clear_auth_env();
    clear_metrics_env();
    env::set_var("ZANN_SMK", TEST_SMK);
    env::set_var("ZANN_ENV", "production");
    set_config_with_metrics("metrics:\n  enabled: true\n  profile: prod\n");

    let settings = Settings::from_env_with_options(false).expect("settings");
    assert!(preflight(&settings).is_ok());
}

#[test]
fn metrics_profile_non_prod_blocked_in_production() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    clear_auth_env();
    clear_metrics_env();
    env::set_var("ZANN_SMK", TEST_SMK);
    env::set_var("ZANN_ENV", "production");
    set_config_with_metrics("metrics:\n  enabled: true\n  profile: staging\n");

    let settings = Settings::from_env_with_options(false).expect("settings");
    let missing = preflight(&settings).expect_err("preflight should fail");
    assert!(missing
        .iter()
        .any(|value| value.contains("metrics.profile must be prod when ZANN_ENV=production")));
}

#[test]
fn metrics_profile_debug_requires_allow_flag() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    clear_auth_env();
    clear_metrics_env();
    env::set_var("ZANN_SMK", TEST_SMK);
    set_config_with_metrics("metrics:\n  enabled: true\n  profile: debug\n");

    let settings = Settings::from_env_with_options(false).expect("settings");
    let missing = preflight(&settings).expect_err("preflight should fail");
    assert!(missing.iter().any(|value| {
        value.contains("metrics.profile=debug requires ZANN_ALLOW_METRICS_DEBUG=true")
    }));
}

#[test]
fn metrics_profile_debug_allowed_with_flag() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    clear_auth_env();
    clear_metrics_env();
    env::set_var("ZANN_SMK", TEST_SMK);
    env::set_var("ZANN_ALLOW_METRICS_DEBUG", "true");
    set_config_with_metrics("metrics:\n  enabled: true\n  profile: debug\n");

    let settings = Settings::from_env_with_options(false).expect("settings");
    assert!(preflight(&settings).is_ok());
}

#[test]
fn tracing_otel_config_parses() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    clear_auth_env();
    clear_metrics_env();
    set_config_with_tracing(
        r#"tracing:
  otel:
    enabled: true
    endpoint: "http://tempo:4318"
    service_name: "zann-server"
    sampling_ratio: 0.25
"#,
    );

    let settings = Settings::from_env_with_options(false).expect("settings");
    assert!(settings.config.tracing.otel.enabled);
    assert_eq!(
        settings.config.tracing.otel.endpoint.as_deref(),
        Some("http://tempo:4318")
    );
    assert_eq!(
        settings.config.tracing.otel.service_name.as_deref(),
        Some("zann-server")
    );
    assert_eq!(settings.config.tracing.otel.sampling_ratio, Some(0.25));
}
