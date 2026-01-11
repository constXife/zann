use std::collections::HashMap;
use std::net::SocketAddr;

use crate::config::ServerConfig;
use crate::domains::access_control::policies::PolicySet;
use crate::domains::secrets::policies::PasswordPolicy;
use ed25519_dalek::SigningKey;
use ipnet::IpNet;
use std::env;
use std::sync::Arc;
use tracing::warn;
use zann_core::crypto::SecretKey;

mod env_config;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct Settings {
    pub addr: SocketAddr,
    pub db_url: String,
    pub db_pool_max: u32,
    pub db_tx_isolation: DbTxIsolation,
    pub password_pepper: String,
    pub token_pepper: String,
    pub require_pepper: bool,
    pub server_master_key: Option<SecretKey>,
    pub identity_key: Arc<SigningKey>,
    pub access_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
    pub item_history_ttl_days: Option<i64>,
    pub item_history_ttl_interval_seconds: u64,
    pub config: ServerConfig,
    pub policies: PolicySet,
    pub secret_policies: HashMap<String, PasswordPolicy>,
    pub secret_default_policy: String,
}

#[derive(Debug, Clone, Copy)]
pub enum DbTxIsolation {
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

impl DbTxIsolation {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "read_committed" | "read committed" => Some(Self::ReadCommitted),
            "repeatable_read" | "repeatable read" => Some(Self::RepeatableRead),
            "serializable" => Some(Self::Serializable),
            _ => None,
        }
    }
}

impl Settings {
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_env_with_options(true)
    }

    #[must_use]
    pub fn from_env_with_options(require_pepper: bool) -> Self {
        let addr = match env::var("ZANN_ADDR") {
            Ok(value) => value.parse().unwrap_or_else(|_| {
                warn!(event = "config_invalid", field = "ZANN_ADDR", value = %value);
                "127.0.0.1:8080".parse().expect("default addr valid")
            }),
            Err(_) => "127.0.0.1:8080".parse().expect("default addr valid"),
        };
        let db_url = env::var("ZANN_DB_URL")
            .unwrap_or_else(|_| "postgres://zann:zann@127.0.0.1:5432/zann".to_string());
        let db_pool_max = env::var("ZANN_DB_POOL_MAX")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(10);
        let db_tx_isolation = match env::var("ZANN_DB_TX_ISOLATION") {
            Ok(value) => match DbTxIsolation::parse(&value) {
                Some(isolation) => isolation,
                None => {
                    warn!(event = "config_invalid", field = "ZANN_DB_TX_ISOLATION", value = %value);
                    DbTxIsolation::ReadCommitted
                }
            },
            Err(_) => DbTxIsolation::ReadCommitted,
        };
        let access_token_ttl_seconds = env::var("ZANN_ACCESS_TOKEN_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(3600);
        let refresh_token_ttl_seconds = env::var("ZANN_REFRESH_TOKEN_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(60 * 60 * 24 * 30);
        let item_history_ttl_days = env::var("ZANN_ITEM_HISTORY_TTL_DAYS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(|value| if value > 0 { Some(value) } else { None });
        let item_history_ttl_interval_seconds = env::var("ZANN_ITEM_HISTORY_TTL_INTERVAL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(6 * 60 * 60);
        let config_path =
            env::var("ZANN_CONFIG_PATH").unwrap_or_else(|_| "config.yaml".to_string());
        let mut config = env_config::load_config(&config_path);
        env_config::apply_auth_env_overrides(&mut config);
        env_config::apply_tracing_env_overrides(&mut config);
        env_config::apply_metrics_env_overrides(&mut config);
        let (password_pepper, token_pepper) = if require_pepper {
            let password_pepper = match env_config::load_secret_env_or_file(
                "ZANN_PASSWORD_PEPPER",
                "ZANN_PASSWORD_PEPPER_FILE",
            ) {
                Ok(Some(value)) => value,
                Ok(None) => String::new(),
                Err(err) => {
                    warn!(event = "config_invalid", field = "ZANN_PASSWORD_PEPPER", error = %err);
                    String::new()
                }
            };
            let token_pepper = match env_config::load_secret_env_or_file(
                "ZANN_TOKEN_PEPPER",
                "ZANN_TOKEN_PEPPER_FILE",
            ) {
                Ok(Some(value)) => value,
                Ok(None) if !password_pepper.is_empty() => password_pepper.clone(),
                Ok(None) => String::new(),
                Err(err) => {
                    warn!(event = "config_invalid", field = "ZANN_TOKEN_PEPPER", error = %err);
                    String::new()
                }
            };
            (password_pepper, token_pepper)
        } else {
            (String::new(), String::new())
        };
        let max_body_bytes = env::var("ZANN_MAX_BODY_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(config.server.max_body_bytes);
        let max_clock_skew_seconds = env::var("ZANN_MAX_CLOCK_SKEW_SECONDS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(config.server.max_clock_skew_seconds);
        config.server.max_body_bytes = max_body_bytes;
        config.server.max_clock_skew_seconds = max_clock_skew_seconds;
        let server_master_key = env_config::load_server_master_key(&config);
        let identity_key = match env_config::load_identity_key(&config) {
            Some(key) => Arc::new(key),
            None => {
                warn!(
                    event = "identity_key_missing",
                    "identity key missing; generating ephemeral key"
                );
                let key = SigningKey::generate(&mut rand::rngs::OsRng);
                Arc::new(key)
            }
        };
        let policies = env_config::load_policies(&config).unwrap_or_else(|err| {
            panic!("Failed to load policies: {err}");
        });
        let (secret_policies, secret_default_policy) = env_config::load_secret_policies(&config)
            .unwrap_or_else(|err| {
                panic!("Failed to load secret policies: {err}");
            });

        Self {
            addr,
            db_url,
            db_pool_max,
            db_tx_isolation,
            password_pepper,
            token_pepper,
            require_pepper,
            server_master_key,
            identity_key,
            access_token_ttl_seconds,
            refresh_token_ttl_seconds,
            item_history_ttl_days,
            item_history_ttl_interval_seconds,
            config,
            policies,
            secret_policies,
            secret_default_policy,
        }
    }
}

pub fn preflight(settings: &Settings) -> Result<(), Vec<String>> {
    let mut missing = Vec::new();
    if settings.require_pepper {
        if settings.token_pepper.is_empty() {
            missing.push(
                "ZANN_TOKEN_PEPPER or ZANN_TOKEN_PEPPER_FILE is required for token hashing and server fingerprint"
                    .to_string(),
            );
        }
        if settings.config.auth.internal.enabled
            && !matches!(settings.config.auth.mode, crate::config::AuthMode::Oidc)
            && settings.password_pepper.is_empty()
        {
            missing.push(
                "ZANN_PASSWORD_PEPPER or ZANN_PASSWORD_PEPPER_FILE is required for internal auth"
                    .to_string(),
            );
        }
        if let Err(err) =
            env_config::load_secret_env_or_file("ZANN_PASSWORD_PEPPER", "ZANN_PASSWORD_PEPPER_FILE")
        {
            missing.push(err);
        }
        if let Err(err) =
            env_config::load_secret_env_or_file("ZANN_TOKEN_PEPPER", "ZANN_TOKEN_PEPPER_FILE")
        {
            missing.push(err);
        }
    }
    if settings.server_master_key.is_none() {
        missing.push("ZANN_SMK or server.master_key/server.master_key_file".to_string());
    }
    if let Some(err) = validate_master_key_mode(settings) {
        missing.push(err);
    }
    if let Ok(path) = env::var("ZANN_SMK_FILE") {
        if std::path::Path::new(&path).exists() {
            if let Err(err) = env_config::check_key_file_permissions(&path) {
                missing.push(err);
            }
        }
    }
    if let Ok(path) = env::var("ZANN_IDENTITY_KEY_FILE") {
        if let Err(err) = env_config::check_key_file_permissions(&path) {
            missing.push(err);
        }
    }
    if let Ok(path) = env::var("ZANN_MASTER_KEY_FILE") {
        if std::path::Path::new(&path).exists() {
            if let Err(err) = env_config::check_key_file_permissions(&path) {
                missing.push(err);
            }
        }
    }
    if let Some(path) = settings.config.server.master_key_file.as_deref() {
        if std::path::Path::new(path).exists() {
            if let Err(err) = env_config::check_key_file_permissions(path) {
                missing.push(err);
            }
        }
    }
    if let Some(path) = settings.config.server.identity_key_file.as_deref() {
        if let Err(err) = env_config::check_key_file_permissions(path) {
            missing.push(err);
        }
    }
    if let Some(err) = validate_trusted_proxies(settings) {
        missing.push(err);
    }
    if let Some(err) = validate_metrics_profile(settings) {
        missing.push(err);
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

fn validate_master_key_mode(settings: &Settings) -> Option<String> {
    use crate::config::MasterKeyMode;

    let mode = &settings.config.server.master_key_mode;
    if matches!(mode, MasterKeyMode::ManualUnseal)
        && settings.config.server.master_key.is_none()
        && env::var("ZANN_SMK").is_err()
    {
        return Some("manual_unseal requires ZANN_SMK or server.master_key".to_string());
    }
    if matches!(mode, MasterKeyMode::External) {
        let has_file = settings.config.server.master_key_file.as_ref().is_some()
            || env::var("ZANN_SMK_FILE").is_ok()
            || env::var("ZANN_MASTER_KEY_FILE").is_ok();
        let has_inline =
            settings.config.server.master_key.is_some() || env::var("ZANN_SMK").is_ok();
        if !has_file && !has_inline {
            return Some("external mode requires master_key_file or ZANN_SMK_FILE".to_string());
        }
    }
    None
}

fn validate_metrics_profile(settings: &Settings) -> Option<String> {
    let metrics = &settings.config.metrics;
    if !metrics.enabled {
        return None;
    }
    let profile = metrics.effective_profile();
    if metrics.profile.is_none() {
        return Some("metrics.profile must be set when metrics.enabled=true".to_string());
    }
    if is_production_env() && profile != crate::config::MetricsProfile::Prod {
        return Some("metrics.profile must be prod when ZANN_ENV=production".to_string());
    }
    if profile == crate::config::MetricsProfile::Debug && !allow_debug_metrics() {
        return Some("metrics.profile=debug requires ZANN_ALLOW_METRICS_DEBUG=true".to_string());
    }
    None
}

fn is_production_env() -> bool {
    env::var("ZANN_ENV")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "prod" | "production"
            )
        })
        .unwrap_or(false)
}

fn allow_debug_metrics() -> bool {
    env::var("ZANN_ALLOW_METRICS_DEBUG")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn validate_trusted_proxies(settings: &Settings) -> Option<String> {
    let proxies = &settings.config.server.trusted_proxies;
    for value in proxies {
        if value.parse::<IpNet>().is_err() {
            return Some(format!("invalid trusted proxy CIDR: {value}"));
        }
    }
    None
}
