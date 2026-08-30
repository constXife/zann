use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tracing::warn;
use uuid::Uuid;
use zann_crypto::crypto::SecretKey;

use crate::config::{AuthMode, InternalRegistration, MasterKeyMode, MetricsProfile, ServerConfig};
use crate::domains::access_control::policies::PolicySet;
use crate::domains::secrets::policies::{
    default_policy, default_policy_name, PasswordPolicy, SecretPoliciesFile,
};

#[cfg(unix)]
pub(super) fn check_key_file_permissions(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("master key file not accessible ({}): {}", path, err))?;
    if !metadata.file_type().is_file() {
        return Err(format!("master key path is not a regular file ({path})"));
    }
    let mode = metadata.permissions().mode();
    let credential_directory = env::var_os("CREDENTIALS_DIRECTORY");
    if !key_permissions_are_secure(Path::new(path), mode, credential_directory.as_deref()) {
        return Err(format!(
            "master key file has insecure permissions ({}) {:o}",
            path, mode
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn key_permissions_are_secure(
    path: &Path,
    mode: u32,
    credential_directory: Option<&std::ffi::OsStr>,
) -> bool {
    if mode & 0o077 == 0 {
        return true;
    }

    mode & 0o077 == 0o040
        && credential_directory.is_some_and(|directory| path.parent() == Some(Path::new(directory)))
}

#[cfg(not(unix))]
pub(super) fn check_key_file_permissions(_path: &str) -> Result<(), String> {
    Ok(())
}

pub(super) fn load_config(path: &str) -> Result<ServerConfig, String> {
    let config_path = Path::new(path);
    if !config_path.exists() {
        if path == "config.yaml" {
            return Ok(ServerConfig::default());
        }
        return Err(format!("config file not found: {path}"));
    }

    let contents = fs::read_to_string(config_path).map_err(|err| {
        warn!(event = "config_read_failed", path, error = %err);
        format!("config read failed ({path}): {err}")
    })?;
    serde_yaml::from_str(&contents).map_err(|err| {
        warn!(event = "config_parse_failed", path, error = %err);
        format!("config parse failed ({path}): {err}")
    })
}

pub(super) fn apply_auth_env_overrides(config: &mut ServerConfig) {
    if let Ok(value) = env::var("ZANN_AUTH_MODE") {
        if let Some(mode) = parse_auth_mode(&value) {
            config.auth.mode = mode;
        } else {
            warn!(event = "config_invalid", field = "ZANN_AUTH_MODE", value = %value);
        }
    }
    if let Ok(value) = env::var("ZANN_AUTH_INTERNAL_ENABLED") {
        if let Some(enabled) = parse_bool(&value) {
            config.auth.internal.enabled = enabled;
        } else {
            warn!(
                event = "config_invalid",
                field = "ZANN_AUTH_INTERNAL_ENABLED",
                value = %value
            );
        }
    }
    if let Ok(value) = env::var("ZANN_AUTH_INTERNAL_REGISTRATION") {
        if let Some(registration) = parse_internal_registration(&value) {
            config.auth.internal.registration = registration;
        } else {
            warn!(
                event = "config_invalid",
                field = "ZANN_AUTH_INTERNAL_REGISTRATION",
                value = %value
            );
        }
    }
    if let Ok(value) = env::var("ZANN_AUTH_OIDC_ENABLED") {
        if let Some(enabled) = parse_bool(&value) {
            config.auth.oidc.enabled = enabled;
        } else {
            warn!(
                event = "config_invalid",
                field = "ZANN_AUTH_OIDC_ENABLED",
                value = %value
            );
        }
    }
}

pub(super) fn apply_tracing_env_overrides(config: &mut ServerConfig) {
    if let Ok(value) = env::var("ZANN_TRACING_OTEL_ENABLED") {
        if let Some(enabled) = parse_bool(&value) {
            config.tracing.otel.enabled = enabled;
        } else {
            warn!(
                event = "config_invalid",
                field = "ZANN_TRACING_OTEL_ENABLED",
                value = %value
            );
        }
    }
    if let Ok(value) = env::var("ZANN_TRACING_OTEL_ENDPOINT") {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            config.tracing.otel.endpoint = None;
        } else {
            config.tracing.otel.endpoint = Some(trimmed.to_string());
        }
    }
    if let Ok(value) = env::var("ZANN_TRACING_OTEL_SERVICE_NAME") {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            config.tracing.otel.service_name = None;
        } else {
            config.tracing.otel.service_name = Some(trimmed.to_string());
        }
    }
    if let Ok(value) = env::var("ZANN_TRACING_OTEL_SAMPLING_RATIO") {
        match value.trim().parse::<f64>() {
            Ok(ratio) => {
                config.tracing.otel.sampling_ratio = Some(ratio);
            }
            Err(_) => {
                warn!(
                    event = "config_invalid",
                    field = "ZANN_TRACING_OTEL_SAMPLING_RATIO",
                    value = %value
                );
            }
        }
    }
    if let Ok(value) = env::var("ZANN_TRACING_OTEL_CA_FILE") {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            config.tracing.otel.ca_file = None;
        } else {
            config.tracing.otel.ca_file = Some(trimmed.to_string());
        }
    }
    if let Ok(value) = env::var("ZANN_TRACING_OTEL_INSECURE") {
        if let Some(insecure) = parse_bool(&value) {
            config.tracing.otel.insecure = Some(insecure);
        } else {
            warn!(
                event = "config_invalid",
                field = "ZANN_TRACING_OTEL_INSECURE",
                value = %value
            );
        }
    }
}

pub(super) fn apply_metrics_env_overrides(config: &mut ServerConfig) {
    if let Ok(value) = env::var("ZANN_METRICS_ENABLED") {
        if let Some(enabled) = parse_bool(&value) {
            config.metrics.enabled = enabled;
        } else {
            warn!(
                event = "config_invalid",
                field = "ZANN_METRICS_ENABLED",
                value = %value
            );
        }
    }
    if let Ok(value) = env::var("ZANN_METRICS_ENDPOINT") {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            warn!(
                event = "config_invalid",
                field = "ZANN_METRICS_ENDPOINT",
                value = %value
            );
        } else {
            config.metrics.endpoint = trimmed.to_string();
        }
    }
    if let Ok(value) = env::var("ZANN_METRICS_PROFILE") {
        if let Some(profile) = parse_metrics_profile(&value) {
            config.metrics.profile = Some(profile);
        } else {
            warn!(
                event = "config_invalid",
                field = "ZANN_METRICS_PROFILE",
                value = %value
            );
        }
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn normalize_enum(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn parse_auth_mode(value: &str) -> Option<AuthMode> {
    match normalize_enum(value).as_str() {
        "internal" => Some(AuthMode::Internal),
        "oidc" => Some(AuthMode::Oidc),
        "hybrid" => Some(AuthMode::Hybrid),
        _ => None,
    }
}

fn parse_internal_registration(value: &str) -> Option<InternalRegistration> {
    match normalize_enum(value).as_str() {
        "open" => Some(InternalRegistration::Open),
        "disabled" => Some(InternalRegistration::Disabled),
        _ => None,
    }
}

fn parse_metrics_profile(value: &str) -> Option<MetricsProfile> {
    match normalize_enum(value).as_str() {
        "prod" | "production" => Some(MetricsProfile::Prod),
        "staging" => Some(MetricsProfile::Staging),
        "debug" => Some(MetricsProfile::Debug),
        _ => None,
    }
}

/// The base64 master key committed to `config/dev.yaml` in public git history
/// since the initial commit. Any deployment still using it provides no at-rest
/// protection for shared vaults.
const PUBLICLY_KNOWN_DEV_MASTER_KEY: &str = "/xdJ8wIDGMQFwaChfY3k7qo1GlzYgR3peAMOFg/0u9w=";

pub(super) fn is_publicly_known_master_key(key: &SecretKey) -> bool {
    let Ok(known) = parse_master_key(PUBLICLY_KNOWN_DEV_MASTER_KEY) else {
        return false;
    };
    key.as_bytes() == known.as_bytes()
}

pub(super) fn load_server_master_key(config: &ServerConfig) -> Option<SecretKey> {
    if let Ok(value) = env::var("ZANN_SMK") {
        return parse_master_key(&value).ok();
    }
    if matches!(config.server.master_key_mode, MasterKeyMode::ManualUnseal) {
        return config
            .server
            .master_key
            .as_deref()
            .and_then(|value| parse_master_key(value).ok());
    }
    if let Ok(file_path) = env::var("ZANN_SMK_FILE") {
        return load_master_key_from_file(&file_path, config);
    }
    if let Some(value) = config.server.master_key.as_deref() {
        return parse_master_key(value).ok();
    }
    if let Some(file_path) = config.server.master_key_file.clone() {
        return load_master_key_from_file(&file_path, config);
    }
    None
}

fn load_master_key_from_file(file_path: &str, config: &ServerConfig) -> Option<SecretKey> {
    let path = Path::new(file_path);
    if path.exists() {
        let value = match read_secret_file(file_path) {
            Ok(value) => value,
            Err(err) => {
                warn!(event = "master_key_read_failed", path = %file_path, error = %err);
                return None;
            }
        };
        return parse_master_key(&value).ok();
    }

    if matches!(config.server.master_key_mode, MasterKeyMode::AutoGenerate) {
        return match generate_master_key_file(path) {
            Ok(key) => Some(key),
            Err(err) => {
                warn!(event = "master_key_autogen_failed", path = %file_path, error = %err);
                None
            }
        };
    }

    None
}

pub(super) fn load_identity_key(config: &ServerConfig) -> Option<SigningKey> {
    let env_key = env::var("ZANN_IDENTITY_KEY").ok();
    if let Some(value) = env_key {
        return parse_identity_key(&value).ok();
    }
    if let Some(value) = config.server.identity_key.as_deref() {
        return parse_identity_key(value).ok();
    }

    let file_path = env::var("ZANN_IDENTITY_KEY_FILE")
        .ok()
        .or_else(|| config.server.identity_key_file.clone());
    let file_path = file_path?;

    let path = Path::new(&file_path);
    if path.exists() {
        let value = match read_secret_file(&file_path) {
            Ok(value) => value,
            Err(err) => {
                warn!(event = "identity_key_read_failed", path = %file_path, error = %err);
                return None;
            }
        };
        return parse_identity_key(&value).ok();
    }

    match generate_identity_key_file(path) {
        Ok(key) => Some(key),
        Err(err) => {
            warn!(event = "identity_key_autogen_failed", path = %file_path, error = %err);
            None
        }
    }
}

fn parse_master_key(value: &str) -> Result<SecretKey, &'static str> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|_| "invalid_master_key")?;
    if bytes.len() != 32 {
        return Err("invalid_master_key_length");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(SecretKey::from_bytes(key))
}

fn parse_identity_key(value: &str) -> Result<SigningKey, &'static str> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|_| "invalid_identity_key")?;
    if bytes.len() != 32 {
        return Err("invalid_identity_key_length");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&key))
}

pub(super) fn load_secret_env_or_file(
    var_name: &str,
    file_var_name: &str,
) -> Result<Option<String>, String> {
    if let Ok(value) = env::var(var_name) {
        return Ok(Some(value));
    }
    let Ok(path) = env::var(file_var_name) else {
        return Ok(None);
    };
    read_secret_file(&path)
        .map(Some)
        .map_err(|err| format!("{file_var_name} invalid: {err}"))
}

fn read_secret_file(path: &str) -> Result<String, String> {
    let value = fs::read_to_string(path)
        .map_err(|err| format!("secret file not accessible ({}): {}", path, err))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("secret file is empty ({})", path));
    }
    Ok(trimmed.to_string())
}

fn generate_master_key_file(path: &Path) -> Result<SecretKey, String> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "master key dir create failed ({}): {}",
                    parent.display(),
                    err
                )
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|err| {
                    format!(
                        "master key dir chmod failed ({}): {}",
                        parent.display(),
                        err
                    )
                })?;
            }
        }
    }

    let key = SecretKey::generate();
    let encoded = base64::engine::general_purpose::STANDARD.encode(key.as_bytes());
    write_secret_file_atomic(path, &encoded)?;
    Ok(key)
}

fn generate_identity_key_file(path: &Path) -> Result<SigningKey, String> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "identity key dir create failed ({}): {}",
                    parent.display(),
                    err
                )
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|err| {
                    format!(
                        "identity key dir chmod failed ({}): {}",
                        parent.display(),
                        err
                    )
                })?;
            }
        }
    }

    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let encoded = base64::engine::general_purpose::STANDARD.encode(key.to_bytes());
    write_secret_file_atomic(path, &encoded)?;
    Ok(key)
}

fn write_secret_file_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "master key path missing parent".to_string())?;
    if !parent.exists() {
        return Err(format!(
            "master key dir does not exist: {}",
            parent.display()
        ));
    }

    let tmp_name = format!(".{}.tmp", Uuid::now_v7());
    let tmp_path = parent.join(tmp_name);
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)
        .map_err(|err| {
            format!(
                "master key file create failed ({}): {}",
                tmp_path.display(),
                err
            )
        })?;

    writeln!(file, "{contents}").map_err(|err| {
        format!(
            "master key file write failed ({}): {}",
            tmp_path.display(),
            err
        )
    })?;
    file.sync_all().map_err(|err| {
        format!(
            "master key file sync failed ({}): {}",
            tmp_path.display(),
            err
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o400)).map_err(|err| {
            format!(
                "master key file chmod failed ({}): {}",
                tmp_path.display(),
                err
            )
        })?;
    }

    fs::rename(&tmp_path, path).map_err(|err| {
        format!(
            "master key file rename failed ({}): {}",
            path.display(),
            err
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
            .map_err(|err| format!("master key file chmod failed ({}): {}", path.display(), err))?;
    }

    Ok(())
}

pub(super) fn load_policies(config: &ServerConfig) -> Result<PolicySet, String> {
    let fallback_paths = [
        "/config/policies.default.yaml",
        "config/policies.default.yaml",
    ];
    let configured = config.policy.file.as_deref();
    let path = configured
        .map(str::to_string)
        .or_else(|| {
            fallback_paths
                .iter()
                .find(|candidate| Path::new(candidate).exists())
                .map(|candidate| candidate.to_string())
        })
        .ok_or_else(|| "policy file not configured".to_string())?;

    if !Path::new(&path).exists() {
        return Err(format!("policy file not found: {path}"));
    }

    let contents = fs::read_to_string(&path).map_err(|err| {
        warn!(event = "policy_read_failed", path, error = %err);
        format!("policy file read failed: {err}")
    })?;
    serde_yaml::from_str(&contents)
        .map(PolicySet::from_rules)
        .map_err(|err| {
            warn!(event = "policy_parse_failed", path, error = %err);
            format!("policy parse failed: {err}")
        })
}

pub(super) fn load_secret_policies(
    config: &ServerConfig,
) -> Result<(HashMap<String, PasswordPolicy>, String), String> {
    let mut policies = HashMap::new();
    policies.insert(default_policy_name().to_string(), default_policy());
    let mut configured_default = config.secrets.default_policy.clone();

    if let Some(path) = config.secrets.policies_file.as_deref() {
        if !Path::new(path).exists() {
            return Err(format!("secret policy file not found: {path}"));
        }
        let contents = fs::read_to_string(path).map_err(|err| {
            warn!(event = "secret_policy_read_failed", path, error = %err);
            format!("secret policy file read failed: {err}")
        })?;
        let parsed: SecretPoliciesFile = serde_yaml::from_str(&contents).map_err(|err| {
            warn!(event = "secret_policy_parse_failed", path, error = %err);
            format!("secret policy parse failed: {err}")
        })?;
        for (name, policy) in parsed.policies {
            policies.insert(name, policy);
        }
        if configured_default.is_none() {
            configured_default = parsed.default_policy;
        }
    }

    let default_name = configured_default.unwrap_or_else(|| default_policy_name().to_string());
    if !policies.contains_key(&default_name) {
        return Err(format!("secret default policy not found: {default_name}"));
    }
    for (name, policy) in &policies {
        policy
            .validate()
            .map_err(|err| format!("invalid secret policy {name}: {err}"))?;
    }

    Ok((policies, default_name))
}

#[cfg(all(test, unix))]
mod tests {
    use super::{check_key_file_permissions, key_permissions_are_secure};
    use std::ffi::OsStr;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use uuid::Uuid;

    #[test]
    fn key_permissions_allow_systemd_group_read_only_in_credential_directory() {
        let directory = OsStr::new("/run/credentials/zann-server.service");
        let credential = Path::new("/run/credentials/zann-server.service/server-master-key");

        assert!(key_permissions_are_secure(
            credential,
            0o100440,
            Some(directory)
        ));
        assert!(!key_permissions_are_secure(
            Path::new("/run/secrets/server-master-key"),
            0o100440,
            Some(directory)
        ));
        assert!(!key_permissions_are_secure(
            credential,
            0o100460,
            Some(directory)
        ));
        assert!(!key_permissions_are_secure(
            credential,
            0o100444,
            Some(directory)
        ));
        assert!(key_permissions_are_secure(credential, 0o100400, None));
    }

    #[test]
    fn key_permissions_reject_symlinks_before_following_them() {
        let path = std::env::temp_dir().join(format!("zann-key-symlink-{}", Uuid::new_v4()));
        symlink("unused-target", &path).expect("create test symlink");

        let result = check_key_file_permissions(path.to_str().expect("UTF-8 temp path"));
        std::fs::remove_file(&path).expect("remove test symlink");

        assert!(result.is_err());
    }
}
