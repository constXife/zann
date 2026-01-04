use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

use base64::Engine;
use tracing::warn;
use uuid::Uuid;
use zann_core::crypto::SecretKey;

use crate::config::{AuthMode, InternalRegistration, MasterKeyMode, ServerConfig};
use crate::domains::access_control::policies::PolicySet;
use crate::domains::secrets::policies::{
    default_policy, default_policy_name, PasswordPolicy, SecretPoliciesFile,
};

#[cfg(unix)]
pub(super) fn check_key_file_permissions(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path)
        .map_err(|err| format!("master key file not accessible ({}): {}", path, err))?;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "master key file has insecure permissions ({}) {:o}",
            path, mode
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn check_key_file_permissions(_path: &str) -> Result<(), String> {
    Ok(())
}

pub(super) fn load_config(path: &str) -> ServerConfig {
    if !Path::new(path).exists() {
        return ServerConfig::default();
    }

    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) => {
            warn!(event = "config_read_failed", path, error = %err);
            return ServerConfig::default();
        }
    };
    match serde_yaml::from_str(&contents) {
        Ok(config) => config,
        Err(err) => {
            warn!(event = "config_parse_failed", path, error = %err);
            ServerConfig::default()
        }
    }
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

pub(super) fn load_server_master_key(config: &ServerConfig) -> Option<SecretKey> {
    let mode = &config.server.master_key_mode;
    let env_key = env::var("ZANN_SMK").ok();
    if let Some(value) = env_key {
        return parse_master_key(&value).ok();
    }
    if let Some(value) = config.server.master_key.as_deref() {
        return parse_master_key(value).ok();
    }
    if matches!(mode, MasterKeyMode::ManualUnseal) {
        return None;
    }

    let file_path = env::var("ZANN_SMK_FILE")
        .ok()
        .or_else(|| env::var("ZANN_MASTER_KEY_FILE").ok())
        .or_else(|| config.server.master_key_file.clone());
    let file_path = file_path?;

    let path = Path::new(&file_path);
    if path.exists() {
        let value = match read_secret_file(&file_path) {
            Ok(value) => value,
            Err(err) => {
                warn!(event = "master_key_read_failed", path = %file_path, error = %err);
                return None;
            }
        };
        return parse_master_key(&value).ok();
    }

    if matches!(mode, MasterKeyMode::AutoGenerate) {
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
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
    }

    let key = SecretKey::generate();
    let encoded = base64::engine::general_purpose::STANDARD.encode(key.as_bytes());
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
    let _ = file.sync_all();

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
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o400));
    }

    Ok(())
}

pub(super) fn load_policies(config: &ServerConfig) -> Result<PolicySet, String> {
    let Some(path) = config.policy.file.as_deref() else {
        return Err("policy file not configured".to_string());
    };

    if !Path::new(path).exists() {
        return Err(format!("policy file not found: {path}"));
    }

    let contents = fs::read_to_string(path).map_err(|err| {
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
