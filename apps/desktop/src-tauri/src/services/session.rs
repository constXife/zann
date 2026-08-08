use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use tauri::{Emitter, State};
use tauri_plugin_biometry::{AuthOptions, BiometryExt};

use crate::constants::DWK_AAD;
use crate::crypto::decrypt_vault_key_with_master;
use crate::infra::auth::ensure_access_token_for_context;
use crate::infra::config::{load_config, load_settings, save_config, save_settings};
use crate::infra::http::{auth_headers, decode_json_response, ensure_success};
use crate::state::AppState;
use crate::types::{
    ApiResponse, AppStatusResponse, AutolockConfig, BootstrapResponse, DesktopSettings,
    KeystoreStatusResponse, PersonalVaultStatusResponse, StatusResponse, VaultDetailResponse,
};
use uuid::Uuid;
use zann_core::crypto::{decrypt_blob, encrypt_blob, EncryptedBlob, SecretKey};
use zann_core::VaultEncryptionType;
use zann_core::{AppService, StorageKind, VaultKind};
use zann_db::local::LocalVault;
use zann_db::local::{KeyWrapType, LocalItemRepo, LocalStorageRepo, LocalVaultRepo, MetadataRepo};
use zann_db::services::LocalServices;
use zann_keystore::{default_keystore, Keystore, KeystoreError};

fn default_local_kdf_params() -> zann_core::api::auth::KdfParams {
    zann_core::api::auth::KdfParams {
        algorithm: "argon2id".to_string(),
        iterations: 3,
        memory_kb: 65536,
        parallelism: 4,
    }
}

fn generate_kdf_salt() -> String {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    base64::engine::general_purpose::STANDARD.encode(salt)
}

async fn fetch_personal_status(
    client: &reqwest::Client,
    headers: &reqwest::header::HeaderMap,
    addr: &str,
) -> Result<PersonalVaultStatusResponse, String> {
    let url = format!("{}/v1/vaults/personal/status", addr.trim_end_matches('/'));
    let response = client
        .get(url)
        .headers(headers.clone())
        .send()
        .await
        .map_err(|err| err.to_string())?;
    let response = match ensure_success(response).await {
        Ok(response) => response,
        Err(err) => return Err(format!("vault_preflight_failed: {err}")),
    };
    decode_json_response::<PersonalVaultStatusResponse>(response).await
}

async fn fetch_vault_detail(
    client: &reqwest::Client,
    headers: &reqwest::header::HeaderMap,
    addr: &str,
    vault_id: &str,
) -> Result<VaultDetailResponse, String> {
    let url = format!("{}/v1/vaults/{}", addr.trim_end_matches('/'), vault_id);
    let response = client
        .get(url)
        .headers(headers.clone())
        .send()
        .await
        .map_err(|err| err.to_string())?;
    let response = match ensure_success(response).await {
        Ok(response) => response,
        Err(err) => return Err(format!("vault_get_failed: {err}")),
    };
    decode_json_response::<VaultDetailResponse>(response).await
}

async fn verify_remote_master_password(
    state: &State<'_, AppState>,
    master_key: &SecretKey,
) -> Result<(), (String, String)> {
    let mut config =
        load_config(&state.root).map_err(|err| ("config_error".to_string(), err.to_string()))?;
    let context_name = match config.current_context.clone() {
        Some(value) => value,
        None => return Ok(()),
    };
    let Some(context) = config.contexts.get(&context_name).cloned() else {
        return Ok(());
    };
    if context.current_token.is_none() {
        return Ok(());
    }
    let addr = context.addr.clone();
    if addr.trim().is_empty() {
        return Ok(());
    }

    let client = reqwest::Client::new();
    let access_token =
        ensure_access_token_for_context(&client, &addr, &context_name, &mut config, None)
            .await
            .map_err(|err| ("vault_list_failed".to_string(), err))?;
    let _ = save_config(&state.root, &config);

    let headers =
        auth_headers(&access_token).map_err(|err| ("vault_list_failed".to_string(), err))?;
    let status = fetch_personal_status(&client, &headers, &addr)
        .await
        .map_err(|err| ("vault_list_failed".to_string(), err))?;

    if !status.personal_key_envelopes_present {
        return Ok(());
    }
    let Some(vault_id) = status.personal_vault_id.as_deref() else {
        return Err((
            "vault_get_failed".to_string(),
            "personal vault missing".to_string(),
        ));
    };

    let vault = fetch_vault_detail(&client, &headers, &addr, vault_id)
        .await
        .map_err(|err| ("vault_get_failed".to_string(), err))?;
    let vault_id = Uuid::parse_str(&vault.id)
        .map_err(|err| ("vault_get_failed".to_string(), err.to_string()))?;
    let encryption_type = VaultEncryptionType::try_from(vault.encryption_type).map_err(|_| {
        (
            "vault_get_failed".to_string(),
            "invalid vault encryption type".to_string(),
        )
    })?;
    let kind = VaultKind::try_from(vault.kind).map_err(|_| {
        (
            "vault_get_failed".to_string(),
            "invalid vault kind".to_string(),
        )
    })?;
    if encryption_type == VaultEncryptionType::Client && kind == VaultKind::Personal {
        let local_vault = LocalVault {
            id: vault_id,
            storage_id: Uuid::nil(),
            name: vault.name.clone(),
            kind,
            is_default: false,
            vault_key_enc: vault.vault_key_enc.clone(),
            key_wrap_type: KeyWrapType::RemoteStrict,
            last_synced_at: None,
        };
        if decrypt_vault_key_with_master(master_key, &local_vault).is_err() {
            return Err((
                "master_password_invalid".to_string(),
                "invalid master password".to_string(),
            ));
        }
    }

    Ok(())
}

pub async fn initialize_local_identity(
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    let mut config = load_config(&state.root).map_err(|err| err.to_string())?;
    if config.identity.is_some() {
        return Ok(ApiResponse::ok(()));
    }
    config.identity = Some(crate::state::IdentityConfig {
        kdf_salt: generate_kdf_salt(),
        kdf_params: default_local_kdf_params(),
        salt_fingerprint: None,
        first_seen_at: None,
        email: None,
    });
    save_config(&state.root, &config).map_err(|err| err.to_string())?;
    Ok(ApiResponse::ok(()))
}

pub async fn bootstrap(state: State<'_, AppState>) -> Result<BootstrapResponse, String> {
    let mut settings = load_settings(&state.root).map_err(|err| err.to_string())?;

    // Auto unlock disabled in bootstrap - requires manual unlock with biometrics
    let auto_unlock_error =
        migrate_legacy_dwk(&state.root, &mut settings, default_keystore().as_ref());

    *state.settings.write().await = settings.clone();

    Ok(BootstrapResponse {
        status: StatusResponse {
            unlocked: state.master_key.read().await.is_some(),
            db_path: crate::state::local_db_path(&state.root)
                .display()
                .to_string(),
        },
        settings,
        auto_unlock_error,
    })
}

pub async fn status(state: State<'_, AppState>) -> Result<StatusResponse, String> {
    Ok(StatusResponse {
        unlocked: state.master_key.read().await.is_some(),
        db_path: crate::state::local_db_path(&state.root)
            .display()
            .to_string(),
    })
}

pub async fn app_status(
    state: State<'_, AppState>,
) -> Result<ApiResponse<AppStatusResponse>, String> {
    let locked = state.master_key.read().await.is_none();
    let dummy_key = SecretKey::from_bytes([0u8; 32]);
    let services = LocalServices::new(&state.pool, &dummy_key);
    let status = services.status(locked).await.map_err(|err| err.message)?;
    Ok(ApiResponse::ok(AppStatusResponse {
        initialized: status.initialized,
        locked: status.locked,
        storages_count: status.storages_count,
        has_local_vault: status.has_local_vault,
    }))
}

pub async fn session_status(
    state: State<'_, AppState>,
) -> Result<ApiResponse<StatusResponse>, String> {
    Ok(match status(state).await {
        Ok(data) => ApiResponse::ok(data),
        Err(message) => ApiResponse::err("status_error", &message),
    })
}

pub async fn session_unlock_with_password(
    app: tauri::AppHandle,
    password: String,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    Ok(match unlock(app, password, state).await {
        Ok(()) => ApiResponse::ok(()),
        Err(message) => ApiResponse::err("unlock_failed", &message),
    })
}

pub async fn initialize_master_password(
    app: tauri::AppHandle,
    password: String,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    if password.trim().is_empty() {
        return Ok(ApiResponse::err(
            "password_required",
            "password is required",
        ));
    }
    let config = load_config(&state.root).map_err(|err| err.to_string())?;
    let identity = config
        .identity
        .ok_or_else(|| "identity not initialized".to_string())?;
    log_master_key_context("initialize", &password, &identity);
    let master_key = derive_master_key(&password, &identity).map_err(|err| err.to_string())?;
    if let Err((kind, message)) = verify_remote_master_password(&state, &master_key).await {
        return Ok(ApiResponse::err(&kind, &message));
    }
    let services = LocalServices::new(&state.pool, &master_key);
    match services.initialize_master_password().await {
        Ok(()) => {
            let master_key_arc = std::sync::Arc::new(master_key);
            *state.master_key.write().await = Some(std::sync::Arc::clone(&master_key_arc));
            handle_master_key_change(&app, &state, master_key_arc.as_ref()).await?;
            Ok(ApiResponse::ok(()))
        }
        Err(err) => Ok(ApiResponse::err(&err.kind, &err.message)),
    }
}

pub async fn session_lock(state: State<'_, AppState>) -> Result<ApiResponse<()>, String> {
    *state.master_key.write().await = None;
    Ok(ApiResponse::ok(()))
}

/// Whether the platform can prompt for OS authentication at all.
fn biometrics_available(app: &tauri::AppHandle) -> bool {
    app.biometry()
        .status()
        .map(|status| status.is_available)
        .unwrap_or(false)
}

/// Prompt for OS confirmation before touching the remembered master key.
///
/// This is a UI gate, not the thing that protects the key: the DWK lives in the
/// OS keystore and is guarded by that store's own rules. Where the platform
/// cannot prompt, the gate is skipped rather than blocking the whole feature.
fn confirm_with_os_auth(
    app: &tauri::AppHandle,
    reason: &str,
    required: bool,
) -> Result<(), (String, String)> {
    if !required || !biometrics_available(app) {
        return Ok(());
    }
    app.biometry()
        .authenticate(
            reason.to_string(),
            AuthOptions {
                allow_device_credential: Some(false),
                cancel_title: Some("Cancel".to_string()),
                fallback_title: None,
                title: None,
                subtitle: None,
                confirmation_required: None,
            },
        )
        .map_err(|err| {
            let message = err.to_string();
            if message.contains("userCancel") {
                (
                    "keystore_cancelled".to_string(),
                    "User cancelled".to_string(),
                )
            } else {
                ("keystore_unavailable".to_string(), message)
            }
        })
}

fn keystore_error(err: &KeystoreError) -> (String, String) {
    let kind = match err {
        KeystoreError::Cancelled => "keystore_cancelled",
        KeystoreError::NotFound => "keystore_not_found",
        KeystoreError::Unsupported => "keystore_unsupported",
        KeystoreError::Internal { .. } => "keystore_unavailable",
    };
    (kind.to_string(), err.to_string())
}

pub async fn keystore_status(
    app: tauri::AppHandle,
) -> Result<ApiResponse<KeystoreStatusResponse>, String> {
    let status = default_keystore().status();
    Ok(ApiResponse::ok(KeystoreStatusResponse {
        supported: status.supported,
        biometrics_available: biometrics_available(&app),
        reason: status.message.or_else(|| {
            status
                .reason
                .map(|reason| format!("{reason:?}").to_ascii_lowercase())
        }),
    }))
}

/// Check that a remembered unlock can actually be stored before the settings
/// flip. Without a working keystore there is nowhere safe to put the DWK, so
/// the feature stays off rather than falling back to a file.
#[allow(non_snake_case)]
pub async fn keystore_enable(
    app: tauri::AppHandle,
    requireBiometrics: bool,
) -> Result<ApiResponse<()>, String> {
    let status = default_keystore().status();
    if !status.supported {
        let message = status
            .message
            .unwrap_or_else(|| "no OS keystore available".to_string());
        return Ok(ApiResponse::err("keystore_unavailable", &message));
    }
    // `requireBiometrics` only decides whether unlocking prompts; it cannot be
    // enforced by the current backends, so it never blocks enabling here.
    let _ = (app, requireBiometrics);
    Ok(ApiResponse::ok(()))
}

pub async fn keystore_disable(app: tauri::AppHandle) -> Result<ApiResponse<()>, String> {
    let _ = app;
    if let Err(err) = default_keystore().delete_dwk() {
        if !matches!(err, KeystoreError::NotFound | KeystoreError::Unsupported) {
            let (kind, message) = keystore_error(&err);
            return Ok(ApiResponse::err(&kind, &message));
        }
    }
    Ok(ApiResponse::ok(()))
}

pub async fn session_unlock_with_biometrics(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    let settings = state.settings.read().await.clone();
    let Some(wrapped) = settings.wrapped_master_key.as_ref() else {
        return Ok(ApiResponse::err("keystore_not_found", "No wrapped key"));
    };

    if let Err((kind, message)) =
        confirm_with_os_auth(&app, "Unlock Zann", settings.require_os_auth)
    {
        return Ok(ApiResponse::err(&kind, &message));
    }

    let dwk_bytes = match default_keystore().load_dwk() {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(ApiResponse::err("keystore_not_found", "Not found")),
        Err(err) => {
            let (kind, message) = keystore_error(&err);
            return Ok(ApiResponse::err(&kind, &message));
        }
    };

    let dwk_arr: [u8; 32] = match dwk_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return Ok(ApiResponse::err(
                "keystore_unavailable",
                "invalid dwk length",
            ))
        }
    };
    let dwk = SecretKey::from_bytes(dwk_arr);

    let encoded = match base64::engine::general_purpose::STANDARD.decode(wrapped) {
        Ok(bytes) => bytes,
        Err(err) => return Ok(ApiResponse::err("keystore_unavailable", &err.to_string())),
    };

    let blob = match EncryptedBlob::from_bytes(&encoded) {
        Ok(blob) => blob,
        Err(err) => return Ok(ApiResponse::err("keystore_unavailable", &err.to_string())),
    };

    let master_bytes = match decrypt_blob(&dwk, &blob, DWK_AAD) {
        Ok(bytes) => bytes,
        Err(err) => return Ok(ApiResponse::err("keystore_unavailable", &err.to_string())),
    };

    let master_arr: [u8; 32] = match master_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return Ok(ApiResponse::err(
                "keystore_unavailable",
                "invalid master key length",
            ))
        }
    };
    let master_key = SecretKey::from_bytes(master_arr);
    let master_key = std::sync::Arc::new(master_key);

    *state.master_key.write().await = Some(std::sync::Arc::clone(&master_key));
    handle_master_key_change(&app, &state, master_key.as_ref()).await?;
    Ok(ApiResponse::ok(()))
}

fn derive_master_key(
    password: &str,
    identity: &crate::state::IdentityConfig,
) -> Result<SecretKey, anyhow::Error> {
    if identity.kdf_params.algorithm != "argon2id" {
        anyhow::bail!("unsupported kdf algorithm");
    }
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&identity.kdf_salt)
        .map_err(|_| anyhow::anyhow!("invalid kdf salt"))?;
    let params = Params::new(
        identity.kdf_params.memory_kb,
        identity.kdf_params.iterations,
        identity.kdf_params.parallelism,
        Some(32),
    )
    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok(SecretKey::from_bytes(key))
}

pub async fn session_rebind_biometrics(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    let master_key = match state.master_key.read().await.clone() {
        Some(key) => key,
        None => return Ok(ApiResponse::err("unlock_required", "unlock required")),
    };
    let mut settings = state.settings.read().await.clone();
    if !settings.remember_unlock {
        return Ok(ApiResponse::err(
            "remember_unlock_disabled",
            "remember unlock is disabled",
        ));
    }
    let wrapped = match store_remembered_unlock(&app, master_key.as_ref(), settings.require_os_auth)
    {
        Ok(wrapped) => wrapped,
        Err((kind, message)) => return Ok(ApiResponse::err(&kind, &message)),
    };
    settings.wrapped_master_key = Some(wrapped);
    if let Err(err) = save_settings(&state.root, settings.clone()) {
        return Ok(ApiResponse::err("keystore_error", &err.to_string()));
    }
    *state.settings.write().await = settings;
    Ok(ApiResponse::ok(()))
}

pub fn system_locale() -> Result<ApiResponse<String>, String> {
    let locale = sys_locale::get_locale().unwrap_or_else(|| "en".to_string());
    Ok(ApiResponse::ok(locale))
}

/// Remember the master key on this device: the DWK goes to the OS keystore and
/// only the key it wraps is returned for storage in the settings file.
fn store_remembered_unlock(
    app: &tauri::AppHandle,
    master_key: &SecretKey,
    require_os_auth: bool,
) -> Result<String, (String, String)> {
    confirm_with_os_auth(app, "Enable unlock on this device", require_os_auth)?;

    let dwk = SecretKey::generate();
    default_keystore()
        .store_dwk(dwk.as_bytes())
        .map_err(|err| keystore_error(&err))?;

    let blob = encrypt_blob(&dwk, master_key.as_bytes(), DWK_AAD)
        .map_err(|err| ("keystore_error".to_string(), err.to_string()))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(blob.to_bytes()))
}

/// Move a pre-keystore DWK out of the settings file.
///
/// If it cannot be moved there is nowhere safe to keep it, so the remembered
/// unlock is dropped entirely — the user falls back to the master password
/// instead of the key staying on disk in the clear.
fn migrate_legacy_dwk(
    root: &std::path::Path,
    settings: &mut DesktopSettings,
    keystore: &dyn Keystore,
) -> Option<String> {
    let legacy = settings.legacy_dwk.take()?;

    let stored = base64::engine::general_purpose::STANDARD
        .decode(&legacy)
        .map_err(|err| err.to_string())
        .and_then(|bytes| keystore.store_dwk(&bytes).map_err(|err| err.to_string()));

    let error = match stored {
        Ok(()) => None,
        Err(message) => {
            settings.wrapped_master_key = None;
            settings.remember_unlock = false;
            settings.auto_unlock = false;
            Some(format!(
                "remembered unlock was reset because the system keystore is unavailable ({message})"
            ))
        }
    };

    // Saving drops `legacy_dwk`, which is never serialized.
    if let Err(err) = save_settings(root, settings.clone()) {
        eprintln!("[keystore] failed to persist dwk migration: {err}");
    }
    error
}

pub async fn session_autolock_config() -> Result<ApiResponse<AutolockConfig>, String> {
    Ok(ApiResponse::ok(AutolockConfig {
        enabled: false,
        minutes: 0,
    }))
}

pub async fn get_settings(state: State<'_, AppState>) -> Result<DesktopSettings, String> {
    Ok(state.settings.read().await.clone())
}

pub async fn update_settings(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    settings: DesktopSettings,
) -> Result<DesktopSettings, String> {
    if settings.auto_unlock && !settings.remember_unlock {
        return Err("auto unlock requires remember unlock".to_string());
    }

    let previous = state.settings.read().await.clone();
    let mut next = settings.clone();
    next.legacy_dwk = None;

    if !previous.remember_unlock && settings.remember_unlock {
        let master_key = state
            .master_key
            .read()
            .await
            .clone()
            .ok_or_else(|| "vault is locked".to_string())?;
        let wrapped = store_remembered_unlock(&app, master_key.as_ref(), next.require_os_auth)
            .map_err(|(kind, message)| format!("{kind}: {message}"))?;
        next.wrapped_master_key = Some(wrapped);
    }

    if previous.remember_unlock && !settings.remember_unlock {
        if let Err(err) = default_keystore().delete_dwk() {
            if !matches!(err, KeystoreError::NotFound | KeystoreError::Unsupported) {
                return Err(err.to_string());
            }
        }
        next.wrapped_master_key = None;
        next.auto_unlock = false;
    }

    save_settings(&state.root, next.clone()).map_err(|err| err.to_string())?;
    *state.settings.write().await = next.clone();
    Ok(next)
}

pub async fn unlock(
    app: tauri::AppHandle,
    password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if password.trim().is_empty() {
        return Err("password is required".to_string());
    }

    let config = load_config(&state.root).map_err(|err| err.to_string())?;
    let identity = config
        .identity
        .ok_or_else(|| "identity not initialized".to_string())?;
    log_master_key_context("unlock", &password, &identity);
    let master_key = derive_master_key(&password, &identity).map_err(|err| err.to_string())?;
    let master_key = std::sync::Arc::new(master_key);
    *state.master_key.write().await = Some(std::sync::Arc::clone(&master_key));
    handle_master_key_change(&app, &state, master_key.as_ref()).await?;
    let mut settings = state.settings.read().await.clone();
    if settings.remember_unlock && settings.wrapped_master_key.is_none() {
        match store_remembered_unlock(&app, master_key.as_ref(), settings.require_os_auth) {
            Ok(wrapped) => {
                settings.wrapped_master_key = Some(wrapped);
                save_settings(&state.root, settings.clone()).map_err(|err| err.to_string())?;
                *state.settings.write().await = settings;
            }
            Err((kind, message)) => return Err(format!("{kind}: {message}")),
        }
    }
    Ok(())
}

async fn handle_master_key_change(
    app: &tauri::AppHandle,
    state: &AppState,
    master_key: &SecretKey,
) -> Result<(), String> {
    let key_fp = key_fingerprint(master_key);
    let meta_repo = MetadataRepo::new(&state.pool);
    let prev_fp = meta_repo
        .get_value("master_key_fp")
        .await
        .map_err(|err| err.to_string())?;
    if prev_fp.as_deref() != Some(key_fp.as_str()) {
        if prev_fp.is_some() {
            let storage_repo = LocalStorageRepo::new(&state.pool);
            let vault_repo = LocalVaultRepo::new(&state.pool);
            let item_repo = LocalItemRepo::new(&state.pool);
            let storages = storage_repo.list().await.map_err(|err| err.to_string())?;
            for storage in storages {
                if storage.kind != StorageKind::Remote {
                    continue;
                }
                let vaults = vault_repo
                    .list_by_storage(storage.id)
                    .await
                    .map_err(|err| err.to_string())?;
                for vault in vaults
                    .iter()
                    .filter(|vault| vault.kind == VaultKind::Shared)
                {
                    let _ = item_repo
                        .delete_by_storage_vault(storage.id, vault.id)
                        .await;
                }
            }
            let _ = app.emit("shared-cache-invalidated", ());
        }
        meta_repo
            .set_value("master_key_fp", &key_fp)
            .await
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn key_fingerprint(key: &SecretKey) -> String {
    let hex = blake3::hash(key.as_bytes()).to_hex().to_string();
    hex.get(0..12).unwrap_or(&hex).to_string()
}

fn log_master_key_context(_label: &str, _password: &str, _identity: &crate::state::IdentityConfig) {
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use zann_keystore::{KeystoreStatus, KeystoreStatusReason};

    struct FakeKeystore {
        stored: Mutex<Option<Vec<u8>>>,
        fail: bool,
    }

    impl FakeKeystore {
        fn working() -> Self {
            Self {
                stored: Mutex::new(None),
                fail: false,
            }
        }

        fn broken() -> Self {
            Self {
                stored: Mutex::new(None),
                fail: true,
            }
        }
    }

    impl Keystore for FakeKeystore {
        fn status(&self) -> KeystoreStatus {
            if self.fail {
                KeystoreStatus::unsupported(KeystoreStatusReason::Unavailable)
            } else {
                KeystoreStatus {
                    supported: true,
                    biometrics_available: false,
                    reason: None,
                    message: None,
                }
            }
        }

        fn store_dwk(&self, dwk: &[u8]) -> Result<(), KeystoreError> {
            if self.fail {
                return Err(KeystoreError::Unsupported);
            }
            *self.stored.lock().unwrap() = Some(dwk.to_vec());
            Ok(())
        }

        fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
            if self.fail {
                return Err(KeystoreError::Unsupported);
            }
            Ok(self.stored.lock().unwrap().clone())
        }

        fn delete_dwk(&self) -> Result<(), KeystoreError> {
            *self.stored.lock().unwrap() = None;
            Ok(())
        }
    }

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zann-dwk-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn remembered_settings(dwk: &str) -> DesktopSettings {
        DesktopSettings {
            remember_unlock: true,
            wrapped_master_key: Some("wrapped".to_string()),
            legacy_dwk: Some(dwk.to_string()),
            ..DesktopSettings::default()
        }
    }

    #[test]
    fn migration_moves_the_legacy_dwk_into_the_keystore() {
        let root = scratch_dir("moves");
        let dwk = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
        let mut settings = remembered_settings(&dwk);
        let keystore = FakeKeystore::working();

        let error = migrate_legacy_dwk(&root, &mut settings, &keystore);

        assert!(error.is_none());
        assert_eq!(keystore.load_dwk().unwrap(), Some([3u8; 32].to_vec()));
        // The remembered unlock survives, only its key moved.
        assert!(settings.remember_unlock);
        assert_eq!(settings.wrapped_master_key.as_deref(), Some("wrapped"));
        assert!(settings.legacy_dwk.is_none());

        let written =
            std::fs::read_to_string(root.join(crate::constants::SETTINGS_FILENAME)).expect("saved");
        assert!(!written.contains("biometry_dwk_backup"));
        assert!(!written.contains(&dwk));
    }

    #[test]
    fn migration_drops_the_remembered_unlock_when_there_is_nowhere_safe_to_put_the_key() {
        let root = scratch_dir("drops");
        let dwk = base64::engine::general_purpose::STANDARD.encode([4u8; 32]);
        let mut settings = remembered_settings(&dwk);
        settings.auto_unlock = true;

        let error = migrate_legacy_dwk(&root, &mut settings, &FakeKeystore::broken());

        assert!(error.is_some());
        assert!(!settings.remember_unlock);
        assert!(!settings.auto_unlock);
        assert!(settings.wrapped_master_key.is_none());
        assert!(settings.legacy_dwk.is_none());

        let written =
            std::fs::read_to_string(root.join(crate::constants::SETTINGS_FILENAME)).expect("saved");
        assert!(!written.contains(&dwk));
    }

    #[test]
    fn migration_is_a_no_op_without_a_legacy_key() {
        let root = scratch_dir("noop");
        let mut settings = DesktopSettings {
            remember_unlock: true,
            wrapped_master_key: Some("wrapped".to_string()),
            ..DesktopSettings::default()
        };

        let error = migrate_legacy_dwk(&root, &mut settings, &FakeKeystore::working());

        assert!(error.is_none());
        assert!(settings.remember_unlock);
        assert!(!root.join(crate::constants::SETTINGS_FILENAME).exists());
    }
}
