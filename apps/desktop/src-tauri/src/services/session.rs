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
use zann_keystore::default_keystore;

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

/// Strip backend-only material and derive UI hints before handing settings to
/// the webview.
fn public_settings(settings: &DesktopSettings) -> DesktopSettings {
    let mut out = settings.clone();
    out.has_biometry_key = out.wrapped_master_key.is_some();
    out.legacy_biometry_dwk_backup = None;
    out
}

/// Older builds persisted the DWK in cleartext inside `desktop.json`. Move it
/// into the OS keystore and rewrite the file so the cleartext copy is gone.
fn migrate_legacy_dwk(root: &std::path::Path, settings: &mut DesktopSettings) {
    let Some(encoded) = settings.legacy_biometry_dwk_backup.take() else {
        return;
    };

    let migrated = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .is_some_and(|key| store_dwk(&SecretKey::from_bytes(key)).is_ok());

    if !migrated {
        // The keystore is unavailable or the blob was corrupt. Drop the wrapped
        // key too: without a usable DWK it is dead weight, and the user falls
        // back to unlocking with the master password.
        settings.wrapped_master_key = None;
        settings.auto_unlock = false;
        eprintln!("[keystore] could not migrate legacy dwk; biometry unlock reset");
    }

    if let Err(err) = save_settings(root, settings.clone()) {
        eprintln!("[keystore] failed to rewrite settings after dwk migration: {err}");
    }
}

pub async fn bootstrap(state: State<'_, AppState>) -> Result<BootstrapResponse, String> {
    let mut settings = load_settings(&state.root).map_err(|err| err.to_string())?;
    migrate_legacy_dwk(&state.root, &mut settings);
    *state.settings.write().await = settings.clone();
    let settings = public_settings(&settings);

    // Auto unlock disabled in bootstrap - requires manual unlock with biometrics
    let auto_unlock_error: Option<String> = None;

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

pub async fn keystore_status(
    app: tauri::AppHandle,
) -> Result<ApiResponse<KeystoreStatusResponse>, String> {
    match app.biometry().status() {
        Ok(status) => Ok(ApiResponse::ok(KeystoreStatusResponse {
            supported: true,
            biometrics_available: status.is_available,
            reason: if status.is_available {
                None
            } else {
                status.error_code
            },
        })),
        Err(err) => {
            let message = err.to_string();
            if message.to_ascii_lowercase().contains("not supported") {
                return Ok(ApiResponse::ok(KeystoreStatusResponse {
                    supported: false,
                    biometrics_available: false,
                    reason: Some(message),
                }));
            }
            eprintln!("[biometry] status error: {:?}", err);
            Ok(ApiResponse::err("keystore_unavailable", &message))
        }
    }
}

/// Enrollment itself happens in `update_settings`, which owns the master key and
/// wraps it. This only reports whether the keystore is reachable, so the UI can
/// fail before flipping the toggle.
#[allow(non_snake_case)]
pub async fn keystore_enable(
    app: tauri::AppHandle,
    requireBiometrics: bool,
) -> Result<ApiResponse<()>, String> {
    let _ = app;
    let _ = requireBiometrics;
    match default_keystore().status() {
        Ok(status) if status.supported => Ok(ApiResponse::ok(())),
        Ok(_) => Ok(ApiResponse::err(
            "keystore_unavailable",
            "platform keystore is unavailable",
        )),
        Err(err) => Ok(ApiResponse::err("keystore_unavailable", &err.to_string())),
    }
}

pub async fn keystore_disable(app: tauri::AppHandle) -> Result<ApiResponse<()>, String> {
    let _ = app;
    clear_dwk();
    Ok(ApiResponse::ok(()))
}

pub async fn session_unlock_with_biometrics(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    let settings = state.settings.read().await.clone();
    if settings.wrapped_master_key.is_none() {
        return Ok(ApiResponse::err("keystore_not_found", "Not found"));
    }

    if let Err(auth_err) = app.biometry().authenticate(
        "Unlock Zann".to_string(),
        AuthOptions {
            allow_device_credential: Some(false),
            cancel_title: Some("Cancel".to_string()),
            fallback_title: None,
            title: None,
            subtitle: None,
            confirmation_required: None,
        },
    ) {
        let err_str = auth_err.to_string();
        if err_str.contains("userCancel") {
            return Ok(ApiResponse::err("keystore_cancelled", "User cancelled"));
        }
        return Ok(ApiResponse::err("keystore_unavailable", &err_str));
    }

    let dwk = match load_dwk() {
        Ok(Some(dwk)) => dwk,
        Ok(None) => return Ok(ApiResponse::err("keystore_not_found", "Not found")),
        Err(err) => return Ok(ApiResponse::err("keystore_unavailable", &err)),
    };

    // Decrypt master key
    let settings = state.settings.read().await.clone();
    let Some(wrapped) = settings.wrapped_master_key.as_ref() else {
        return Ok(ApiResponse::err("keystore_not_found", "No wrapped key"));
    };

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
    let wrapped = match wrap_master_key_with_biometry(&app, master_key.as_ref()) {
        Ok(result) => result,
        Err(err) => return Ok(ApiResponse::err("keystore_unavailable", &err)),
    };
    settings.wrapped_master_key = Some(wrapped);
    settings.legacy_biometry_dwk_backup = None;
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

fn store_dwk(dwk: &SecretKey) -> Result<(), String> {
    default_keystore()
        .store_dwk(dwk.as_bytes(), false)
        .map_err(|err| format!("keystore unavailable: {err}"))
}

fn load_dwk() -> Result<Option<SecretKey>, String> {
    let bytes = default_keystore()
        .load_dwk("Unlock Zann")
        .map_err(|err| format!("keystore unavailable: {err}"))?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid dwk length".to_string())?;
    Ok(Some(SecretKey::from_bytes(key)))
}

fn clear_dwk() {
    if let Err(err) = default_keystore().delete_dwk() {
        eprintln!("[keystore] failed to delete dwk: {err}");
    }
}

fn wrap_master_key_with_biometry(
    app: &tauri::AppHandle,
    master_key: &SecretKey,
) -> Result<String, String> {
    let dwk = SecretKey::generate();

    app.biometry()
        .authenticate(
            "Enable Touch ID".to_string(),
            AuthOptions {
                allow_device_credential: Some(false),
                cancel_title: Some("Cancel".to_string()),
                fallback_title: None,
                title: None,
                subtitle: None,
                confirmation_required: None,
            },
        )
        .map_err(|err| err.to_string())?;

    let blob = encrypt_blob(&dwk, master_key.as_bytes(), DWK_AAD).map_err(|err| err.to_string())?;

    // The DWK goes to the OS keystore, never to the settings file: storing it
    // alongside the blob it unwraps would make the wrapping decorative.
    store_dwk(&dwk)?;

    Ok(base64::engine::general_purpose::STANDARD.encode(blob.to_bytes()))
}

pub async fn session_autolock_config() -> Result<ApiResponse<AutolockConfig>, String> {
    Ok(ApiResponse::ok(AutolockConfig {
        enabled: false,
        minutes: 0,
    }))
}

pub async fn get_settings(state: State<'_, AppState>) -> Result<DesktopSettings, String> {
    Ok(public_settings(&*state.settings.read().await))
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
    next.legacy_biometry_dwk_backup = None;
    if next.wrapped_master_key.is_none() {
        next.wrapped_master_key = previous.wrapped_master_key.clone();
    }

    if !previous.remember_unlock && settings.remember_unlock {
        let master_key = state
            .master_key
            .read()
            .await
            .clone()
            .ok_or_else(|| "vault is locked".to_string())?;
        next.wrapped_master_key = Some(wrap_master_key_with_biometry(&app, master_key.as_ref())?);
    }

    if previous.remember_unlock && !settings.remember_unlock {
        next.wrapped_master_key = None;
        next.auto_unlock = false;
        clear_dwk();
    }

    save_settings(&state.root, next.clone()).map_err(|err| err.to_string())?;
    *state.settings.write().await = next.clone();
    Ok(public_settings(&next))
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
    if settings.remember_unlock {
        if settings.wrapped_master_key.is_none() {
            match wrap_master_key_with_biometry(&app, master_key.as_ref()) {
                Ok(wrapped) => {
                    settings.wrapped_master_key = Some(wrapped);
                    save_settings(&state.root, settings.clone()).map_err(|err| err.to_string())?;
                    *state.settings.write().await = settings;
                }
                Err(err) => {
                    return Err(err);
                }
            }
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
