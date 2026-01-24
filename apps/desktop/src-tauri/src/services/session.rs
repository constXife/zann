use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use tauri::{Emitter, State};
use tauri_plugin_biometry::{AuthOptions, BiometryExt};
use rand::rngs::OsRng;
use rand::RngCore;

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
use zann_core::crypto::{decrypt_blob, encrypt_blob, EncryptedBlob, SecretKey};
use zann_core::{AppService, StorageKind, VaultKind};
use zann_db::local::{KeyWrapType, LocalItemRepo, LocalStorageRepo, LocalVaultRepo, MetadataRepo};
use zann_db::services::LocalServices;
use zann_db::local::LocalVault;
use zann_core::VaultEncryptionType;
use uuid::Uuid;

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
    let mut config = load_config(&state.root).map_err(|err| ("config_error".to_string(), err.to_string()))?;
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
    let access_token = ensure_access_token_for_context(
        &client,
        &addr,
        &context_name,
        &mut config,
        None,
    )
    .await
    .map_err(|err| ("vault_list_failed".to_string(), err))?;
    let _ = save_config(&state.root, &config);

    let headers = auth_headers(&access_token).map_err(|err| ("vault_list_failed".to_string(), err))?;
    let status = fetch_personal_status(&client, &headers, &addr)
        .await
        .map_err(|err| ("vault_list_failed".to_string(), err))?;

    if !status.personal_key_envelopes_present {
        return Ok(());
    }
    let Some(vault_id) = status.personal_vault_id.as_deref() else {
        return Err(("vault_get_failed".to_string(), "personal vault missing".to_string()));
    };

    let vault = fetch_vault_detail(&client, &headers, &addr, vault_id)
        .await
        .map_err(|err| ("vault_get_failed".to_string(), err))?;
    let vault_id = Uuid::parse_str(&vault.id)
        .map_err(|err| ("vault_get_failed".to_string(), err.to_string()))?;
    let encryption_type = VaultEncryptionType::try_from(vault.encryption_type)
        .map_err(|_| ("vault_get_failed".to_string(), "invalid vault encryption type".to_string()))?;
    let kind = VaultKind::try_from(vault.kind)
        .map_err(|_| ("vault_get_failed".to_string(), "invalid vault kind".to_string()))?;
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

pub async fn initialize_local_identity(state: State<'_, AppState>) -> Result<ApiResponse<()>, String> {
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
    let settings = load_settings(&state.root).map_err(|err| err.to_string())?;
    *state.settings.write().await = settings.clone();

    // Auto unlock disabled in bootstrap - requires manual unlock with biometrics
    let auto_unlock_error: Option<String> = None;

    Ok(BootstrapResponse {
        status: StatusResponse {
            unlocked: state.master_key.read().await.is_some(),
            db_path: crate::state::local_db_path(&state.root).display().to_string(),
        },
        settings,
        auto_unlock_error,
    })
}

pub async fn status(state: State<'_, AppState>) -> Result<StatusResponse, String> {
    Ok(StatusResponse {
        unlocked: state.master_key.read().await.is_some(),
        db_path: crate::state::local_db_path(&state.root).display().to_string(),
    })
}

pub async fn app_status(state: State<'_, AppState>) -> Result<ApiResponse<AppStatusResponse>, String> {
    let locked = state.master_key.read().await.is_none();
    let dummy_key = SecretKey::from_bytes([0u8; 32]);
    let services = LocalServices::new(&state.pool, &dummy_key);
    let status = services
        .status(locked)
        .await
        .map_err(|err| err.message)?;
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
            reason: if status.is_available { None } else { status.error_code },
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

#[allow(non_snake_case)]
pub async fn keystore_enable(
    app: tauri::AppHandle,
    requireBiometrics: bool,
) -> Result<ApiResponse<()>, String> {
    let _ = app;
    let _ = requireBiometrics;
    Ok(ApiResponse::ok(()))
}

pub async fn keystore_disable(app: tauri::AppHandle) -> Result<ApiResponse<()>, String> {
    let _ = app;
    Ok(ApiResponse::ok(()))
}

pub async fn session_unlock_with_biometrics(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    let settings = state.settings.read().await.clone();
    let Some(dwk_backup) = settings.biometry_dwk_backup.as_ref() else {
        return Ok(ApiResponse::err("keystore_not_found", "Not found"));
    };

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

    let dwk_bytes = match base64::engine::general_purpose::STANDARD.decode(dwk_backup) {
        Ok(bytes) => bytes,
        Err(err) => return Ok(ApiResponse::err("keystore_unavailable", &err.to_string())),
    };

    let dwk_arr: [u8; 32] = match dwk_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return Ok(ApiResponse::err("keystore_unavailable", "invalid dwk length")),
    };
    let dwk = SecretKey::from_bytes(dwk_arr);

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
        Err(_) => return Ok(ApiResponse::err("keystore_unavailable", "invalid master key length")),
    };
    let master_key = SecretKey::from_bytes(master_arr);

    *state.master_key.write().await = Some(std::sync::Arc::new(master_key));
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
    let (wrapped, dwk_backup) = match wrap_master_key_with_biometry(&app, master_key.as_ref()) {
        Ok(result) => result,
        Err(err) => return Ok(ApiResponse::err("keystore_unavailable", &err)),
    };
    settings.wrapped_master_key = Some(wrapped);
    settings.biometry_dwk_backup = dwk_backup;
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

fn wrap_master_key_with_biometry(
    app: &tauri::AppHandle,
    master_key: &SecretKey,
) -> Result<(String, Option<String>), String> {
    let dwk = SecretKey::generate();
    let encoded_dwk = base64::engine::general_purpose::STANDARD.encode(dwk.as_bytes());

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
    let dwk_backup = Some(encoded_dwk);

    let blob = encrypt_blob(&dwk, master_key.as_bytes(), DWK_AAD)
        .map_err(|err| err.to_string())?;

    Ok((
        base64::engine::general_purpose::STANDARD.encode(blob.to_bytes()),
        dwk_backup,
    ))
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
    if next.biometry_dwk_backup.is_none() {
        next.biometry_dwk_backup = previous.biometry_dwk_backup.clone();
    }

    if !previous.remember_unlock && settings.remember_unlock {
        let master_key = state
            .master_key
            .read()
            .await
            .clone()
            .ok_or_else(|| "vault is locked".to_string())?;
        let (wrapped, dwk_backup) = wrap_master_key_with_biometry(&app, master_key.as_ref())?;
        next.wrapped_master_key = Some(wrapped);
        next.biometry_dwk_backup = dwk_backup;
    }

    if previous.remember_unlock && !settings.remember_unlock {
        next.wrapped_master_key = None;
        next.biometry_dwk_backup = None;
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
    let identity = config.identity.ok_or_else(|| "identity not initialized".to_string())?;
    log_master_key_context("unlock", &password, &identity);
    let master_key = derive_master_key(&password, &identity).map_err(|err| err.to_string())?;
    let master_key = std::sync::Arc::new(master_key);
    *state.master_key.write().await = Some(std::sync::Arc::clone(&master_key));
    handle_master_key_change(&app, &state, master_key.as_ref()).await?;
    let mut settings = state.settings.read().await.clone();
    if settings.remember_unlock {
        if settings.wrapped_master_key.is_none() {
            match wrap_master_key_with_biometry(&app, master_key.as_ref()) {
                Ok((wrapped, dwk_backup)) => {
                    settings.wrapped_master_key = Some(wrapped);
                    settings.biometry_dwk_backup = dwk_backup;
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
                for vault in vaults.iter().filter(|vault| vault.kind == VaultKind::Shared) {
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

fn log_master_key_context(_label: &str, _password: &str, _identity: &crate::state::IdentityConfig) {}
