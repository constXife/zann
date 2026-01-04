use chrono::{Duration as ChronoDuration, Utc};
use tauri::{Emitter, State};
use uuid::Uuid;

use crate::infra::config::{ensure_context, load_config, save_config};
use crate::state::{AppState, PendingLogin, PendingLoginResult, TokenEntry};
use crate::types::{ApiResponse, OidcConfigResponse, OidcDiscovery, OidcLoginStatusResponse};
use crate::util::storage_name_from_url;
use zann_db::local::{
    LocalItemRepo, LocalStorage, LocalStorageRepo, LocalVaultRepo, PendingChangeRepo,
    SyncCursorRepo,
};

pub(crate) fn empty_oidc_config() -> OidcConfigResponse {
    OidcConfigResponse {
        issuer: String::new(),
        client_id: String::new(),
        audience: None,
        scopes: Vec::new(),
    }
}

pub(crate) fn empty_oidc_discovery() -> OidcDiscovery {
    OidcDiscovery {
        authorization_endpoint: String::new(),
        device_authorization_endpoint: None,
        token_endpoint: String::new(),
    }
}

pub(crate) fn oidc_status_error(login_id: &str, message: impl Into<String>) -> OidcLoginStatusResponse {
    OidcLoginStatusResponse {
        login_id: login_id.to_string(),
        status: "error".to_string(),
        message: Some(message.into()),
        storage_id: None,
        email: None,
        old_fingerprint: None,
        new_fingerprint: None,
    }
}

pub(crate) fn oidc_status_fingerprint_changed(
    login_id: &str,
    old_fingerprint: &str,
    new_fingerprint: &str,
) -> OidcLoginStatusResponse {
    OidcLoginStatusResponse {
        login_id: login_id.to_string(),
        status: "fingerprint_changed".to_string(),
        message: Some("server fingerprint changed".to_string()),
        storage_id: None,
        email: None,
        old_fingerprint: Some(old_fingerprint.to_string()),
        new_fingerprint: Some(new_fingerprint.to_string()),
    }
}

pub(crate) fn emit_oidc_status(
    app: &tauri::AppHandle,
    payload: OidcLoginStatusResponse,
) -> Result<(), tauri::Error> {
    app.emit("oidc-login-status", payload)
}

pub(crate) fn fingerprint_change_for_context(
    state: &State<'_, AppState>,
    context_name: &str,
    new_fingerprint: &str,
) -> Option<String> {
    let config = load_config(&state.root).ok()?;
    let existing = config
        .contexts
        .get(context_name)
        .and_then(|ctx| ctx.server_fingerprint.as_deref())?;
    if existing != new_fingerprint {
        Some(existing.to_string())
    } else {
        None
    }
}

pub(crate) fn insert_pending_login(
    state: &State<'_, AppState>,
    login_id: String,
    pending: PendingLogin,
) -> Result<(), String> {
    let mut guard = state
        .pending_logins
        .lock()
        .map_err(|err| err.to_string())?;
    guard.insert(login_id, pending);
    Ok(())
}

pub(crate) fn update_pending_login_for_fingerprint(
    state: &State<'_, AppState>,
    login_id: &str,
    new_fingerprint: &str,
    result: &PendingLoginResult,
) -> Result<Option<String>, String> {
    let Some(existing) = fingerprint_change_for_context(state, "desktop", new_fingerprint) else {
        return Ok(None);
    };
    let mut guard = state
        .pending_logins
        .lock()
        .map_err(|err| err.to_string())?;
    if let Some(entry) = guard.get_mut(login_id) {
        entry.fingerprint_new = Some(new_fingerprint.to_string());
        entry.fingerprint_trusted = false;
        entry.pending_result = Some(result.clone());
    }
    Ok(Some(existing))
}

pub(crate) async fn finalize_login(
    state: &State<'_, AppState>,
    login_id: &str,
    pending: PendingLogin,
    result: PendingLoginResult,
) -> Result<ApiResponse<OidcLoginStatusResponse>, String> {
    let storage_id_string = apply_login_context(state, &pending.server_url, &result).await?;

    let mut guard = state
        .pending_logins
        .lock()
        .map_err(|err| err.to_string())?;
    guard.remove(login_id);

    Ok(ApiResponse::ok(OidcLoginStatusResponse {
        login_id: login_id.to_string(),
        status: "success".to_string(),
        message: None,
        storage_id: storage_id_string,
        email: Some(result.email),
        old_fingerprint: None,
        new_fingerprint: None,
    }))
}

pub(crate) async fn apply_login_context(
    state: &State<'_, AppState>,
    server_url: &str,
    result: &PendingLoginResult,
) -> Result<Option<String>, String> {
    let mut config = load_config(&state.root).unwrap_or_else(|_| Default::default());
    let repo = LocalStorageRepo::new(&state.pool);
    let matching_storages = repo
        .list()
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .filter(|storage| storage.server_url.as_deref() == Some(server_url))
        .collect::<Vec<_>>();
    let existing_storage_id = matching_storages.first().map(|storage| storage.id.to_string());
    let token_name = result.token_name.clone();
    let storage_id_string = {
        let context = ensure_context(&mut config, "desktop", server_url);
        if context.storage_id.is_none() {
            context.storage_id = existing_storage_id.clone();
        }
        context.addr = server_url.to_string();
        context.server_fingerprint = Some(result.info.server_fingerprint.clone());
        context.tokens.insert(
            token_name.clone(),
            TokenEntry {
                access_token: result.access_token.clone(),
                refresh_token: Some(result.refresh_token.clone()),
                access_expires_at: Some(
                    (Utc::now() + ChronoDuration::seconds(result.expires_in as i64)).to_rfc3339(),
                ),
                service_account_token: None,
            },
        );
        context.current_token = Some(token_name);
        if context.storage_id.is_none() {
            context.storage_id = Some(Uuid::now_v7().to_string());
        }
        context.storage_id.clone()
    };
    config.current_context = Some("desktop".to_string());
    config.identity = Some(crate::state::IdentityConfig {
        kdf_salt: result.prelogin.kdf_salt.clone(),
        kdf_params: result.prelogin.kdf_params.clone(),
        salt_fingerprint: Some(result.prelogin.salt_fingerprint.clone()),
        first_seen_at: None,
        email: Some(result.email.clone()),
    });
    save_config(&state.root, &config).map_err(|err| err.to_string())?;

    if let Some(storage_id) = storage_id_string.as_deref() {
        let storage_uuid = Uuid::parse_str(storage_id).map_err(|e| e.to_string())?;
        cleanup_duplicate_storages(state, server_url, storage_uuid).await;
        let name = format!("Remote ({})", storage_name_from_url(server_url));
        let storage = LocalStorage {
            id: storage_uuid,
            kind: "remote".to_string(),
            name,
            server_url: Some(server_url.to_string()),
            server_name: result.info.server_name.clone(),
            server_fingerprint: Some(result.info.server_fingerprint.clone()),
            account_subject: Some(result.email.clone()),
            personal_vaults_enabled: result.info.personal_vaults_enabled,
            auth_method: None,
        };
        repo.upsert(&storage)
            .await
            .map_err(|err| err.to_string())?;
    }
    Ok(storage_id_string)
}

async fn cleanup_duplicate_storages(
    state: &State<'_, AppState>,
    server_url: &str,
    keep_id: Uuid,
) {
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let item_repo = LocalItemRepo::new(&state.pool);
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let cursor_repo = SyncCursorRepo::new(&state.pool);
    let pending_repo = PendingChangeRepo::new(&state.pool);

    let storages = match storage_repo.list().await {
        Ok(storages) => storages,
        Err(_) => return,
    };

    for storage in storages {
        if storage.id == keep_id {
            continue;
        }
        if storage.server_url.as_deref() != Some(server_url) {
            continue;
        }
        let _ = pending_repo.delete_by_storage(storage.id).await;
        let _ = cursor_repo.delete_by_storage(&storage.id.to_string()).await;
        let _ = item_repo.delete_by_storage(storage.id).await;
        let _ = vault_repo.delete_by_storage(storage.id).await;
        let _ = storage_repo.delete(storage.id).await;

        if let Ok(mut config) = load_config(&state.root) {
            let contexts_to_remove: Vec<String> = config
                .contexts
                .iter()
                .filter(|(_, ctx)| ctx.storage_id.as_deref() == Some(&storage.id.to_string()))
                .map(|(name, _)| name.clone())
                .collect();
            for name in contexts_to_remove {
                config.contexts.remove(&name);
                if config.current_context.as_deref() == Some(&name) {
                    config.current_context = None;
                }
            }
            let _ = save_config(&state.root, &config);
        }
    }
}
