use chrono::{Duration as ChronoDuration, Utc};
use tauri::{Emitter, State};
use uuid::Uuid;

use crate::infra::config::{ensure_context, load_config, save_config};
use crate::state::{AppState, PendingLogin, PendingLoginResult, TokenEntry};
use crate::types::{ApiResponse, OidcConfigResponse, OidcDiscovery, OidcLoginStatusResponse};
use crate::util::{context_name_from_url, storage_name_from_url};
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

pub(crate) fn context_name_for_server_id(
    state: &State<'_, AppState>,
    server_id: &str,
) -> Option<String> {
    let config = load_config(&state.root).ok()?;
    config
        .contexts
        .iter()
        .find(|(_, ctx)| ctx.server_id.as_deref() == Some(server_id))
        .map(|(name, _)| name.clone())
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
    server_url: &str,
    login_id: &str,
    new_fingerprint: &str,
    result: &PendingLoginResult,
) -> Result<Option<String>, String> {
    let context_name = result
        .info
        .server_id
        .as_deref()
        .and_then(|server_id| context_name_for_server_id(state, server_id))
        .unwrap_or_else(|| context_name_from_url(server_url));
    let Some(existing) =
        fingerprint_change_for_context(state, &context_name, new_fingerprint)
    else {
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
        let context_name = context_name_from_url(server_url);
        let server_id = result.info.server_id.clone();
        let migrated_storage_id = server_id
            .as_deref()
            .and_then(|server_id| migrate_context_for_server_id(&mut config, &context_name, server_id));

        let context = ensure_context(&mut config, &context_name, server_url);
        if context.storage_id.is_none() {
            context.storage_id = migrated_storage_id.or_else(|| existing_storage_id.clone());
        }
        context.addr = server_url.to_string();
        context.server_id = server_id;
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
    config.current_context = Some(context_name_from_url(server_url));
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

pub(crate) fn migrate_context_for_server_id(
    config: &mut crate::state::CliConfig,
    context_name: &str,
    server_id: &str,
) -> Option<String> {
    let Some((old_name, old_context)) = config
        .contexts
        .iter()
        .find(|(name, ctx)| {
            ctx.server_id.as_deref() == Some(server_id) && name.as_str() != context_name
        })
        .map(|(name, ctx)| (name.clone(), ctx.clone()))
    else {
        return None;
    };

    let can_replace = config
        .contexts
        .get(context_name)
        .and_then(|ctx| ctx.server_id.as_deref())
        .map(|existing_id| existing_id == server_id)
        .unwrap_or(true);

    if !can_replace {
        return None;
    }

    let storage_id = old_context.storage_id.clone();
    config.contexts.remove(&old_name);
    config.contexts.insert(context_name.to_string(), old_context);
    storage_id
}

#[cfg(test)]
mod tests {
    use super::migrate_context_for_server_id;
    use crate::state::{CliConfig, CliContext};

    #[test]
    fn migrates_context_by_server_id() {
        let mut config = CliConfig::default();
        let old_ctx = CliContext {
            addr: "https://old.example".to_string(),
            needs_salt_update: false,
            server_id: Some("server-1".to_string()),
            server_fingerprint: None,
            expected_master_key_fp: None,
            tokens: std::collections::HashMap::new(),
            current_token: None,
            storage_id: Some("storage-1".to_string()),
        };
        config
            .contexts
            .insert("https://old.example".to_string(), old_ctx.clone());

        let migrated =
            migrate_context_for_server_id(&mut config, "https://new.example", "server-1");

        assert_eq!(migrated.as_deref(), Some("storage-1"));
        assert!(config.contexts.contains_key("https://new.example"));
        assert!(!config.contexts.contains_key("https://old.example"));
    }

    #[test]
    fn skips_migration_when_context_name_conflicts() {
        let mut config = CliConfig::default();
        let old_ctx = CliContext {
            addr: "https://old.example".to_string(),
            needs_salt_update: false,
            server_id: Some("server-1".to_string()),
            server_fingerprint: None,
            expected_master_key_fp: None,
            tokens: std::collections::HashMap::new(),
            current_token: None,
            storage_id: Some("storage-1".to_string()),
        };
        let conflicting = CliContext {
            addr: "https://new.example".to_string(),
            needs_salt_update: false,
            server_id: Some("server-2".to_string()),
            server_fingerprint: None,
            expected_master_key_fp: None,
            tokens: std::collections::HashMap::new(),
            current_token: None,
            storage_id: Some("storage-2".to_string()),
        };
        config
            .contexts
            .insert("https://old.example".to_string(), old_ctx);
        config
            .contexts
            .insert("https://new.example".to_string(), conflicting);

        let migrated =
            migrate_context_for_server_id(&mut config, "https://new.example", "server-1");

        assert!(migrated.is_none());
        assert!(config.contexts.contains_key("https://old.example"));
        assert!(config.contexts.contains_key("https://new.example"));
    }
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
