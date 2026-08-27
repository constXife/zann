use std::time::{Duration, Instant};

use tauri::State;
use uuid::Uuid;
use zann_client::app::SessionOperation;
use zann_core::crypto::SecretKey;
use zann_core::StorageKind;
use zann_db::local::{LocalStorageRepo, SyncCursorRepo};

use crate::infra::config::load_config;
use crate::infra::sync_client::{app_client, import_from_context, sync_error_kind};
use crate::state::{ensure_unlocked, AppState};
use crate::types::ApiResponse;

pub async fn remote_sync(
    storage_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<ApiResponse<serde_json::Value>, String> {
    let master_key_arc = state.master_key.read().await.clone();
    let Some(master_key) = master_key_arc else {
        return Ok(ApiResponse::err("vault_locked", "unlock required"));
    };

    let config = load_config(&state.root).unwrap_or_else(|_| Default::default());
    let context_name = config
        .current_context
        .clone()
        .unwrap_or_else(|| "desktop".to_string());
    let Some(context) = config.contexts.get(&context_name).cloned() else {
        return Ok(ApiResponse::err("context_missing", "context not found"));
    };

    let client = match app_client(&state.root) {
        Ok(client) => client,
        Err(error) => return Ok(ApiResponse::err("configuration", &error)),
    };
    if let Err(error) = import_from_context(&client, &context_name, &context).await {
        let kind = error
            .split_once(':')
            .map(|(kind, _)| kind)
            .unwrap_or("sync_session");
        return Ok(ApiResponse::err(kind, &error));
    }

    let target = match client.configured_target(storage_id.as_deref()) {
        Ok(target) => target,
        Err(error) => {
            return Ok(ApiResponse::err(
                crate::infra::sync_client::session_error_kind(error.kind()),
                &error.to_string(),
            ));
        }
    };
    let operation = SessionOperation::new(Instant::now() + Duration::from_secs(10 * 60)).0;
    let operation_key = SecretKey::from_bytes(*master_key.as_bytes());
    match client.sync(target, operation_key, operation).await {
        Ok(outcome) => Ok(ApiResponse::ok(serde_json::json!({
            "applied": outcome.changes_committed(),
            "locked_vaults": Vec::<String>::new(),
        }))),
        Err(error) => Ok(ApiResponse::err(
            sync_error_kind(&error),
            &error.to_string(),
        )),
    }
}

pub async fn remote_reset(
    storage_id: String,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_uuid = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let Some(storage) = storage_repo
        .get(storage_uuid)
        .await
        .map_err(|err| err.to_string())?
    else {
        return Ok(ApiResponse::err("storage_not_found", "storage not found"));
    };
    if storage.kind != StorageKind::Remote {
        return Ok(ApiResponse::err(
            "not_remote",
            "reset only supported for remote storages",
        ));
    }

    let master_key_arc = state.master_key.read().await.clone();
    let Some(master_key) = master_key_arc else {
        return Ok(ApiResponse::err("vault_locked", "unlock required"));
    };
    let client = match app_client(&state.root) {
        Ok(client) => client,
        Err(error) => return Ok(ApiResponse::err("configuration", &error)),
    };
    let target = match client.configured_target(Some(storage_id.as_str())) {
        Ok(target) => target,
        Err(error) => {
            return Ok(ApiResponse::err(
                crate::infra::sync_client::session_error_kind(error.kind()),
                &error.to_string(),
            ));
        }
    };
    let operation_key = SecretKey::from_bytes(*master_key.as_bytes());
    match client.reset_sync(target, operation_key).await {
        Ok(()) => Ok(ApiResponse::ok(())),
        Err(error) => Ok(ApiResponse::err(
            sync_error_kind(&error),
            &error.to_string(),
        )),
    }
}

pub async fn sync_reset_cursor(
    storage_id: String,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_uuid = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let Some(storage) = storage_repo
        .get(storage_uuid)
        .await
        .map_err(|err| err.to_string())?
    else {
        return Ok(ApiResponse::err("storage_not_found", "storage not found"));
    };
    if storage.kind != StorageKind::Remote {
        return Ok(ApiResponse::err(
            "not_remote",
            "reset only supported for remote storages",
        ));
    }

    let cursor_repo = SyncCursorRepo::new(&state.pool);
    cursor_repo
        .delete_by_storage(storage_uuid)
        .await
        .map_err(|err| err.to_string())?;

    Ok(ApiResponse::ok(()))
}
