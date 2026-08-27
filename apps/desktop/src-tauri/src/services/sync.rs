use tauri::State;
use uuid::Uuid;
use zann_core::StorageKind;
use zann_db::local::{LocalStorageRepo, SyncCursorRepo};

use crate::infra::config::load_config;
use crate::infra::sync_client::{run_reset, run_sync};
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

    match run_sync(
        &state.root,
        &context_name,
        &context,
        storage_id.as_deref(),
        master_key.as_ref(),
    )
    .await
    {
        Ok(applied) => Ok(ApiResponse::ok(serde_json::json!({
            "applied": applied,
            "locked_vaults": Vec::<String>::new(),
        }))),
        Err(error) => Ok(ApiResponse::err(&error.kind, &error.message)),
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
    match run_reset(&state.root, storage_id.as_str(), master_key.as_ref()).await {
        Ok(()) => Ok(ApiResponse::ok(())),
        Err(error) => Ok(ApiResponse::err(&error.kind, &error.message)),
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
