use chrono::Utc;
use tauri::State;
use uuid::Uuid;

use crate::state::{ensure_unlocked, AppState};
use crate::types::{
    ApiResponse, ItemDeleteRequest, ItemDetail, ItemGetRequest, ItemPutRequest, ItemSummary,
    ItemUpdateRequest, ItemsEmptyTrashRequest, ItemsListRequest, ItemsTrashPurgeRequest,
    PendingChangesCountRequest,
};
use zann_core::{ChangeType, EncryptedPayload, ItemListParams, ItemsService, SyncStatus};
use zann_db::local::{LocalItemRepo, LocalPendingChange, LocalVaultRepo, PendingChangeRepo};
use zann_db::services::LocalServices;

pub async fn items_list(
    state: State<'_, AppState>,
    req: ItemsListRequest,
) -> Result<ApiResponse<Vec<ItemSummary>>, String> {
    Ok(match list_items(state, req.storage_id, req.vault_id, req.include_deleted).await {
        Ok(data) => ApiResponse::ok(data),
        Err(message) => ApiResponse::err("items_list_failed", &message),
    })
}

pub async fn pending_changes_count(
    state: State<'_, AppState>,
    req: PendingChangesCountRequest,
) -> Result<ApiResponse<usize>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let pending_repo = PendingChangeRepo::new(&state.pool);
    let pending = match req.vault_id {
        Some(vault_id) => {
            let vault_id = Uuid::parse_str(&vault_id).map_err(|_| "invalid vault id")?;
            pending_repo
                .list_by_storage_vault(storage_id, vault_id)
                .await
        }
        None => pending_repo.list_by_storage(storage_id).await,
    };
    Ok(match pending {
        Ok(entries) => ApiResponse::ok(entries.len()),
        Err(err) => ApiResponse::err("pending_change_failed", &err.to_string()),
    })
}

pub async fn items_get(
    state: State<'_, AppState>,
    req: ItemGetRequest,
) -> Result<ApiResponse<ItemDetail>, String> {
    Ok(match get_item(state, req.storage_id, req.item_id).await {
        Ok(data) => ApiResponse::ok(data),
        Err(message) => ApiResponse::err("item_get_failed", &message),
    })
}

pub async fn items_put(
    state: State<'_, AppState>,
    req: ItemPutRequest,
) -> Result<ApiResponse<String>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let vault_id = Uuid::parse_str(&req.vault_id).map_err(|_| "invalid vault id")?;
    let path = req.path.trim();
    if path.is_empty() {
        return Ok(ApiResponse::err("path_required", "path is required"));
    }

    let vault_repo = LocalVaultRepo::new(&state.pool);
    let _vault = match vault_repo.get_by_id(storage_id, vault_id).await {
        Ok(Some(v)) => v,
        Ok(None) => return Ok(ApiResponse::err("vault_not_found", "vault not found")),
        Err(_) => return Ok(ApiResponse::err("db_error", "failed to get vault")),
    };

    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    let payload = normalize_payload(req.payload, &req.type_id);
    match services
        .put_item(
            storage_id,
            vault_id,
            path.to_string(),
            req.type_id.clone(),
            payload,
        )
        .await
    {
        Ok(id) => Ok(ApiResponse::ok(id.to_string())),
        Err(err) => Ok(ApiResponse::err(&err.kind, &err.message)),
    }
}

pub async fn items_delete(
    state: State<'_, AppState>,
    req: ItemDeleteRequest,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let item_id = Uuid::parse_str(&req.item_id).map_err(|_| "invalid item id")?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    match services.delete_item(storage_id, item_id).await {
        Ok(()) => Ok(ApiResponse::ok(())),
        Err(err) => Ok(ApiResponse::err(&err.kind, &err.message)),
    }
}

pub async fn items_restore(
    state: State<'_, AppState>,
    req: ItemDeleteRequest,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let item_id = Uuid::parse_str(&req.item_id).map_err(|_| "invalid item id")?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    match services.restore_item(storage_id, item_id).await {
        Ok(()) => Ok(ApiResponse::ok(())),
        Err(err) => Ok(ApiResponse::err(&err.kind, &err.message)),
    }
}

pub async fn items_purge(
    state: State<'_, AppState>,
    req: ItemDeleteRequest,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let item_id = Uuid::parse_str(&req.item_id).map_err(|_| "invalid item id")?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    match services.purge_item(storage_id, item_id).await {
        Ok(()) => Ok(ApiResponse::ok(())),
        Err(err) => Ok(ApiResponse::err(&err.kind, &err.message)),
    }
}

pub async fn items_empty_trash(
    state: State<'_, AppState>,
    req: ItemsEmptyTrashRequest,
) -> Result<ApiResponse<usize>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    match services.purge_trash(storage_id, None).await {
        Ok(count) => Ok(ApiResponse::ok(count)),
        Err(err) => Ok(ApiResponse::err(&err.kind, &err.message)),
    }
}

pub async fn items_purge_trash(
    state: State<'_, AppState>,
    req: ItemsTrashPurgeRequest,
) -> Result<ApiResponse<usize>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    match services
        .purge_trash(storage_id, req.older_than_days)
        .await
    {
        Ok(count) => Ok(ApiResponse::ok(count)),
        Err(err) => Ok(ApiResponse::err(&err.kind, &err.message)),
    }
}

pub async fn items_update(
    state: State<'_, AppState>,
    req: ItemUpdateRequest,
) -> Result<ApiResponse<String>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let item_id = Uuid::parse_str(&req.item_id).map_err(|_| "invalid item id")?;
    let path = req.path.trim();
    if path.is_empty() {
        return Ok(ApiResponse::err("path_required", "path is required"));
    }

    let item_repo = LocalItemRepo::new(&state.pool);
    let item = match item_repo.get_by_id(storage_id, item_id).await {
        Ok(Some(i)) => i,
        Ok(None) => return Ok(ApiResponse::err("item_not_found", "item not found")),
        Err(_) => return Ok(ApiResponse::err("db_error", "failed to get item")),
    };

    let vault_repo = LocalVaultRepo::new(&state.pool);
    let _vault = match vault_repo.get_by_id(storage_id, item.vault_id).await {
        Ok(Some(v)) => v,
        Ok(None) => return Ok(ApiResponse::err("vault_not_found", "vault not found")),
        Err(_) => return Ok(ApiResponse::err("db_error", "failed to get vault")),
    };

    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    let payload = normalize_payload(req.payload, &req.type_id);
    match services
        .update_item_by_id(
            storage_id,
            item_id,
            path.to_string(),
            req.type_id.clone(),
            payload,
        )
        .await
    {
        Ok(id) => Ok(ApiResponse::ok(id.to_string())),
        Err(err) => Ok(ApiResponse::err(&err.kind, &err.message)),
    }
}

pub async fn items_resolve_conflict(
    state: State<'_, AppState>,
    req: ItemGetRequest,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let item_id = Uuid::parse_str(&req.item_id).map_err(|_| "invalid item id")?;

    let item_repo = LocalItemRepo::new(&state.pool);
    let mut item = match item_repo.get_by_id(storage_id, item_id).await {
        Ok(Some(i)) => i,
        Ok(None) => return Ok(ApiResponse::err("item_not_found", "item not found")),
        Err(_) => return Ok(ApiResponse::err("db_error", "failed to get item")),
    };

    let pending_repo = PendingChangeRepo::new(&state.pool);
    let _ = pending_repo.delete_by_item(storage_id, item_id).await;

    let now = Utc::now();
    item.sync_status = SyncStatus::Modified;
    item.updated_at = now;
    item_repo
        .update(&item)
        .await
        .map_err(|_| "failed to update item")?;

    let change = LocalPendingChange {
        id: Uuid::now_v7(),
        storage_id,
        vault_id: item.vault_id,
        item_id: item.id,
        operation: ChangeType::Create,
        payload_enc: Some(item.payload_enc.clone()),
        checksum: Some(item.checksum.clone()),
        path: Some(item.path.clone()),
        name: Some(item.name.clone()),
        type_id: Some(item.type_id.clone()),
        base_seq: None,
        created_at: now,
    };
    pending_repo
        .create(&change)
        .await
        .map_err(|_| "failed to create pending change")?;

    Ok(ApiResponse::ok(()))
}

async fn list_items(
    state: State<'_, AppState>,
    storage_id: String,
    vault_id: String,
    include_deleted: bool,
) -> Result<Vec<ItemSummary>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;
    let vault_id = Uuid::parse_str(&vault_id).map_err(|_| "invalid vault id")?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    let items = services
        .list_items(
            storage_id,
            vault_id,
            ItemListParams {
                include_deleted,
                ..ItemListParams::default()
            },
        )
        .await
        .map_err(|err| err.message)?
        .items;
    Ok(items
        .into_iter()
        .map(|item| ItemSummary {
            id: item.id.to_string(),
            vault_id: item.vault_id.to_string(),
            path: item.path,
            name: item.name,
            type_id: item.type_id,
            sync_status: Some(item.sync_status.as_i32()),
            updated_at: item.updated_at.to_rfc3339(),
            deleted_at: item.deleted_at.map(|value| value.to_rfc3339()),
        })
        .collect())
}

async fn get_item(
    state: State<'_, AppState>,
    storage_id: String,
    item_id: String,
) -> Result<ItemDetail, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;
    let item_id = Uuid::parse_str(&item_id).map_err(|_| "invalid item id")?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    let item = services
        .get_item(storage_id, item_id)
        .await
        .map_err(|err| err.message)?;

    Ok(ItemDetail {
        id: item.id.to_string(),
        vault_id: item.vault_id.to_string(),
        path: item.path,
        name: item.name,
        type_id: item.type_id,
        payload: serde_json::to_value(item.payload).map_err(|err| err.to_string())?,
        payload_enc: None,
    })
}

fn normalize_payload(mut payload: EncryptedPayload, type_id: &str) -> EncryptedPayload {
    payload.type_id = type_id.to_string();
    if payload.v == 0 {
        payload.v = 1;
    }
    payload
}
