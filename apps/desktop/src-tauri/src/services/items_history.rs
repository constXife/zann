use tauri::State;
use uuid::Uuid;

use crate::state::{ensure_unlocked, AppState};
use crate::types::{
    ApiResponse, ItemHistoryDetail, ItemHistoryGetRequest, ItemHistoryListRequest,
    ItemHistoryRestoreRequest, ItemHistorySummary,
};
use zann_db::local::LocalItemHistoryRepo;
use zann_db::services::LocalServices;

pub async fn items_history_list(
    state: State<'_, AppState>,
    req: ItemHistoryListRequest,
) -> Result<ApiResponse<Vec<ItemHistorySummary>>, String> {
    Ok(match list_item_history(state, req).await {
        Ok(data) => ApiResponse::ok(data),
        Err(message) => {
            if message == "history_unavailable_shared" {
                ApiResponse::err("history_unavailable_shared", &message)
            } else {
                ApiResponse::err("history_list_failed", &message)
            }
        }
    })
}

pub async fn items_history_get(
    state: State<'_, AppState>,
    req: ItemHistoryGetRequest,
) -> Result<ApiResponse<ItemHistoryDetail>, String> {
    Ok(match get_item_history(state, req).await {
        Ok(data) => ApiResponse::ok(data),
        Err(message) => {
            if message == "history_unavailable_shared" {
                ApiResponse::err("history_unavailable_shared", &message)
            } else {
                ApiResponse::err("history_get_failed", &message)
            }
        }
    })
}

pub async fn items_history_restore(
    state: State<'_, AppState>,
    req: ItemHistoryRestoreRequest,
) -> Result<ApiResponse<()>, String> {
    Ok(match restore_item_history(state, req).await {
        Ok(()) => ApiResponse::ok(()),
        Err(message) => ApiResponse::err("history_restore_failed", &message),
    })
}

async fn list_item_history(
    state: State<'_, AppState>,
    req: ItemHistoryListRequest,
) -> Result<Vec<ItemHistorySummary>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let item_id = Uuid::parse_str(&req.item_id).map_err(|_| "invalid item id")?;
    let limit = req.limit.unwrap_or(5).clamp(1, 5);
    let repo = LocalItemHistoryRepo::new(&state.pool);
    let list = repo
        .list_by_item_limit(storage_id, item_id, limit)
        .await
        .map_err(|_| "history_list_failed")?;
    Ok(list
        .into_iter()
        .map(|entry| ItemHistorySummary {
            version: entry.version,
            checksum: entry.checksum,
            change_type: entry.change_type.as_i32(),
            changed_by_name: entry.changed_by_name,
            changed_by_email: entry.changed_by_email,
            created_at: entry.created_at.to_rfc3339(),
        })
        .collect())
}

async fn get_item_history(
    state: State<'_, AppState>,
    req: ItemHistoryGetRequest,
) -> Result<ItemHistoryDetail, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let vault_id = Uuid::parse_str(&req.vault_id).map_err(|_| "invalid vault id")?;
    let item_id = Uuid::parse_str(&req.item_id).map_err(|_| "invalid item id")?;

    let repo = LocalItemHistoryRepo::new(&state.pool);
    let entry = repo
        .get_by_item_version(storage_id, item_id, req.version)
        .await
        .map_err(|_| "history_get_failed")?
        .ok_or_else(|| "history_not_found".to_string())?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    let payload = services
        .decrypt_payload_for_item(storage_id, vault_id, item_id, &entry.payload_enc)
        .await
        .map_err(|err| err.message)?;

    Ok(ItemHistoryDetail {
        version: req.version,
        payload: serde_json::to_value(payload).map_err(|err| err.to_string())?,
    })
}

async fn restore_item_history(
    state: State<'_, AppState>,
    req: ItemHistoryRestoreRequest,
) -> Result<(), String> {
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
    services
        .restore_item_version(storage_id, item_id, req.version)
        .await
        .map_err(|err| err.message)?;
    Ok(())
}
