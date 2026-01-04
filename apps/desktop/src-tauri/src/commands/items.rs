use tauri::State;

use crate::services::items as items_service;
use crate::state::AppState;
use crate::types::{
    ApiResponse, ItemDeleteRequest, ItemDetail, ItemGetRequest, ItemPutRequest, ItemSummary,
    ItemUpdateRequest, ItemsEmptyTrashRequest, ItemsListRequest, ItemsTrashPurgeRequest,
};

#[tauri::command]
pub async fn items_list(
    state: State<'_, AppState>,
    req: ItemsListRequest,
) -> Result<ApiResponse<Vec<ItemSummary>>, String> {
    items_service::items_list(state, req).await
}

#[tauri::command]
pub async fn items_get(
    state: State<'_, AppState>,
    req: ItemGetRequest,
) -> Result<ApiResponse<ItemDetail>, String> {
    items_service::items_get(state, req).await
}

#[tauri::command]
pub async fn items_put(
    state: State<'_, AppState>,
    req: ItemPutRequest,
) -> Result<ApiResponse<String>, String> {
    items_service::items_put(state, req).await
}

#[tauri::command]
pub async fn items_delete(
    state: State<'_, AppState>,
    req: ItemDeleteRequest,
) -> Result<ApiResponse<()>, String> {
    items_service::items_delete(state, req).await
}

#[tauri::command]
pub async fn items_restore(
    state: State<'_, AppState>,
    req: ItemDeleteRequest,
) -> Result<ApiResponse<()>, String> {
    items_service::items_restore(state, req).await
}

#[tauri::command]
pub async fn items_purge(
    state: State<'_, AppState>,
    req: ItemDeleteRequest,
) -> Result<ApiResponse<()>, String> {
    items_service::items_purge(state, req).await
}

#[tauri::command]
pub async fn items_empty_trash(
    state: State<'_, AppState>,
    req: ItemsEmptyTrashRequest,
) -> Result<ApiResponse<usize>, String> {
    items_service::items_empty_trash(state, req).await
}

#[tauri::command]
pub async fn items_purge_trash(
    state: State<'_, AppState>,
    req: ItemsTrashPurgeRequest,
) -> Result<ApiResponse<usize>, String> {
    items_service::items_purge_trash(state, req).await
}

#[tauri::command]
pub async fn items_update(
    state: State<'_, AppState>,
    req: ItemUpdateRequest,
) -> Result<ApiResponse<String>, String> {
    items_service::items_update(state, req).await
}

#[tauri::command]
pub async fn items_resolve_conflict(
    state: State<'_, AppState>,
    req: ItemGetRequest,
) -> Result<ApiResponse<()>, String> {
    items_service::items_resolve_conflict(state, req).await
}
