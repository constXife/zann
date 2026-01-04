use tauri::State;

use crate::services::items_history as items_history_service;
use crate::state::AppState;
use crate::types::{
    ApiResponse, ItemHistoryDetail, ItemHistoryGetRequest, ItemHistoryListRequest,
    ItemHistoryRestoreRequest, ItemHistorySummary,
};

#[tauri::command]
pub async fn items_history_list(
    state: State<'_, AppState>,
    req: ItemHistoryListRequest,
) -> Result<ApiResponse<Vec<ItemHistorySummary>>, String> {
    items_history_service::items_history_list(state, req).await
}

#[tauri::command]
pub async fn items_history_get(
    state: State<'_, AppState>,
    req: ItemHistoryGetRequest,
) -> Result<ApiResponse<ItemHistoryDetail>, String> {
    items_history_service::items_history_get(state, req).await
}

#[tauri::command]
pub async fn items_history_restore(
    state: State<'_, AppState>,
    req: ItemHistoryRestoreRequest,
) -> Result<ApiResponse<()>, String> {
    items_history_service::items_history_restore(state, req).await
}
