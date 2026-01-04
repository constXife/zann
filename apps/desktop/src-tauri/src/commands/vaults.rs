use tauri::State;

use crate::services::vaults as vaults_service;
use crate::state::AppState;
use crate::types::{
    ApiResponse, VaultCreateRequest, VaultListRequest, VaultSummary,
};

#[tauri::command]
pub async fn vault_list(
    state: State<'_, AppState>,
    req: VaultListRequest,
) -> Result<ApiResponse<Vec<VaultSummary>>, String> {
    vaults_service::vault_list(state, req).await
}

#[tauri::command]
pub async fn vault_create(
    state: State<'_, AppState>,
    req: VaultCreateRequest,
) -> Result<ApiResponse<VaultSummary>, String> {
    vaults_service::vault_create(state, req).await
}

#[tauri::command]
pub async fn vault_reset_personal(
    state: State<'_, AppState>,
    storage_id: String,
) -> Result<ApiResponse<()>, String> {
    vaults_service::vault_reset_personal(state, storage_id).await
}
