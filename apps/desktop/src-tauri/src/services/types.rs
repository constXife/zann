use tauri::State;

use crate::state::AppState;
use crate::types::ApiResponse;
use zann_core::SecurityProfile;

pub async fn types_list(
    state: State<'_, AppState>,
) -> Result<ApiResponse<Vec<String>>, String> {
    let mut keys = state
        .security_profiles
        .profiles()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    Ok(ApiResponse::ok(keys))
}

pub async fn types_show(
    state: State<'_, AppState>,
    type_id: String,
) -> Result<ApiResponse<SecurityProfile>, String> {
    Ok(match state.security_profiles.profile(&type_id) {
        Some(profile) => ApiResponse::ok(profile.clone()),
        None => ApiResponse::err("type_not_found", "unknown type_id"),
    })
}

pub async fn publish_list() -> Result<ApiResponse<Vec<String>>, String> {
    Ok(ApiResponse::ok(vec![]))
}

pub async fn publish_trigger() -> Result<ApiResponse<()>, String> {
    Ok(ApiResponse::err(
        "not_implemented",
        "publish trigger is not implemented yet",
    ))
}
