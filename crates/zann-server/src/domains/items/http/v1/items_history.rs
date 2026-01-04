use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::items::service;

use super::items_helpers::item_response;
use super::items_models::{
    HistoryListQuery, ItemHistoryDetailResponse, ItemHistoryListResponse, ItemHistorySummary,
};
use super::map_items_error;

pub(super) async fn list_item_versions(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path((vault_id, item_id)): axum::extract::Path<(String, Uuid)>,
    Query(query): Query<HistoryListQuery>,
) -> impl IntoResponse {
    let versions =
        match service::list_item_versions(&state, &identity, &vault_id, item_id, query.limit).await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|history| ItemHistorySummary {
                    version: history.version,
                    checksum: history.checksum,
                    change_type: history.change_type.as_str().to_string(),
                    changed_by_name: history.changed_by_name,
                    changed_by_email: history.changed_by_email,
                    created_at: history.created_at.to_rfc3339(),
                })
                .collect(),
            Err(error) => return map_items_error(error),
        };

    Json(ItemHistoryListResponse { versions }).into_response()
}

#[tracing::instrument(skip(state, identity), fields(vault_id = %vault_id, item_id = %item_id, version = %version))]
pub(super) async fn get_item_version(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path((vault_id, item_id, version)): axum::extract::Path<(String, Uuid, i64)>,
) -> impl IntoResponse {
    let history =
        match service::get_item_version(&state, &identity, &vault_id, item_id, version).await {
            Ok(history) => history,
            Err(error) => return map_items_error(error),
        };

    let response = ItemHistoryDetailResponse {
        version: history.version,
        checksum: history.checksum,
        payload_enc: history.payload_enc,
        change_type: history.change_type.as_str().to_string(),
        created_at: history.created_at.to_rfc3339(),
    };
    Json(response).into_response()
}

#[tracing::instrument(skip(state, identity), fields(vault_id = %vault_id, item_id = %item_id, version = %version))]
pub(super) async fn restore_item_version(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path((vault_id, item_id, version)): axum::extract::Path<(String, Uuid, i64)>,
) -> impl IntoResponse {
    match service::restore_item_version(&state, &identity, &vault_id, item_id, version).await {
        Ok(item) => Json(item_response(item)).into_response(),
        Err(error) => map_items_error(error),
    }
}
