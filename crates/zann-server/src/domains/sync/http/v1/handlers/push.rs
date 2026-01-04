use axum::{
    extract::{Extension, State},
    response::IntoResponse,
    Json,
};
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::sync::service;

use super::super::types::{SyncPushRequest, SyncPushResponse, SyncSharedPushRequest};
use super::map_sync_error;

pub(crate) async fn sync_push(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Json(payload): Json<SyncPushRequest>,
) -> impl IntoResponse {
    let result =
        match service::sync_push(&state, &identity, payload.vault_id, payload.changes).await {
            Ok(result) => result,
            Err(error) => return map_sync_error(error),
        };

    Json(SyncPushResponse {
        applied: result.applied,
        applied_changes: result.applied_changes,
        conflicts: result.conflicts,
        new_cursor: result.new_cursor,
    })
    .into_response()
}

#[tracing::instrument(skip(state, identity, payload))]

pub(crate) async fn sync_shared_push(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Json(payload): Json<SyncSharedPushRequest>,
) -> impl IntoResponse {
    let result =
        match service::sync_shared_push(&state, &identity, payload.vault_id, payload.changes).await
        {
            Ok(result) => result,
            Err(error) => return map_sync_error(error),
        };

    Json(SyncPushResponse {
        applied: result.applied,
        applied_changes: result.applied_changes,
        conflicts: result.conflicts,
        new_cursor: result.new_cursor,
    })
    .into_response()
}
