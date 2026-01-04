use axum::{
    extract::{Extension, State},
    response::IntoResponse,
    Json,
};
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::sync::service;

use super::super::types::{
    SyncPullRequest, SyncPullResponse, SyncSharedPullRequest, SyncSharedPullResponse,
};
use super::map_sync_error;

pub(crate) async fn sync_pull(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Json(payload): Json<SyncPullRequest>,
) -> impl IntoResponse {
    let result = match service::sync_pull(
        &state,
        &identity,
        payload.vault_id,
        payload.cursor,
        payload.limit,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => return map_sync_error(error),
    };

    Json(SyncPullResponse {
        changes: result.changes,
        next_cursor: result.next_cursor,
        has_more: result.has_more,
        push_available: result.push_available,
    })
    .into_response()
}

#[tracing::instrument(skip(state, identity, payload))]

pub(crate) async fn sync_shared_pull(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Json(payload): Json<SyncSharedPullRequest>,
) -> impl IntoResponse {
    let result = match service::sync_shared_pull(
        &state,
        &identity,
        payload.vault_id,
        payload.cursor,
        payload.limit,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => return map_sync_error(error),
    };

    Json(SyncSharedPullResponse {
        changes: result.changes,
        next_cursor: result.next_cursor,
        has_more: result.has_more,
        push_available: result.push_available,
    })
    .into_response()
}
