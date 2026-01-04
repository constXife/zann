use axum::{extract::State, response::IntoResponse, Extension, Json};
use uuid::Uuid;
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::items::service;

use super::items_helpers::{item_response, item_summary};
use super::items_models::ItemsResponse;
use super::map_items_error;

pub(super) async fn list_items(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(vault_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let items = match service::list_items(&state, &identity, &vault_id).await {
        Ok(items) => items,
        Err(error) => return map_items_error(error),
    };

    let items = items.into_iter().map(item_summary).collect::<Vec<_>>();
    tracing::info!(
        event = "items_listed",
        count = items.len(),
        "Item list returned"
    );
    Json(ItemsResponse { items }).into_response()
}

#[tracing::instrument(skip(state, identity), fields(vault_id = %vault_id))]
pub(super) async fn get_item(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path((vault_id, item_id)): axum::extract::Path<(String, Uuid)>,
) -> impl IntoResponse {
    let item = match service::get_item(&state, &identity, &vault_id, item_id).await {
        Ok(item) => item,
        Err(error) => return map_items_error(error),
    };

    let usage_tracker = state.usage_tracker.clone();
    let user_id = identity.user_id;
    let device_id = identity.device_id;
    tokio::spawn(async move {
        usage_tracker.record_read(item_id, user_id, device_id).await;
    });

    tracing::info!(event = "item_fetched", item_id = %item_id, "Item fetched");
    Json(item_response(item)).into_response()
}
