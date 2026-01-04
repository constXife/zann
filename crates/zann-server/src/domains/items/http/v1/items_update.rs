use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use uuid::Uuid;
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::items::service::{self, UpdateItemCommand};

use super::items_helpers::item_response;
use super::items_models::UpdateItemRequest;
use super::map_items_error;

pub(super) async fn update_item(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path((vault_id, item_id)): axum::extract::Path<(String, Uuid)>,
    Json(payload): Json<UpdateItemRequest>,
) -> impl IntoResponse {
    let command = UpdateItemCommand {
        path: payload.path,
        name: payload.name,
        type_id: payload.type_id,
        tags: payload.tags,
        favorite: payload.favorite,
        payload_enc: payload.payload_enc,
        payload: payload.payload,
        checksum: payload.checksum,
        version: payload.version,
        base_version: payload.base_version,
        fields_changed: payload.fields_changed,
    };
    match service::update_item(&state, &identity, &vault_id, item_id, command).await {
        Ok(item) => Json(item_response(item)).into_response(),
        Err(error) => map_items_error(error),
    }
}

#[tracing::instrument(skip(state, identity), fields(vault_id = %vault_id, item_id = %item_id))]
pub(super) async fn delete_item(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path((vault_id, item_id)): axum::extract::Path<(String, Uuid)>,
) -> impl IntoResponse {
    match service::delete_item(&state, &identity, &vault_id, item_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => map_items_error(error),
    }
}
