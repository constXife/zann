use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::items::service::{self, CreateItemCommand};

use super::items_helpers::item_response;
use super::items_models::CreateItemRequest;
use super::map_items_error;

pub(super) async fn create_item(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(vault_id): axum::extract::Path<String>,
    Json(payload): Json<CreateItemRequest>,
) -> impl IntoResponse {
    let command = CreateItemCommand {
        path: payload.path,
        type_id: payload.type_id,
        tags: payload.tags,
        favorite: payload.favorite,
        payload_enc: payload.payload_enc,
        payload: payload.payload,
        checksum: payload.checksum,
        version: payload.version,
        fields_changed: payload.fields_changed,
    };
    match service::create_item(&state, &identity, &vault_id, command).await {
        Ok(response) => match item_response(&state, &response.vault, response.item) {
            Ok(item) => (StatusCode::CREATED, Json(item)).into_response(),
            Err(error) => map_items_error(error),
        },
        Err(error) => map_items_error(error),
    }
}
