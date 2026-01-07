mod items_create;
mod items_files;
mod items_helpers;
mod items_history;
pub(crate) mod items_models;
mod items_read;
mod items_update;

use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};

use crate::app::AppState;
use crate::domains::items::service::ItemsError;

use items_create::create_item;
use items_files::{download_item_file, upload_item_file};
use items_history::{get_item_version, list_item_versions, restore_item_version};
use items_read::{get_item, list_items};
use items_update::{delete_item, update_item};

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/vaults/:vault_id/items",
            get(list_items).post(create_item),
        )
        .route(
            "/v1/vaults/:vault_id/items/:item_id",
            get(get_item).put(update_item).delete(delete_item),
        )
        .route(
            "/v1/vaults/:vault_id/items/:item_id/file",
            get(download_item_file).post(upload_item_file),
        )
        .route(
            "/v1/vaults/:vault_id/items/:item_id/versions",
            get(list_item_versions),
        )
        .route(
            "/v1/vaults/:vault_id/items/:item_id/versions/:version",
            get(get_item_version),
        )
        .route(
            "/v1/vaults/:vault_id/items/:item_id/versions/:version/restore",
            axum::routing::post(restore_item_version),
        )
}

fn map_items_error(error: ItemsError) -> axum::response::Response {
    match error {
        ItemsError::ForbiddenNoBody => StatusCode::FORBIDDEN.into_response(),
        ItemsError::Forbidden(code) => (
            StatusCode::FORBIDDEN,
            Json(items_models::ErrorResponse { error: code }),
        )
            .into_response(),
        ItemsError::NotFound => StatusCode::NOT_FOUND.into_response(),
        ItemsError::BadRequest(code) => (
            StatusCode::BAD_REQUEST,
            Json(items_models::ErrorResponse { error: code }),
        )
            .into_response(),
        ItemsError::Conflict(code) => (
            StatusCode::CONFLICT,
            Json(items_models::ErrorResponse { error: code }),
        )
            .into_response(),
        ItemsError::PayloadTooLarge(code) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(items_models::ErrorResponse { error: code }),
        )
            .into_response(),
        ItemsError::Db => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(items_models::ErrorResponse { error: "db_error" }),
        )
            .into_response(),
        ItemsError::Internal(code) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(items_models::ErrorResponse { error: code }),
        )
            .into_response(),
    }
}
