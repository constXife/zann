use axum::{
    routing::{get, post},
    Router,
};

use crate::app::AppState;

mod handlers;
mod helpers;
pub(crate) mod types;

const HISTORY_LIMIT: i64 = 5;
const ROTATION_STATE_ROTATING: &str = "rotating";
const ROTATION_STATE_STALE: &str = "stale";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/shared/items", get(handlers::list_shared_items))
        .route("/v1/shared/items/:item_id", get(handlers::get_shared_item))
        .route(
            "/v1/shared/items/:item_id/rotate/start",
            post(handlers::rotate_start),
        )
        .route(
            "/v1/shared/items/:item_id/rotate/status",
            get(handlers::rotate_status),
        )
        .route(
            "/v1/shared/items/:item_id/rotate/candidate",
            post(handlers::rotate_candidate),
        )
        .route(
            "/v1/shared/items/:item_id/rotate/recover",
            post(handlers::rotate_recover),
        )
        .route(
            "/v1/shared/items/:item_id/rotate/commit",
            post(handlers::rotate_commit),
        )
        .route(
            "/v1/shared/items/:item_id/rotate/abort",
            post(handlers::rotate_abort),
        )
        .route(
            "/v1/shared/items/:item_id/history",
            get(handlers::list_shared_versions),
        )
        .route(
            "/v1/shared/items/:item_id/history/:version",
            get(handlers::get_shared_version),
        )
}
