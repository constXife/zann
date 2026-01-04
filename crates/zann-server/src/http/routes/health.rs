use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use schemars::JsonSchema;
use serde::Serialize;

use crate::app::AppState;

#[derive(Serialize, JsonSchema)]
pub(crate) struct HealthResponse {
    pub(crate) status: &'static str,
    pub(crate) version: &'static str,
    pub(crate) build_commit: Option<&'static str>,
    pub(crate) uptime_seconds: u64,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/health", get(health))
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let version = env!("CARGO_PKG_VERSION");
    let build_commit = option_env!("GIT_COMMIT");

    if sqlx_core::query::query::<sqlx_postgres::Postgres>("SELECT 1")
        .execute(&state.db)
        .await
        .is_ok()
    {
        (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok",
                version,
                build_commit,
                uptime_seconds,
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "db_error",
                version,
                build_commit,
                uptime_seconds,
            }),
        )
    }
}
