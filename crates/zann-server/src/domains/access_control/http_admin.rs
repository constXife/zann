use axum::{
    extract::State, http::StatusCode, response::IntoResponse, routing::post, Extension, Json,
    Router,
};
use schemars::JsonSchema;
use serde::Serialize;
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::access_control::policies::PolicySet;
use crate::infra::metrics;

#[derive(Serialize, JsonSchema)]
pub(crate) struct ReloadResponse {
    pub(crate) status: &'static str,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/admin/policies/reload", post(reload))
}

#[tracing::instrument(skip(state, identity))]
async fn reload(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
) -> impl IntoResponse {
    let policies = state.policy_store.get();
    if !policies.is_allowed(&identity, "write", "admin/policies/reload") {
        metrics::forbidden_access("admin/policies/reload");
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = "admin/policies/reload",
            "Access denied"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    let Some(path) = state.config.policy.file.as_deref() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "policy_file_not_configured"})),
        )
            .into_response();
    };

    let Ok(contents) = std::fs::read_to_string(path) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "policy_file_read_failed"})),
        )
            .into_response();
    };

    let Ok(rules) = serde_yaml::from_str(&contents) else {
        tracing::error!(event = "policies_reload_failed", "Invalid policy file");
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "policy_file_invalid"})),
        )
            .into_response();
    };

    state.policy_store.set(PolicySet::from_rules(rules));

    tracing::info!(event = "policies_reloaded", "Policies reloaded");
    (StatusCode::OK, Json(ReloadResponse { status: "ok" })).into_response()
}
