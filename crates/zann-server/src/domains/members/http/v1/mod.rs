use axum::{
    extract::State, http::StatusCode, response::IntoResponse, routing::get, Extension, Json, Router,
};
use schemars::JsonSchema;
use serde::Serialize;
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::access_control::http::{find_vault, vault_role_allows, VaultScope};
use crate::domains::access_control::policies::PolicyDecision;
use crate::infra::metrics;
use zann_db::repo::VaultRepo;

#[derive(Serialize, JsonSchema)]
pub(crate) struct MembersResponse {
    pub(crate) members: Vec<serde_json::Value>,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/vaults/:vault_id/members", get(list_members))
}

#[tracing::instrument(skip(state, identity), fields(vault_id = %vault_id))]
async fn list_members(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(vault_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let policies = state.policy_store.get();
    let resource = format!("vaults/{vault_id}/members");

    let vault_repo = VaultRepo::new(&state.db);
    let vault = match find_vault(&vault_repo, &vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "members_list_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "db_error" })),
            )
                .into_response();
        }
    };

    match policies.evaluate(&identity, "list", &resource) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny => {
            metrics::forbidden_access(&resource);
            tracing::warn!(
                event = "forbidden",
                action = "list",
                resource = %resource,
                "Access denied"
            );
            return StatusCode::FORBIDDEN.into_response();
        }
        PolicyDecision::NoMatch => {
            match vault_role_allows(&state, &identity, vault.id, "list", VaultScope::Members).await
            {
                Ok(true) => {}
                Ok(false) => {
                    metrics::forbidden_access(&resource);
                    tracing::warn!(
                        event = "forbidden",
                        action = "list",
                        resource = %resource,
                        "Access denied"
                    );
                    return StatusCode::FORBIDDEN.into_response();
                }
                Err(_) => {
                    tracing::error!(event = "members_list_failed", "DB error");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({ "error": "db_error" })),
                    )
                        .into_response();
                }
            }
        }
    }

    tracing::info!(event = "members_listed", "Member list returned");
    let body = MembersResponse { members: vec![] };
    (StatusCode::OK, Json(body)).into_response()
}
