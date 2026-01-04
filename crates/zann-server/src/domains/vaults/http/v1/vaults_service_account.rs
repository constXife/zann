use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use zann_core::{Identity, VaultEncryptionType, VaultKind};
use zann_db::repo::{ServiceAccountRepo, VaultRepo};

use crate::app::AppState;
use crate::domains::vaults::http::v1::ErrorResponse;
use crate::infra::metrics;

#[allow(clippy::cognitive_complexity)]
pub(super) async fn list_service_account_vaults(
    state: AppState,
    identity: Identity,
) -> axum::response::Response {
    let resource = "vaults/*";
    let policies = state.policy_store.get();
    if !policies.is_allowed(&identity, "list", resource) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = "list",
            resource = %resource,
            "Access denied"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    let Some(service_account_id) = identity.service_account_id else {
        return StatusCode::FORBIDDEN.into_response();
    };

    let sa_repo = ServiceAccountRepo::new(&state.db);
    let account = match sa_repo.get_by_id(service_account_id).await {
        Ok(Some(account)) => account,
        Ok(None) => return StatusCode::FORBIDDEN.into_response(),
        Err(_) => {
            tracing::error!(event = "service_account_get_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let repo = VaultRepo::new(&state.db);
    let mut vaults = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let Ok(all_vaults) = repo.list_all().await else {
        tracing::error!(event = "vaults_list_failed", "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    };
    for vault in all_vaults {
        if vault.kind != VaultKind::Shared || vault.encryption_type != VaultEncryptionType::Server {
            continue;
        }
        if !crate::domains::access_control::http::scopes_allow_vault(&account.scopes.0, &vault) {
            continue;
        }
        if !seen.insert(vault.id) {
            continue;
        }
        vaults.push(zann_core::api::vaults::VaultSummary {
            id: vault.id,
            slug: vault.slug,
            name: vault.name,
            kind: vault.kind,
            cache_policy: vault.cache_policy,
            tags: vault.tags.map(|tags| tags.0),
        });
    }

    let body = zann_core::api::vaults::VaultListResponse { vaults };
    (axum::http::StatusCode::OK, Json(body)).into_response()
}
