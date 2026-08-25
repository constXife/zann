use std::io;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use zann_core::{CachePolicy, Identity, VaultKind};
use zann_db::repo::{ServiceAccountRepo, VaultRepo};

use crate::app::AppState;
use crate::domains::vaults::http::v1::ErrorResponse;
use crate::domains::vaults::service::service_account_catalog_filter;
use crate::infra::metrics;

// Current catalog consumers make one request and interpret a short page as a
// complete snapshot. Returning a partial page would therefore authorize stale
// local state. Fetch one lookahead row and fail closed until a versioned cursor
// contract is available end to end.
const MAX_COMPLETE_CATALOG: usize = 199;
const CATALOG_LOOKAHEAD_LIMIT: i64 = 200;
const MAX_CATALOG_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

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

    let filter = service_account_catalog_filter(&account.scopes.0);
    let repo = VaultRepo::new(&state.db);
    let Ok(entries) = repo
        .list_service_account_catalog(&filter, CATALOG_LOOKAHEAD_LIMIT)
        .await
    else {
        tracing::error!(event = "vaults_list_failed", "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    };
    if entries.len() > MAX_COMPLETE_CATALOG {
        return catalog_too_large();
    }

    let mut vaults = Vec::with_capacity(entries.len());
    for entry in entries {
        let (Some(slug), Some(name), Some(tags)) = (entry.slug, entry.name, entry.tags) else {
            tracing::error!(
                event = "vaults_list_failed",
                "Invalid bounded metadata in DB"
            );
            return db_error();
        };
        let Ok(cache_policy) = CachePolicy::try_from(i32::from(entry.cache_policy)) else {
            tracing::error!(event = "vaults_list_failed", "Invalid cache policy in DB");
            return db_error();
        };
        vaults.push(zann_core::api::vaults::VaultSummary {
            id: entry.id,
            slug,
            name,
            kind: VaultKind::Shared,
            cache_policy,
            tags: Some(tags.0),
        });
    }
    let body = zann_core::api::vaults::VaultListResponse { vaults };
    if serialized_len(&body).is_none_or(|len| len > MAX_CATALOG_RESPONSE_BYTES) {
        return catalog_too_large();
    }
    (axum::http::StatusCode::OK, Json(body)).into_response()
}

fn serialized_len<T: Serialize>(value: &T) -> Option<usize> {
    let mut writer = CountingWriter { written: 0 };
    serde_json::to_writer(&mut writer, value).ok()?;
    Some(writer.written)
}

struct CountingWriter {
    written: usize,
}

impl io::Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.written = self
            .written
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("catalog length overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn catalog_too_large() -> axum::response::Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(ErrorResponse {
            error: "catalog_too_large",
        }),
    )
        .into_response()
}

fn db_error() -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: "db_error" }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_budget_is_measured_without_allocating_a_second_body() {
        let body = zann_core::api::vaults::VaultListResponse { vaults: Vec::new() };
        assert_eq!(serialized_len(&body), Some(br#"{"vaults":[]}"#.len()));
    }
}
