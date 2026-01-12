use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use chrono::Utc;
use uuid::Uuid;
use zann_core::{FieldKind, Identity};
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{ItemRepo, VaultRepo};

use crate::app::AppState;
use crate::domains::access_control::http::{vault_role_allows, VaultScope};
use crate::infra::metrics;

use super::super::helpers::{
    encrypt_rotation_candidate, fetch_rotation_row, generate_password, is_shared_server_vault,
};
use super::super::types::{ErrorResponse, RotateStartRequest, RotationCandidateResponse};
use super::super::ROTATION_STATE_ROTATING;

pub(crate) async fn rotate_start(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
    Json(req): Json<RotateStartRequest>,
) -> impl IntoResponse {
    let resource = "shared/items/rotate/start";
    let policies = state.policy_store.get();

    if identity.service_account_id.is_some() {
        metrics::forbidden_access(resource);
        return StatusCode::FORBIDDEN.into_response();
    }

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "rotation_start_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let vault_repo = VaultRepo::new(&state.db);
    let Some(vault) = vault_repo.get_by_id(item.vault_id).await.ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !is_shared_server_vault(&vault) {
        return StatusCode::NOT_FOUND.into_response();
    }

    match policies.evaluate(&identity, "rotate_start", resource) {
        crate::domains::access_control::policies::PolicyDecision::Allow => {}
        crate::domains::access_control::policies::PolicyDecision::Deny => {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
        crate::domains::access_control::policies::PolicyDecision::NoMatch => {
            match vault_role_allows(
                &state,
                &identity,
                vault.id,
                "rotate_start",
                VaultScope::Items,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => {
                    metrics::forbidden_access(resource);
                    return StatusCode::FORBIDDEN.into_response();
                }
                Err(_) => {
                    tracing::error!(event = "rotation_start_failed", "DB error");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: "db_error" }),
                    )
                        .into_response();
                }
            }
        }
    }

    let smk = match state.server_master_key.as_ref() {
        Some(value) => value.as_ref(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_key_missing",
                }),
            )
                .into_response();
        }
    };

    let rotation = match fetch_rotation_row(&state, item_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "rotation_missing",
                }),
            )
                .into_response();
        }
        Err(_) => {
            tracing::error!(event = "rotation_start_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    if rotation.state.is_some() {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "rotation_in_progress",
            }),
        )
            .into_response();
    }

    let vault_key = match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
        Ok(key) => key,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };
    let decrypted =
        match core_crypto::decrypt_payload(&vault_key, vault.id, item.id, &item.payload_enc) {
            Ok(payload) => payload,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "decrypt_failed",
                    }),
                )
                    .into_response();
            }
        };
    if !decrypted
        .fields
        .values()
        .any(|field| field.kind == FieldKind::Password)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "password_field_missing",
            }),
        )
            .into_response();
    }

    let candidate = match generate_password(req.policy.as_deref()) {
        Ok(candidate) => candidate,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_policy",
                }),
            )
                .into_response();
        }
    };
    let candidate_enc = match encrypt_rotation_candidate(smk, &vault, item.id, &candidate) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "encrypt_failed",
                }),
            )
                .into_response();
        }
    };

    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(state.config.rotation.lock_ttl_seconds);
    let recover_until =
        expires_at + chrono::Duration::seconds(state.config.rotation.stale_retention_seconds);
    let result = sqlx_core::query::query(
        r#"
        UPDATE items
        SET rotation_state = $1,
            rotation_candidate_enc = $2,
            rotation_started_at = $3,
            rotation_started_by = $4,
            rotation_expires_at = $5,
            rotation_recover_until = $6,
            rotation_aborted_reason = NULL
        WHERE id = $7
          AND rotation_state IS NULL
        "#,
    )
    .bind(ROTATION_STATE_ROTATING)
    .bind(candidate_enc)
    .bind(now)
    .bind(identity.user_id)
    .bind(expires_at)
    .bind(recover_until)
    .bind(item.id)
    .execute(&state.db)
    .await;
    match result {
        Ok(result) if result.rows_affected() > 0 => {}
        Ok(_) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "rotation_in_progress",
                }),
            )
                .into_response();
        }
        Err(_) => {
            tracing::error!(event = "rotation_start_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    }

    let response = RotationCandidateResponse {
        state: ROTATION_STATE_ROTATING.to_string(),
        candidate,
        expires_at: Some(expires_at.to_rfc3339()),
        recover_until: Some(recover_until.to_rfc3339()),
    };
    (StatusCode::OK, Json(response)).into_response()
}
