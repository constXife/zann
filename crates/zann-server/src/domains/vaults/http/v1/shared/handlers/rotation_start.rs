use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use chrono::Utc;
use uuid::Uuid;
use zann_core::{Identity, SyncStatus};
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{ItemRepo, VaultRepo};

use crate::app::AppState;
use crate::infra::metrics;

use super::super::helpers::{
    encrypt_rotation_candidate, fetch_rotation_row, generate_rotation_candidate,
    is_shared_server_vault, rotation_action_allowed, rotation_password_field_name,
    RotationTelemetry,
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
    let mut telemetry = RotationTelemetry::new(&identity, "rotate_start", item_id);

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
    if item.sync_status != SyncStatus::Active || item.deleted_at.is_some() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let vault_repo = VaultRepo::new(&state.db);
    let Some(vault) = vault_repo.get_by_id(item.vault_id).await.ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !is_shared_server_vault(&vault) {
        return StatusCode::NOT_FOUND.into_response();
    }
    telemetry.set_target(vault.id, &item.path);

    match rotation_action_allowed(
        &state,
        &identity,
        &vault,
        "rotate_start",
        resource,
        &item.path,
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
    if let Err(error) = rotation_password_field_name(&decrypted) {
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse { error })).into_response();
    }

    let candidate = match generate_rotation_candidate(
        &state.secret_policies,
        &state.secret_default_policy,
        req.policy.as_deref(),
    ) {
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
    let candidate_enc = match encrypt_rotation_candidate(smk, &vault, item.id, candidate.as_str()) {
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
          AND sync_status = $8
          AND deleted_at IS NULL
          AND row_version = $9
        "#,
    )
    .bind(ROTATION_STATE_ROTATING)
    .bind(candidate_enc)
    .bind(now)
    .bind(identity.user_id)
    .bind(expires_at)
    .bind(recover_until)
    .bind(item.id)
    .bind(SyncStatus::ACTIVE)
    .bind(item.row_version)
    .execute(&state.db)
    .await;
    match result {
        Ok(result) if result.rows_affected() > 0 => {}
        Ok(_) => {
            let error = match fetch_rotation_row(&state, item.id).await {
                Ok(Some(row)) if row.state.is_some() => "rotation_in_progress",
                Ok(Some(_)) => "rotation_conflict",
                Ok(None) => "rotation_missing",
                Err(_) => "db_error",
            };
            let status = if error == "db_error" {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::CONFLICT
            };
            return (status, Json(ErrorResponse { error })).into_response();
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
        previous_version: item.version,
        expires_at: Some(expires_at.to_rfc3339()),
        recover_until: Some(recover_until.to_rfc3339()),
    };
    telemetry.succeed();
    (StatusCode::OK, Json(response)).into_response()
}
