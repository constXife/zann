use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use chrono::Utc;
use uuid::Uuid;
use zann_core::Identity;
use zann_db::repo::{ItemRepo, VaultRepo};

use crate::app::AppState;
use crate::infra::metrics;

use super::super::helpers::{
    decrypt_rotation_candidate, fetch_rotation_row, is_shared_server_vault,
    normalize_rotation_state, rotation_abort_state_allowed, rotation_action_allowed,
    rotation_state_label, RotationTelemetry,
};
use super::super::types::{
    ErrorResponse, RotateAbortRequest, RotationCandidateResponse, RotationStatusResponse,
};
use super::super::{ROTATION_STATE_ROTATING, ROTATION_STATE_STALE};

const MAX_ROTATION_ABORT_REASON_BYTES: usize = 1024;

fn valid_rotation_abort_reason(reason: Option<&str>) -> bool {
    reason.is_none_or(|reason| {
        !reason.is_empty()
            && reason.len() <= MAX_ROTATION_ABORT_REASON_BYTES
            && reason.trim() == reason
            && !reason.chars().any(char::is_control)
    })
}

pub(crate) async fn rotate_status(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    let resource = "shared/items/rotate/status";
    let mut telemetry = RotationTelemetry::new(&identity, "rotate_status", item_id);

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "rotation_status_failed", "DB error");
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
    telemetry.set_target(vault.id, &item.path);

    match rotation_action_allowed(
        &state,
        &identity,
        &vault,
        "rotate_status",
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
            tracing::error!(event = "rotation_status_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    }

    let row = match fetch_rotation_row(&state, item.id).await {
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
            tracing::error!(event = "rotation_status_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    let row = match normalize_rotation_state(&state, item.id, row).await {
        Ok(row) => row,
        Err(_) => {
            tracing::error!(event = "rotation_status_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let response = RotationStatusResponse {
        state: rotation_state_label(&row.state),
        started_at: row.started_at.map(|value| value.to_rfc3339()),
        started_by: row.started_by.map(|value| value.to_string()),
        expires_at: row.expires_at.map(|value| value.to_rfc3339()),
        recover_until: row.recover_until.map(|value| value.to_rfc3339()),
        aborted_reason: row.aborted_reason,
    };
    telemetry.succeed();
    (StatusCode::OK, Json(response)).into_response()
}

#[tracing::instrument(skip(state, identity), fields(item_id = %item_id))]

pub(crate) async fn rotate_candidate(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    let resource = "shared/items/rotate/candidate";
    let mut telemetry = RotationTelemetry::new(&identity, "rotate_candidate", item_id);

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "rotation_candidate_failed", "DB error");
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
    telemetry.set_target(vault.id, &item.path);

    match rotation_action_allowed(
        &state,
        &identity,
        &vault,
        "read_candidate",
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
            tracing::error!(event = "rotation_candidate_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    }

    let row = match fetch_rotation_row(&state, item.id).await {
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
            tracing::error!(event = "rotation_candidate_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    let row = match normalize_rotation_state(&state, item.id, row).await {
        Ok(row) => row,
        Err(_) => {
            tracing::error!(event = "rotation_candidate_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    if row.state.as_deref() != Some(ROTATION_STATE_ROTATING) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "rotation_not_active",
            }),
        )
            .into_response();
    }
    let candidate_enc = match row.candidate_enc {
        Some(value) => value,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "rotation_missing",
                }),
            )
                .into_response();
        }
    };

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
    let candidate = match decrypt_rotation_candidate(smk, &vault, item.id, &candidate_enc) {
        Ok(value) => value,
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

    let response = RotationCandidateResponse {
        state: ROTATION_STATE_ROTATING.to_string(),
        candidate,
        previous_version: item.version,
        expires_at: row.expires_at.map(|value| value.to_rfc3339()),
        recover_until: row.recover_until.map(|value| value.to_rfc3339()),
    };
    telemetry.succeed();
    (StatusCode::OK, Json(response)).into_response()
}

#[tracing::instrument(skip(state, identity), fields(item_id = %item_id))]

pub(crate) async fn rotate_recover(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    let resource = "shared/items/rotate/recover";
    let mut telemetry = RotationTelemetry::new(&identity, "rotate_recover", item_id);

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "rotation_recover_failed", "DB error");
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
    telemetry.set_target(vault.id, &item.path);

    match rotation_action_allowed(&state, &identity, &vault, "recover", resource, &item.path).await
    {
        Ok(true) => {}
        Ok(false) => {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
        Err(_) => {
            tracing::error!(event = "rotation_recover_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    }

    let row = match fetch_rotation_row(&state, item.id).await {
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
            tracing::error!(event = "rotation_recover_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    let row = match normalize_rotation_state(&state, item.id, row).await {
        Ok(row) => row,
        Err(_) => {
            tracing::error!(event = "rotation_recover_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    if row.state.as_deref() == Some(ROTATION_STATE_ROTATING) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "rotation_active",
            }),
        )
            .into_response();
    }
    if row.state.as_deref() != Some(ROTATION_STATE_STALE) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "rotation_missing",
            }),
        )
            .into_response();
    }
    if row.recover_until.is_some_and(|value| Utc::now() > value) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "rotation_expired",
            }),
        )
            .into_response();
    }

    let candidate_enc = match row.candidate_enc {
        Some(value) => value,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "rotation_missing",
                }),
            )
                .into_response();
        }
    };
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
    let candidate = match decrypt_rotation_candidate(smk, &vault, item.id, &candidate_enc) {
        Ok(value) => value,
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

    let response = RotationCandidateResponse {
        state: ROTATION_STATE_STALE.to_string(),
        candidate,
        previous_version: item.version,
        expires_at: row.expires_at.map(|value| value.to_rfc3339()),
        recover_until: row.recover_until.map(|value| value.to_rfc3339()),
    };
    telemetry.succeed();
    (StatusCode::OK, Json(response)).into_response()
}

#[tracing::instrument(skip(state, identity), fields(item_id = %item_id))]

pub(crate) async fn rotate_abort(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
    Json(payload): Json<RotateAbortRequest>,
) -> impl IntoResponse {
    let resource = "shared/items/rotate/abort";
    let mut telemetry = RotationTelemetry::new(&identity, "rotate_abort", item_id);

    if !valid_rotation_abort_reason(payload.reason.as_deref()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_abort_reason",
            }),
        )
            .into_response();
    }

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "rotation_abort_failed", "DB error");
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
    telemetry.set_target(vault.id, &item.path);

    let action = if payload.force {
        "rotate_abort_force"
    } else {
        "rotate_abort"
    };

    match rotation_action_allowed(&state, &identity, &vault, action, resource, &item.path).await {
        Ok(true) => {}
        Ok(false) => {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
        Err(_) => {
            tracing::error!(event = "rotation_abort_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    }

    let row = match fetch_rotation_row(&state, item.id).await {
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
            tracing::error!(event = "rotation_abort_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    let row = match normalize_rotation_state(&state, item.id, row).await {
        Ok(row) => row,
        Err(_) => {
            tracing::error!(event = "rotation_abort_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    if row.state.is_none() {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "rotation_missing",
            }),
        )
            .into_response();
    }
    if !rotation_abort_state_allowed(row.state.as_deref(), payload.force) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "rotation_invalid_state",
            }),
        )
            .into_response();
    }

    let reason = payload.reason.clone();
    let expected_state = row.state.clone();
    let result = sqlx_core::query::query(
        r#"
        UPDATE items
        SET rotation_state = NULL,
            rotation_candidate_enc = NULL,
            rotation_started_at = NULL,
            rotation_started_by = NULL,
            rotation_expires_at = NULL,
            rotation_recover_until = NULL,
            rotation_aborted_reason = $2
        WHERE id = $1
          AND rotation_state = $3
        "#,
    )
    .bind(item.id)
    .bind(reason.clone())
    .bind(expected_state)
    .execute(&state.db)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "rotation_conflict",
                }),
            )
                .into_response();
        }
        Err(err) => {
            tracing::error!(event = "rotation_abort_failed", error = %err, "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    }

    let response = RotationStatusResponse {
        state: "active".to_string(),
        started_at: None,
        started_by: None,
        expires_at: None,
        recover_until: None,
        aborted_reason: reason,
    };
    telemetry.succeed();
    (StatusCode::OK, Json(response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::{valid_rotation_abort_reason, MAX_ROTATION_ABORT_REASON_BYTES};

    #[test]
    fn abort_reason_is_bounded_and_single_line() {
        assert!(valid_rotation_abort_reason(None));
        assert!(valid_rotation_abort_reason(Some("hook failed")));
        assert!(!valid_rotation_abort_reason(Some("")));
        assert!(!valid_rotation_abort_reason(Some(" hook failed")));
        assert!(!valid_rotation_abort_reason(Some("hook\nfailed")));
        assert!(!valid_rotation_abort_reason(Some(
            &"x".repeat(MAX_ROTATION_ABORT_REASON_BYTES + 1)
        )));
    }
}
