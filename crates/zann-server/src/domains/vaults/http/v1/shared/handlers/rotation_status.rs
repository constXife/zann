use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use chrono::Utc;
use uuid::Uuid;
use zann_core::Identity;
use zann_db::repo::{ItemRepo, VaultRepo};

use crate::app::AppState;
use crate::domains::access_control::http::{vault_role_allows, VaultScope};
use crate::infra::metrics;

use super::super::helpers::{
    decrypt_rotation_candidate, fetch_rotation_row, is_shared_server_vault,
    normalize_rotation_state, rotation_state_label,
};
use super::super::types::{
    ErrorResponse, RotateAbortRequest, RotationCandidateResponse, RotationStatusResponse,
};
use super::super::{ROTATION_STATE_ROTATING, ROTATION_STATE_STALE};

pub(crate) async fn rotate_status(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    let resource = "shared/items/rotate/status";
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

    match policies.evaluate(&identity, "read", resource) {
        crate::domains::access_control::policies::PolicyDecision::Allow => {}
        crate::domains::access_control::policies::PolicyDecision::Deny => {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
        crate::domains::access_control::policies::PolicyDecision::NoMatch => {
            match vault_role_allows(&state, &identity, vault.id, "read", VaultScope::Items).await {
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
    (StatusCode::OK, Json(response)).into_response()
}

#[tracing::instrument(skip(state, identity), fields(item_id = %item_id))]

pub(crate) async fn rotate_candidate(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    let resource = "shared/items/rotate/candidate";
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

    match policies.evaluate(&identity, "read_candidate", resource) {
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
                "read_candidate",
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
                    tracing::error!(event = "rotation_candidate_failed", "DB error");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: "db_error" }),
                    )
                        .into_response();
                }
            }
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
        expires_at: row.expires_at.map(|value| value.to_rfc3339()),
        recover_until: row.recover_until.map(|value| value.to_rfc3339()),
    };
    (StatusCode::OK, Json(response)).into_response()
}

#[tracing::instrument(skip(state, identity), fields(item_id = %item_id))]

pub(crate) async fn rotate_recover(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    let resource = "shared/items/rotate/recover";
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

    match policies.evaluate(&identity, "recover", resource) {
        crate::domains::access_control::policies::PolicyDecision::Allow => {}
        crate::domains::access_control::policies::PolicyDecision::Deny => {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
        crate::domains::access_control::policies::PolicyDecision::NoMatch => {
            match vault_role_allows(&state, &identity, vault.id, "recover", VaultScope::Items).await
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
        expires_at: row.expires_at.map(|value| value.to_rfc3339()),
        recover_until: row.recover_until.map(|value| value.to_rfc3339()),
    };
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

    let action = if payload.force {
        "rotate_abort_force"
    } else {
        "rotate_abort"
    };

    match policies.evaluate(&identity, action, resource) {
        crate::domains::access_control::policies::PolicyDecision::Allow => {}
        crate::domains::access_control::policies::PolicyDecision::Deny => {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
        crate::domains::access_control::policies::PolicyDecision::NoMatch => {
            match vault_role_allows(&state, &identity, vault.id, action, VaultScope::Items).await {
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
    if row.state.is_none() {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "rotation_missing",
            }),
        )
            .into_response();
    }

    let reason = payload.reason.clone();
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
        "#,
    )
    .bind(item.id)
    .bind(reason.clone())
    .execute(&state.db)
    .await;
    if let Err(err) = result {
        tracing::error!(event = "rotation_abort_failed", error = %err, "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }

    let response = RotationStatusResponse {
        state: "active".to_string(),
        started_at: None,
        started_by: None,
        expires_at: None,
        recover_until: None,
        aborted_reason: reason,
    };
    (StatusCode::OK, Json(response)).into_response()
}
