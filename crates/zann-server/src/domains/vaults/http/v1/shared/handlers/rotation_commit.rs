use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use chrono::{DateTime, Utc};
use sqlx_core::row::Row;
use uuid::Uuid;
use zann_core::{FieldKind, Identity};
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{ItemHistoryRepo, ItemRepo, VaultRepo};

use crate::app::AppState;
use crate::domains::access_control::http::{vault_role_allows, VaultScope};
use crate::infra::metrics;

use super::super::helpers::{actor_snapshot, decrypt_rotation_candidate, is_shared_server_vault};
use super::super::types::{ErrorResponse, RotationCommitResponse};
use super::super::{ROTATION_STATE_ROTATING, ROTATION_STATE_STALE};

pub(crate) async fn rotate_commit(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    let resource = "shared/items/rotate/commit";
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
            tracing::error!(event = "rotation_commit_failed", "DB error");
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

    match policies.evaluate(&identity, "rotate_commit", resource) {
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
                "rotate_commit",
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
                    tracing::error!(event = "rotation_commit_failed", "DB error");
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

    let actor = actor_snapshot(&state, &identity, identity.device_id).await;
    let mut conn = match state.db.acquire().await {
        Ok(conn) => conn,
        Err(_) => {
            tracing::error!(event = "rotation_commit_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    if let Err(err) = sqlx_core::query::query("BEGIN")
        .execute(&mut *conn)
        .await
    {
        tracing::error!(event = "rotation_commit_failed", error = %err, "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }

    let row = sqlx_core::query::query(
        r#"
        SELECT
            payload_enc,
            checksum,
            version,
            row_version,
            device_id,
            rotation_state,
            rotation_candidate_enc,
            rotation_expires_at,
            rotation_recover_until
        FROM items
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(item.id)
    .fetch_optional(&mut *conn)
    .await;

    let row = match row {
        Ok(Some(row)) => row,
        Ok(None) => {
            let _ = sqlx_core::query::query("ROLLBACK")
                .execute(&mut *conn)
                .await;
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(_) => {
            let _ = sqlx_core::query::query("ROLLBACK")
                .execute(&mut *conn)
                .await;
            tracing::error!(event = "rotation_commit_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let rotation_state: Option<String> = row.try_get("rotation_state").ok();
    let mut state_label = rotation_state.as_deref();
    let expires_at: Option<DateTime<Utc>> = row.try_get("rotation_expires_at").ok();
    if state_label == Some(ROTATION_STATE_ROTATING)
        && expires_at.is_some_and(|value| Utc::now() > value)
    {
        state_label = Some(ROTATION_STATE_STALE);
    }
    if !matches!(
        state_label,
        Some(ROTATION_STATE_ROTATING) | Some(ROTATION_STATE_STALE)
    ) {
        let _ = sqlx_core::query::query("ROLLBACK")
            .execute(&mut *conn)
            .await;
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "rotation_missing",
            }),
        )
            .into_response();
    }
    let recover_until: Option<DateTime<Utc>> = row.try_get("rotation_recover_until").ok();
    if recover_until.is_some_and(|value| Utc::now() > value) {
        let _ = sqlx_core::query::query("ROLLBACK")
            .execute(&mut *conn)
            .await;
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "rotation_expired",
            }),
        )
            .into_response();
    }

    let candidate_enc: Option<Vec<u8>> = row.try_get("rotation_candidate_enc").ok();
    let Some(candidate_enc) = candidate_enc else {
        let _ = sqlx_core::query::query("ROLLBACK")
            .execute(&mut *conn)
            .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "rotation_missing",
            }),
        )
            .into_response();
    };

    let candidate = match decrypt_rotation_candidate(smk, &vault, item.id, &candidate_enc) {
        Ok(value) => value,
        Err(_) => {
            let _ = sqlx_core::query::query("ROLLBACK")
                .execute(&mut *conn)
                .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };

    let payload_enc: Vec<u8> = row.try_get("payload_enc").unwrap_or_default();
    let previous_checksum: String = row.try_get("checksum").unwrap_or_default();
    let previous_version: i64 = row.try_get("version").unwrap_or(1);
    let row_version: i64 = row.try_get("row_version").unwrap_or(1);
    let existing_device_id: Uuid = row.try_get("device_id").unwrap_or(item.device_id);
    let vault_key = match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
        Ok(key) => key,
        Err(_) => {
            let _ = sqlx_core::query::query("ROLLBACK")
                .execute(&mut *conn)
                .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };
    let mut payload =
        match core_crypto::decrypt_payload(&vault_key, vault.id, item.id, &payload_enc) {
            Ok(payload) => payload,
            Err(_) => {
                let _ = sqlx_core::query::query("ROLLBACK")
                    .execute(&mut *conn)
                    .await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "decrypt_failed",
                    }),
                )
                    .into_response();
            }
        };

    let mut updated = false;
    for field in payload.fields.values_mut() {
        if field.kind == FieldKind::Password {
            field.value = candidate.clone();
            updated = true;
            break;
        }
    }
    if !updated {
        let _ = sqlx_core::query::query("ROLLBACK")
            .execute(&mut *conn)
            .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "password_field_missing",
            }),
        )
            .into_response();
    }

    let new_payload_enc =
        match core_crypto::encrypt_payload(&vault_key, vault.id, item.id, &payload) {
            Ok(value) => value,
            Err(_) => {
                let _ = sqlx_core::query::query("ROLLBACK")
                    .execute(&mut *conn)
                    .await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "encrypt_failed",
                    }),
                )
                    .into_response();
            }
        };
    let new_checksum = core_crypto::payload_checksum(&new_payload_enc);

    let history_id = Uuid::now_v7();
    let now = Utc::now();
    let change_type = zann_core::ChangeType::Update.as_i32();
    let _ = sqlx_core::query::query(
        r#"
        INSERT INTO item_history (
            id,
            item_id,
            version,
            payload_enc,
            checksum,
            change_type,
            fields_changed,
            changed_by_user_id,
            changed_by_email,
            changed_by_name,
            changed_by_device_id,
            changed_by_device_name,
            created_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12, $13
        )
        ON CONFLICT (item_id, version) DO NOTHING
        "#,
    )
    .bind(history_id)
    .bind(item.id)
    .bind(previous_version)
    .bind(payload_enc)
    .bind(previous_checksum.as_str())
    .bind(change_type)
    .bind(Option::<serde_json::Value>::None)
    .bind(identity.user_id)
    .bind(actor.email.as_str())
    .bind(actor.name.as_deref())
    .bind(identity.device_id)
    .bind(actor.device_name.as_deref())
    .bind(now)
    .execute(&mut *conn)
    .await;

    let new_version = previous_version + 1;
    let device_id = identity.device_id.unwrap_or(existing_device_id);
    let updated = sqlx_core::query::query(
        r#"
        UPDATE items
        SET payload_enc = $2,
            checksum = $3,
            version = $4,
            row_version = $5,
            device_id = $6,
            updated_at = $7,
            rotation_state = NULL,
            rotation_candidate_enc = NULL,
            rotation_started_at = NULL,
            rotation_started_by = NULL,
            rotation_expires_at = NULL,
            rotation_recover_until = NULL,
            rotation_aborted_reason = NULL
        WHERE id = $1 AND row_version = $8
        "#,
    )
    .bind(item.id)
    .bind(new_payload_enc)
    .bind(new_checksum.as_str())
    .bind(new_version)
    .bind(row_version + 1)
    .bind(device_id)
    .bind(now)
    .bind(row_version)
    .execute(&mut *conn)
    .await;

    if let Err(err) = updated {
        let _ = sqlx_core::query::query("ROLLBACK")
            .execute(&mut *conn)
            .await;
        tracing::error!(event = "rotation_commit_failed", error = %err, "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }

    if let Err(err) = sqlx_core::query::query("COMMIT")
        .execute(&mut *conn)
        .await
    {
        tracing::error!(event = "rotation_commit_failed", error = %err, "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }

    let history_repo = ItemHistoryRepo::new(&state.db);
    let _ = history_repo
        .prune_by_item(item.id, state.config.rotation.max_versions)
        .await;

    let response = RotationCommitResponse {
        status: "committed",
        version: new_version,
    };
    (StatusCode::OK, Json(response)).into_response()
}
