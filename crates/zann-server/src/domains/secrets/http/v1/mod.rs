use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::secrets::service::{self, SecretError, SecretRecord};
use crate::infra::{audit, metrics};

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ErrorResponse {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<PolicyMismatchDetails>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct PolicyMismatchDetails {
    requested_policy: String,
    existing_policy: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SecretRequest {
    path: String,
    #[serde(default)]
    policy: Option<String>,
    #[serde(default)]
    meta: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct BatchEnsureRequest {
    secrets: Vec<SecretRequest>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct BatchGetRequest {
    paths: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct SecretResponse {
    pub(crate) path: String,
    pub(crate) vault_id: String,
    pub(crate) value: String,
    pub(crate) policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) meta: Option<HashMap<String, String>>,
    pub(crate) version: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) previous_version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) created: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct BatchResult {
    path: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<SecretResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorResponse>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/vaults/:vault_id/secrets/*path", get(get_secret))
        .route("/v1/vaults/:vault_id/secrets/ensure", post(ensure_secret))
        .route("/v1/vaults/:vault_id/secrets/rotate", post(rotate_secret))
        .route(
            "/v1/vaults/:vault_id/secrets/batch/ensure",
            post(batch_ensure),
        )
        .route("/v1/vaults/:vault_id/secrets/batch/get", post(batch_get))
}

async fn get_secret(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((vault_id, path)): Path<(String, String)>,
) -> impl IntoResponse {
    let start = Instant::now();
    let result = service::get_secret(&state, &identity, &vault_id, &path).await;
    let elapsed = start.elapsed().as_secs_f64();
    match result {
        Ok(record) => {
            metrics::secrets_operation("get", "ok", elapsed);
            audit::secrets_event(&identity, "get", "ok", &vault_id, &path, None);
            (StatusCode::OK, Json(secret_response(record, None, None))).into_response()
        }
        Err(err) => {
            let label = error_label(&err);
            metrics::secrets_operation("get", label, elapsed);
            audit::secrets_event(&identity, "get", label, &vault_id, &path, Some(label));
            map_secret_error(err)
        }
    }
}

async fn ensure_secret(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(vault_id): Path<String>,
    Json(payload): Json<SecretRequest>,
) -> impl IntoResponse {
    let start = Instant::now();
    let result = service::ensure_secret(
        &state,
        &identity,
        &vault_id,
        &payload.path,
        payload.policy.as_deref(),
        payload.meta.clone(),
    )
    .await;
    let elapsed = start.elapsed().as_secs_f64();
    match result {
        Ok((record, created)) => {
            let result_label = if created { "created" } else { "existing" };
            metrics::secrets_operation("ensure", result_label, elapsed);
            audit::secrets_event(
                &identity,
                "ensure",
                result_label,
                &vault_id,
                &payload.path,
                None,
            );
            (
                StatusCode::OK,
                Json(secret_response(record, None, Some(created))),
            )
                .into_response()
        }
        Err(err) => {
            let label = error_label(&err);
            metrics::secrets_operation("ensure", label, elapsed);
            audit::secrets_event(
                &identity,
                "ensure",
                label,
                &vault_id,
                &payload.path,
                Some(label),
            );
            map_secret_error(err)
        }
    }
}

async fn rotate_secret(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(vault_id): Path<String>,
    Json(payload): Json<SecretRequest>,
) -> impl IntoResponse {
    let start = Instant::now();
    let result = service::rotate_secret(
        &state,
        &identity,
        &vault_id,
        &payload.path,
        payload.policy.as_deref(),
        payload.meta.clone(),
    )
    .await;
    let elapsed = start.elapsed().as_secs_f64();
    match result {
        Ok((record, previous_version)) => {
            metrics::secrets_operation("rotate", "ok", elapsed);
            audit::secrets_event(&identity, "rotate", "ok", &vault_id, &payload.path, None);
            (
                StatusCode::OK,
                Json(secret_response(record, Some(previous_version), None)),
            )
                .into_response()
        }
        Err(err) => {
            let label = error_label(&err);
            metrics::secrets_operation("rotate", label, elapsed);
            audit::secrets_event(
                &identity,
                "rotate",
                label,
                &vault_id,
                &payload.path,
                Some(label),
            );
            map_secret_error(err)
        }
    }
}

async fn batch_ensure(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(vault_id): Path<String>,
    Json(payload): Json<BatchEnsureRequest>,
) -> impl IntoResponse {
    let mut results = Vec::with_capacity(payload.secrets.len());
    for secret in payload.secrets {
        let path = secret.path;
        let audit_path = path.clone();
        let start = Instant::now();
        let outcome = service::ensure_secret(
            &state,
            &identity,
            &vault_id,
            &path,
            secret.policy.as_deref(),
            secret.meta.clone(),
        )
        .await;
        let elapsed = start.elapsed().as_secs_f64();
        let result = match outcome {
            Ok((record, created)) => {
                let result_label = if created { "created" } else { "existing" };
                metrics::secrets_operation("ensure", result_label, elapsed);
                audit::secrets_event(
                    &identity,
                    "ensure",
                    result_label,
                    &vault_id,
                    &audit_path,
                    None,
                );
                BatchResult {
                    path,
                    status: if created { "created" } else { "existing" }.to_string(),
                    secret: Some(secret_response(record, None, Some(created))),
                    error: None,
                }
            }
            Err(err) => {
                let label = error_label(&err);
                metrics::secrets_operation("ensure", label, elapsed);
                audit::secrets_event(
                    &identity,
                    "ensure",
                    label,
                    &vault_id,
                    &audit_path,
                    Some(label),
                );
                BatchResult {
                    path,
                    status: "error".to_string(),
                    secret: None,
                    error: Some(map_secret_error_body(err)),
                }
            }
        };
        results.push(result);
    }
    (StatusCode::OK, Json(results)).into_response()
}

async fn batch_get(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(vault_id): Path<String>,
    Json(payload): Json<BatchGetRequest>,
) -> impl IntoResponse {
    let mut results = Vec::with_capacity(payload.paths.len());
    for path in payload.paths {
        let audit_path = path.clone();
        let start = Instant::now();
        let outcome = service::get_secret(&state, &identity, &vault_id, &path).await;
        let elapsed = start.elapsed().as_secs_f64();
        let result = match outcome {
            Ok(record) => {
                metrics::secrets_operation("get", "ok", elapsed);
                audit::secrets_event(&identity, "get", "ok", &vault_id, &audit_path, None);
                BatchResult {
                    path,
                    status: "ok".to_string(),
                    secret: Some(secret_response(record, None, None)),
                    error: None,
                }
            }
            Err(err) => {
                let label = error_label(&err);
                metrics::secrets_operation("get", label, elapsed);
                audit::secrets_event(&identity, "get", label, &vault_id, &audit_path, Some(label));
                BatchResult {
                    path,
                    status: "error".to_string(),
                    secret: None,
                    error: Some(map_secret_error_body(err)),
                }
            }
        };
        results.push(result);
    }
    (StatusCode::OK, Json(results)).into_response()
}

fn secret_response(
    record: SecretRecord,
    previous_version: Option<i64>,
    created: Option<bool>,
) -> SecretResponse {
    SecretResponse {
        path: record.path,
        vault_id: record.vault_id,
        value: record.value,
        policy: record.policy,
        meta: record.meta,
        version: record.version,
        previous_version,
        created,
    }
}

fn map_secret_error(error: SecretError) -> axum::response::Response {
    match error {
        SecretError::ForbiddenNoBody => StatusCode::FORBIDDEN.into_response(),
        SecretError::Forbidden(code) => (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: code,
                details: None,
            }),
        )
            .into_response(),
        SecretError::NotFound => StatusCode::NOT_FOUND.into_response(),
        SecretError::BadRequest(code) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: code,
                details: None,
            }),
        )
            .into_response(),
        SecretError::Conflict(code) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: code,
                details: None,
            }),
        )
            .into_response(),
        SecretError::PolicyMismatch {
            existing,
            requested,
        } => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "policy_mismatch",
                details: Some(PolicyMismatchDetails {
                    requested_policy: requested,
                    existing_policy: existing,
                }),
            }),
        )
            .into_response(),
        SecretError::Db => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "db_error",
                details: None,
            }),
        )
            .into_response(),
        SecretError::Internal(code) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: code,
                details: None,
            }),
        )
            .into_response(),
    }
}

fn map_secret_error_body(error: SecretError) -> ErrorResponse {
    match error {
        SecretError::PolicyMismatch {
            existing,
            requested,
        } => ErrorResponse {
            error: "policy_mismatch",
            details: Some(PolicyMismatchDetails {
                requested_policy: requested,
                existing_policy: existing,
            }),
        },
        SecretError::ForbiddenNoBody => ErrorResponse {
            error: "forbidden",
            details: None,
        },
        SecretError::Forbidden(code) => ErrorResponse {
            error: code,
            details: None,
        },
        SecretError::NotFound => ErrorResponse {
            error: "not_found",
            details: None,
        },
        SecretError::BadRequest(code) => ErrorResponse {
            error: code,
            details: None,
        },
        SecretError::Conflict(code) => ErrorResponse {
            error: code,
            details: None,
        },
        SecretError::Db => ErrorResponse {
            error: "db_error",
            details: None,
        },
        SecretError::Internal(code) => ErrorResponse {
            error: code,
            details: None,
        },
    }
}

fn error_label(error: &SecretError) -> &'static str {
    match error {
        SecretError::ForbiddenNoBody | SecretError::Forbidden(_) => "forbidden",
        SecretError::NotFound => "not_found",
        SecretError::BadRequest(_) => "bad_request",
        SecretError::Conflict(_) => "conflict",
        SecretError::PolicyMismatch { .. } => "policy_mismatch",
        SecretError::Db => "db_error",
        SecretError::Internal(_) => "internal",
    }
}
