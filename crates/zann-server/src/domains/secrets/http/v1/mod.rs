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
use std::fmt;
use std::io::Write;
use std::time::Instant;
use zann_core::Identity;
use zeroize::Zeroize;

use crate::app::AppState;
use crate::domains::items::contract::MAX_PLAINTEXT_PAYLOAD_BYTES;
use crate::domains::secrets::service::{self, SecretError, SecretRecord};
use crate::infra::{audit, metrics};

const MAX_BATCH_SECRETS: usize = 64;
const MAX_BATCH_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BATCH_ENSURE_RESULT_OVERHEAD_BYTES: usize = 8 * 1024;

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

#[derive(Deserialize, Serialize, JsonSchema)]
pub(crate) struct SecretRequest {
    path: String,
    #[serde(default)]
    policy: Option<String>,
    #[serde(default)]
    meta: Option<HashMap<String, String>>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct SecretSetRequest {
    value: String,
    #[serde(default)]
    policy: Option<String>,
    #[serde(default)]
    meta: Option<HashMap<String, String>>,
}

impl fmt::Debug for SecretSetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretSetRequest")
            .field("value", &"<redacted>")
            .field("policy", &"<redacted>")
            .field(
                "meta_count",
                &self.meta.as_ref().map(HashMap::len).unwrap_or(0),
            )
            .finish()
    }
}

impl Drop for SecretSetRequest {
    fn drop(&mut self) {
        wipe_string(&mut self.value);
        if let Some(policy) = self.policy.as_mut() {
            wipe_string(policy);
        }
        wipe_string_map(&mut self.meta);
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub(crate) struct BatchEnsureRequest {
    secrets: Vec<SecretRequest>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct BatchGetRequest {
    paths: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
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

impl fmt::Debug for SecretResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretResponse")
            .field("path", &self.path)
            .field("vault_id", &self.vault_id)
            .field("value", &"<redacted>")
            .field("policy", &"<redacted>")
            .field(
                "meta_count",
                &self.meta.as_ref().map(HashMap::len).unwrap_or(0),
            )
            .field("version", &self.version)
            .field("previous_version", &self.previous_version)
            .field("created", &self.created)
            .finish()
    }
}

impl Drop for SecretResponse {
    fn drop(&mut self) {
        wipe_string(&mut self.value);
        wipe_string(&mut self.policy);
        wipe_string_map(&mut self.meta);
    }
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

fn wipe_string(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    bytes.zeroize();
}

fn wipe_string_map(value: &mut Option<HashMap<String, String>>) {
    if let Some(map) = value.as_mut() {
        for (mut key, mut value) in map.drain() {
            wipe_string(&mut key);
            wipe_string(&mut value);
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/vaults/:vault_id/secrets/*path",
            get(get_secret).put(set_secret),
        )
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

async fn set_secret(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((vault_id, path)): Path<(String, String)>,
    Json(payload): Json<SecretSetRequest>,
) -> impl IntoResponse {
    let start = Instant::now();
    let result = service::set_secret(
        &state,
        &identity,
        &vault_id,
        &path,
        &payload.value,
        payload.policy.as_deref(),
        payload.meta.clone(),
    )
    .await;
    let elapsed = start.elapsed().as_secs_f64();
    match result {
        Ok((record, created)) => {
            let result_label = if created { "created" } else { "updated" };
            metrics::secrets_operation("set", result_label, elapsed);
            audit::secrets_event(&identity, "set", result_label, &vault_id, &path, None);
            (
                StatusCode::OK,
                Json(secret_response(record, None, Some(created))),
            )
                .into_response()
        }
        Err(err) => {
            let label = error_label(&err);
            metrics::secrets_operation("set", label, elapsed);
            audit::secrets_event(&identity, "set", label, &vault_id, &path, Some(label));
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
    if !validate_batch_ensure_preflight(&payload) {
        return batch_payload_too_large();
    }
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
    if !validate_batch_count(payload.paths.len()) {
        return batch_payload_too_large();
    }
    let mut results = Vec::with_capacity(payload.paths.len());
    let mut response_bytes = 0_usize;
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
        if !reserve_batch_response_bytes(&mut response_bytes, &result) {
            return batch_payload_too_large();
        }
        results.push(result);
    }
    (StatusCode::OK, Json(results)).into_response()
}

fn validate_batch_count(count: usize) -> bool {
    count <= MAX_BATCH_SECRETS
}

/// Proves an aggregate response bound before `batch_ensure` can perform its
/// first write. Every successful secret payload is contract-bounded; the
/// additional allowance covers the path, vault ID and batch response envelope.
fn validate_batch_ensure_preflight(payload: &BatchEnsureRequest) -> bool {
    let count = payload.secrets.len();
    if !validate_batch_count(count) {
        return false;
    }

    let per_result =
        match MAX_PLAINTEXT_PAYLOAD_BYTES.checked_add(MAX_BATCH_ENSURE_RESULT_OVERHEAD_BYTES) {
            Some(value) => value,
            None => return false,
        };
    let response_bound = match count
        .checked_mul(per_result)
        .and_then(|value| value.checked_add(count.saturating_sub(1)))
        .and_then(|value| value.checked_add(2))
    {
        Some(value) => value,
        None => return false,
    };
    if response_bound > MAX_BATCH_RESPONSE_BYTES {
        return false;
    }

    let mut writer = CountingWriter { written: 0 };
    serde_json::to_writer(&mut writer, payload).is_ok()
        && writer.written <= MAX_BATCH_RESPONSE_BYTES
}

fn batch_payload_too_large() -> axum::response::Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(ErrorResponse {
            error: "batch_too_large",
            details: None,
        }),
    )
        .into_response()
}

fn reserve_batch_response_bytes<T: Serialize>(used: &mut usize, value: &T) -> bool {
    let mut writer = CountingWriter { written: 0 };
    if serde_json::to_writer(&mut writer, value).is_err() {
        return false;
    }
    let Some(total) = used.checked_add(writer.written) else {
        return false;
    };
    if total > MAX_BATCH_RESPONSE_BYTES {
        return false;
    }
    *used = total;
    true
}

struct CountingWriter {
    written: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.written = self
            .written
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("batch response size overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn secret_response(
    record: SecretRecord,
    previous_version: Option<i64>,
    created: Option<bool>,
) -> SecretResponse {
    let (path, vault_id, value, policy, meta, version) = record.into_parts();
    SecretResponse {
        path,
        vault_id,
        value,
        policy,
        meta,
        version,
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
        SecretError::Unauthorized(code) => (
            StatusCode::UNAUTHORIZED,
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
        SecretError::PayloadTooLarge(code) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                error: code,
                details: None,
            }),
        )
            .into_response(),
        SecretError::DbError => (
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
        SecretError::NoChanges => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "no_changes",
                details: None,
            }),
        )
            .into_response(),
        SecretError::InvalidPassword => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_password",
                details: None,
            }),
        )
            .into_response(),
        SecretError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_credentials",
                details: None,
            }),
        )
            .into_response(),
        SecretError::Kdf => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "kdf_error",
                details: None,
            }),
        )
            .into_response(),
        SecretError::DeviceRequired => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "device_required",
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
        SecretError::Unauthorized(code) => ErrorResponse {
            error: code,
            details: None,
        },
        SecretError::DbError => ErrorResponse {
            error: "db_error",
            details: None,
        },
        SecretError::Internal(code) => ErrorResponse {
            error: code,
            details: None,
        },
        SecretError::PayloadTooLarge(code) => ErrorResponse {
            error: code,
            details: None,
        },
        SecretError::NoChanges => ErrorResponse {
            error: "no_changes",
            details: None,
        },
        SecretError::InvalidPassword => ErrorResponse {
            error: "invalid_password",
            details: None,
        },
        SecretError::InvalidCredentials => ErrorResponse {
            error: "invalid_credentials",
            details: None,
        },
        SecretError::Kdf => ErrorResponse {
            error: "kdf_error",
            details: None,
        },
        SecretError::DeviceRequired => ErrorResponse {
            error: "device_required",
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
        SecretError::Unauthorized(_) => "unauthorized",
        SecretError::PolicyMismatch { .. } => "policy_mismatch",
        SecretError::PayloadTooLarge(_) => "payload_too_large",
        SecretError::DbError => "db_error",
        SecretError::Internal(_) => "internal",
        SecretError::NoChanges => "no_changes",
        SecretError::InvalidPassword => "invalid_password",
        SecretError::InvalidCredentials => "invalid_credentials",
        SecretError::Kdf => "kdf_error",
        SecretError::DeviceRequired => "device_required",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_http_debug_output_is_redacted() {
        let request = SecretSetRequest {
            value: "sentinel-value".to_string(),
            policy: Some("sentinel-policy".to_string()),
            meta: Some(HashMap::from([(
                "sentinel-key".to_string(),
                "sentinel-meta".to_string(),
            )])),
        };
        let response = SecretResponse {
            path: "/folder/secret".to_string(),
            vault_id: "vault".to_string(),
            value: "sentinel-value".to_string(),
            policy: "sentinel-policy".to_string(),
            meta: Some(HashMap::from([(
                "sentinel-key".to_string(),
                "sentinel-meta".to_string(),
            )])),
            version: 1,
            previous_version: None,
            created: Some(true),
        };
        for rendered in [format!("{request:?}"), format!("{response:?}")] {
            for sentinel in [
                "sentinel-value",
                "sentinel-policy",
                "sentinel-key",
                "sentinel-meta",
            ] {
                assert!(!rendered.contains(sentinel));
            }
        }
    }

    #[test]
    fn batch_count_is_rejected_before_work_above_the_boundary() {
        assert!(validate_batch_count(MAX_BATCH_SECRETS));
        assert!(!validate_batch_count(MAX_BATCH_SECRETS + 1));
    }

    #[test]
    fn batch_response_budget_counts_encoded_bytes_without_buffering() {
        let result = BatchResult {
            path: "/secret".to_string(),
            status: "ok".to_string(),
            secret: None,
            error: None,
        };
        let mut used = MAX_BATCH_RESPONSE_BYTES - 1;
        assert!(!reserve_batch_response_bytes(&mut used, &result));
        assert_eq!(used, MAX_BATCH_RESPONSE_BYTES - 1);
    }

    #[test]
    fn batch_ensure_late_overflow_is_rejected_by_preflight() {
        let max_safe = MAX_BATCH_RESPONSE_BYTES
            / (MAX_PLAINTEXT_PAYLOAD_BYTES + MAX_BATCH_ENSURE_RESULT_OVERHEAD_BYTES);
        assert!(max_safe < MAX_BATCH_SECRETS);

        let secrets = (0..=max_safe)
            .map(|index| SecretRequest {
                path: format!("secret-{index}"),
                policy: None,
                meta: None,
            })
            .collect();
        assert!(!validate_batch_ensure_preflight(&BatchEnsureRequest {
            secrets,
        }));
    }
}
