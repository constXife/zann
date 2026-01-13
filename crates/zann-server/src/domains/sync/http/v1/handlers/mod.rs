mod pull;
mod push;
pub(crate) mod push_apply;

pub(crate) use pull::{sync_pull, sync_shared_pull};
pub(crate) use push::{sync_push, sync_shared_push};

use crate::domains::sync::service::SyncError;
use axum::{http::StatusCode, response::IntoResponse, Json};

use super::types::ErrorResponse;

pub(super) fn map_sync_error(error: SyncError) -> axum::response::Response {
    match error {
        SyncError::ForbiddenNoBody => StatusCode::FORBIDDEN.into_response(),
        SyncError::Forbidden(code) => {
            (StatusCode::FORBIDDEN, Json(ErrorResponse { error: code })).into_response()
        }
        SyncError::Unauthorized(code) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse { error: code }),
        )
            .into_response(),
        SyncError::NotFound => StatusCode::NOT_FOUND.into_response(),
        SyncError::DeviceRequired => (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "device_required",
            }),
        )
            .into_response(),
        SyncError::BadRequest(code) => {
            (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: code })).into_response()
        }
        SyncError::Conflict(code) => {
            (StatusCode::CONFLICT, Json(ErrorResponse { error: code })).into_response()
        }
        SyncError::PayloadTooLarge(code) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse { error: code }),
        )
            .into_response(),
        SyncError::DbError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response(),
        SyncError::Internal(code) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: code }),
        )
            .into_response(),
        SyncError::NoChanges => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "no_changes",
            }),
        )
            .into_response(),
        SyncError::InvalidPassword => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_password",
            }),
        )
            .into_response(),
        SyncError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_credentials",
            }),
        )
            .into_response(),
        SyncError::Kdf => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "kdf_error" }),
        )
            .into_response(),
        SyncError::PolicyMismatch { .. } => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "policy_mismatch",
            }),
        )
            .into_response(),
    }
}
