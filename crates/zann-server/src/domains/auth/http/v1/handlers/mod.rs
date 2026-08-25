mod oidc;
mod prelogin_register;
mod service_account;
mod session;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use zann_core::api::auth::ApiErrorResponse;

use crate::domains::auth::service::AuthError;

pub(crate) use oidc::{login_oidc, oidc_config};
pub(crate) use prelogin_register::{prelogin, register};
pub(crate) use service_account::login_service_account;
pub(crate) use session::{login, logout, refresh};

pub(super) fn map_auth_error(error: AuthError) -> axum::response::Response {
    match error {
        AuthError::ForbiddenNoBody => StatusCode::FORBIDDEN.into_response(),
        AuthError::Forbidden(code) => {
            (StatusCode::FORBIDDEN, Json(ApiErrorResponse::new(code))).into_response()
        }
        AuthError::Unauthorized(code) => {
            (StatusCode::UNAUTHORIZED, Json(ApiErrorResponse::new(code))).into_response()
        }
        AuthError::BadRequest(code) => {
            (StatusCode::BAD_REQUEST, Json(ApiErrorResponse::new(code))).into_response()
        }
        AuthError::Conflict(code) => {
            (StatusCode::CONFLICT, Json(ApiErrorResponse::new(code))).into_response()
        }
        AuthError::NotFound => StatusCode::NOT_FOUND.into_response(),
        AuthError::PayloadTooLarge(code) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ApiErrorResponse::new(code)),
        )
            .into_response(),
        AuthError::DbError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse::new("db_error")),
        )
            .into_response(),
        AuthError::Internal(code) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse::new(code)),
        )
            .into_response(),
        AuthError::NoChanges => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse::new("no_changes")),
        )
            .into_response(),
        AuthError::InvalidPassword => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse::new("invalid_password")),
        )
            .into_response(),
        AuthError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse::new("invalid_credentials")),
        )
            .into_response(),
        AuthError::Kdf => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse::new("kdf_error")),
        )
            .into_response(),
        AuthError::DeviceRequired => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse::new("device_required")),
        )
            .into_response(),
        AuthError::PolicyMismatch { .. } => (
            StatusCode::CONFLICT,
            Json(ApiErrorResponse::new("policy_mismatch")),
        )
            .into_response(),
    }
}
