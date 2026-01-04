mod oidc;
mod prelogin_register;
mod service_account;
mod session;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::domains::auth::service::AuthError;

use super::types::ErrorResponse;

pub(crate) use oidc::{login_oidc, oidc_config};
pub(crate) use prelogin_register::{prelogin, register};
pub(crate) use service_account::login_service_account;
pub(crate) use session::{login, logout, refresh};

pub(super) fn map_auth_error(error: AuthError) -> axum::response::Response {
    match error {
        AuthError::Forbidden(code) => {
            (StatusCode::FORBIDDEN, Json(ErrorResponse { error: code })).into_response()
        }
        AuthError::Unauthorized(code) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse { error: code }),
        )
            .into_response(),
        AuthError::BadRequest(code) => {
            (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: code })).into_response()
        }
        AuthError::Conflict(code) => {
            (StatusCode::CONFLICT, Json(ErrorResponse { error: code })).into_response()
        }
        AuthError::NotFound => StatusCode::NOT_FOUND.into_response(),
        AuthError::Internal(code) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: code }),
        )
            .into_response(),
    }
}
