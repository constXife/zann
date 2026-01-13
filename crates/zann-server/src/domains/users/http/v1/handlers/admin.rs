use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::users::admin_service::{
    self, AdminUserError, CreateUserCommand, ListUsersCommand, ResetPasswordCommand,
};

use super::super::types::{
    CreateUserRequest, ErrorResponse, ListUsersQuery, ResetPasswordRequest, ResetPasswordResponse,
    UserListResponse,
};
use super::helpers::user_response;

fn map_admin_error(error: AdminUserError) -> axum::response::Response {
    match error {
        AdminUserError::ForbiddenNoBody => StatusCode::FORBIDDEN.into_response(),
        AdminUserError::Forbidden(code) => {
            (StatusCode::FORBIDDEN, Json(ErrorResponse { error: code })).into_response()
        }
        AdminUserError::Unauthorized(code) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse { error: code }),
        )
            .into_response(),
        AdminUserError::BadRequest(code) => {
            (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: code })).into_response()
        }
        AdminUserError::Conflict(code) => {
            (StatusCode::CONFLICT, Json(ErrorResponse { error: code })).into_response()
        }
        AdminUserError::NotFound => StatusCode::NOT_FOUND.into_response(),
        AdminUserError::PayloadTooLarge(code) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse { error: code }),
        )
            .into_response(),
        AdminUserError::DbError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response(),
        AdminUserError::Internal(code) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: code }),
        )
            .into_response(),
        AdminUserError::NoChanges => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "no_changes",
            }),
        )
            .into_response(),
        AdminUserError::InvalidPassword => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_password",
            }),
        )
            .into_response(),
        AdminUserError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_credentials",
            }),
        )
            .into_response(),
        AdminUserError::Kdf => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "kdf_error" }),
        )
            .into_response(),
        AdminUserError::DeviceRequired => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "device_required",
            }),
        )
            .into_response(),
        AdminUserError::PolicyMismatch { .. } => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "policy_mismatch",
            }),
        )
            .into_response(),
    }
}

#[tracing::instrument(skip(state, identity, query))]
pub(crate) async fn list_users(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Query(query): Query<ListUsersQuery>,
) -> impl IntoResponse {
    let command = ListUsersCommand {
        status: query.status,
        sort: query.sort.clone(),
        limit: query.limit,
        offset: query.offset,
    };
    match admin_service::list_users(&state, &identity, command).await {
        Ok(result) => {
            let users: Vec<_> = result.users.into_iter().map(user_response).collect();
            (StatusCode::OK, Json(UserListResponse { users })).into_response()
        }
        Err(err) => map_admin_error(err),
    }
}

#[tracing::instrument(skip(state, identity, payload))]
pub(crate) async fn create_user(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Json(payload): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let command = CreateUserCommand {
        email: payload.email,
        password: payload.password,
        full_name: payload.full_name,
    };
    match admin_service::create_user(&state, &identity, command).await {
        Ok(user) => (StatusCode::OK, Json(user_response(user))).into_response(),
        Err(err) => map_admin_error(err),
    }
}

#[tracing::instrument(skip(state, identity))]
pub(crate) async fn get_user(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    match admin_service::get_user(&state, &identity, &id).await {
        Ok(user) => (StatusCode::OK, Json(user_response(user))).into_response(),
        Err(err) => map_admin_error(err),
    }
}

#[tracing::instrument(skip(state, identity))]
pub(crate) async fn delete_user(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    match admin_service::delete_user(&state, &identity, &id, identity.device_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => map_admin_error(err),
    }
}

#[tracing::instrument(skip(state, identity))]
pub(crate) async fn block_user(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    match admin_service::block_user(&state, &identity, &id).await {
        Ok(user) => (StatusCode::OK, Json(user_response(user))).into_response(),
        Err(err) => map_admin_error(err),
    }
}

#[tracing::instrument(skip(state, identity))]
pub(crate) async fn unblock_user(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    match admin_service::unblock_user(&state, &identity, &id).await {
        Ok(user) => (StatusCode::OK, Json(user_response(user))).into_response(),
        Err(err) => map_admin_error(err),
    }
}

#[tracing::instrument(skip(state, identity, payload))]
pub(crate) async fn reset_password(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<ResetPasswordRequest>,
) -> impl IntoResponse {
    let command = ResetPasswordCommand {
        user_id: id,
        password: payload.password,
    };
    match admin_service::reset_password(&state, &identity, command).await {
        Ok(result) => (
            StatusCode::OK,
            Json(ResetPasswordResponse {
                password: result.password,
            }),
        )
            .into_response(),
        Err(err) => map_admin_error(err),
    }
}
