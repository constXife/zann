use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::users::service::{
    change_password as change_password_service, create_recovery_kit as create_recovery_kit_service,
    get_me, update_me as update_me_service, ChangePasswordCommand, MeError, UpdateMeCommand,
};

use super::super::types::{
    ChangePasswordRequest, ErrorResponse, RecoveryKitResponse, UpdateMeRequest,
};
use super::helpers::user_response;

fn map_me_error(error: MeError) -> axum::response::Response {
    match error {
        MeError::ForbiddenNoBody => StatusCode::FORBIDDEN.into_response(),
        MeError::Forbidden(code) => {
            (StatusCode::FORBIDDEN, Json(ErrorResponse { error: code })).into_response()
        }
        MeError::NotFound => StatusCode::NOT_FOUND.into_response(),
        MeError::Db => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response(),
        MeError::NoChanges => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "no_changes",
            }),
        )
            .into_response(),
        MeError::InvalidPassword => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_password",
            }),
        )
            .into_response(),
        MeError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_credentials",
            }),
        )
            .into_response(),
        MeError::Kdf => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "kdf_error" }),
        )
            .into_response(),
    }
}

#[tracing::instrument(skip(state, identity))]
pub(crate) async fn me(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
) -> impl IntoResponse {
    match get_me(&state, &identity).await {
        Ok(identity) => (StatusCode::OK, Json(identity)).into_response(),
        Err(err) => map_me_error(err),
    }
}

#[tracing::instrument(skip(state, identity, payload))]
pub(crate) async fn update_me(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Json(payload): Json<UpdateMeRequest>,
) -> impl IntoResponse {
    let command = UpdateMeCommand {
        full_name: payload.full_name,
    };
    match update_me_service(&state, &identity, command).await {
        Ok(user) => (StatusCode::OK, Json(user_response(user))).into_response(),
        Err(err) => map_me_error(err),
    }
}

#[tracing::instrument(skip(state, identity, payload))]
pub(crate) async fn change_password(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Json(payload): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let command = ChangePasswordCommand {
        current_password: payload.current_password,
        new_password: payload.new_password,
    };
    match change_password_service(&state, &identity, command).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => map_me_error(err),
    }
}

#[tracing::instrument(skip(state, identity))]
pub(crate) async fn create_recovery_kit(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
) -> impl IntoResponse {
    match create_recovery_kit_service(&state, &identity).await {
        Ok(result) => (
            StatusCode::OK,
            Json(RecoveryKitResponse {
                recovery_key: result.recovery_key,
            }),
        )
            .into_response(),
        Err(err) => map_me_error(err),
    }
}
