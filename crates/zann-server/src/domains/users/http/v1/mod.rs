use axum::{
    routing::{get, post},
    Router,
};

use crate::app::AppState;

mod handlers;
pub(crate) mod types;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/users/me", get(handlers::me).put(handlers::update_me))
        .route("/v1/users/me/password", post(handlers::change_password))
        .route(
            "/v1/users/me/recovery-kit",
            post(handlers::create_recovery_kit),
        )
        .route(
            "/v1/users",
            get(handlers::list_users).post(handlers::create_user),
        )
        .route(
            "/v1/users/:id",
            get(handlers::get_user).delete(handlers::delete_user),
        )
        .route("/v1/users/:id/block", post(handlers::block_user))
        .route("/v1/users/:id/unblock", post(handlers::unblock_user))
        .route(
            "/v1/users/:id/reset-password",
            post(handlers::reset_password),
        )
}
