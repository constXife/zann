use axum::{
    routing::{get, post},
    Router,
};

use crate::app::AppState;

mod handlers;
pub(crate) mod types;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/register", post(handlers::register))
        .route("/v1/auth/prelogin", get(handlers::prelogin))
        .route("/v1/auth/login", post(handlers::login))
        .route("/v1/auth/login/oidc", post(handlers::login_oidc))
        .route(
            "/v1/auth/service-account",
            post(handlers::login_service_account),
        )
        .route("/v1/auth/refresh", post(handlers::refresh))
        .route("/v1/auth/logout", post(handlers::logout))
        .route("/v1/auth/oidc/config", get(handlers::oidc_config))
}
