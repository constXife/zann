use crate::app::AppState;
use axum::{middleware, Router};

pub fn router() -> Router<AppState> {
    // Protected API requires auth middleware.
    let protected = Router::new()
        .merge(crate::domains::vaults::http::v1::router())
        .merge(crate::domains::items::http::v1::router())
        .merge(crate::domains::members::http::v1::router())
        .merge(crate::domains::sync::http::v1::router())
        .merge(crate::domains::devices::http::v1::router())
        .merge(crate::domains::groups::http::v1::router())
        .merge(crate::domains::users::http::v1::router())
        .merge(crate::domains::secrets::http::v1::router())
        .layer(middleware::from_fn(
            crate::domains::auth::core::auth_middleware,
        ));

    // Public routes do their own auth or are unauthenticated.
    Router::new()
        .merge(crate::domains::auth::http::v1::router())
        .merge(crate::domains::system::http::v1::router())
        .merge(protected)
}
