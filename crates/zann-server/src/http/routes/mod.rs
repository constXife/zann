use crate::app::AppState;
use axum::{middleware, Router};

pub(crate) mod health;
mod policies;
pub mod v1;

pub fn router() -> Router<AppState> {
    let admin = Router::new()
        .merge(policies::router())
        .layer(middleware::from_fn(
            crate::domains::auth::core::auth_middleware,
        ));

    Router::new()
        .merge(health::router())
        .merge(admin)
        .merge(v1::router())
}
