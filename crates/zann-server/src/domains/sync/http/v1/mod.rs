use axum::Router;

macro_rules! query {
    ($sql:expr $(, $arg:expr)* $(,)?) => {{
        #[allow(unused_mut)]
        let mut q = sqlx_core::query::query::<sqlx_postgres::Postgres>($sql);
        $(q = q.bind($arg);)*
        q
    }};
}

macro_rules! query_as {
    ($ty:ty, $sql:expr $(, $arg:expr)* $(,)?) => {{
        #[allow(unused_mut)]
        let mut q = sqlx_core::query_as::query_as::<sqlx_postgres::Postgres, $ty>($sql);
        $(q = q.bind($arg);)*
        q
    }};
}

pub(crate) mod handlers;
pub(crate) mod helpers;
pub(crate) mod types;

#[cfg(test)]
mod tests;

const ITEM_HISTORY_LIMIT: i64 = 5;

pub fn router() -> Router<crate::app::AppState> {
    Router::new()
        .route("/v1/sync/pull", axum::routing::post(handlers::sync_pull))
        .route("/v1/sync/push", axum::routing::post(handlers::sync_push))
        .route(
            "/v1/sync/shared/pull",
            axum::routing::post(handlers::sync_shared_pull),
        )
        .route(
            "/v1/sync/shared/push",
            axum::routing::post(handlers::sync_shared_push),
        )
}
