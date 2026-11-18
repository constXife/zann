//! Recheck interactive session authority inside each protected write transaction.
use crate::domains::errors::ServiceError;
use sqlx_postgres::PgConnection;
use zann_core::Identity;
use zann_db::repo::{SessionRepo, SessionWriteError};
pub async fn guard(conn: &mut PgConnection, identity: &Identity) -> Result<(), ServiceError> {
    SessionRepo::guard_identity_in(conn, identity)
        .await
        .map_err(|error| {
            // No secret material is part of this error. Preserve the original SQLx
            // source in causal diagnostics while exposing a closed public code.
            tracing::warn!(error=?error,"protected mutation authority rejected");
            match error {
                SessionWriteError::Invalidated => ServiceError::Unauthorized("session_invalidated"),
                SessionWriteError::Database(_) => ServiceError::DbError,
            }
        })
}

pub fn database(error: sqlx_core::Error) -> ServiceError {
    tracing::error!(error=?error,"protected mutation persistence failed");
    ServiceError::DbError
}
pub async fn begin<'a>(
    state: &'a crate::app::AppState,
    identity: &Identity,
) -> Result<sqlx_core::transaction::Transaction<'a, sqlx_postgres::Postgres>, ServiceError> {
    let mut tx = state.db.begin().await.map_err(database)?;
    crate::infra::db::apply_tx_isolation(&mut tx, state.db_tx_isolation)
        .await
        .map_err(database)?;
    sqlx_core::query::query::<sqlx_postgres::Postgres>("SET LOCAL lock_timeout='500ms'")
        .execute(&mut *tx)
        .await
        .map_err(database)?;
    guard(&mut tx, identity).await?;
    Ok(tx)
}
pub fn response(error: ServiceError) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (status, code) = match error {
        ServiceError::Unauthorized(code) => (axum::http::StatusCode::UNAUTHORIZED, code),
        _ => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    (status, axum::Json(serde_json::json!({"error":code}))).into_response()
}
