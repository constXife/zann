use super::*;
use crate::domains::auth::helpers::SessionTokens;
use zann_core::Device;

/// All login side effects serialize with recovery before acquiring device FKs.
pub(super) async fn issue_login_session(
    state: &AppState,
    user: &User,
    device: &Device,
    now: chrono::DateTime<Utc>,
    ctx: &AuthRequestContext,
    method: &'static str,
) -> Result<SessionTokens, AuthError> {
    let tokens = create_session_for_user(state, user.id, device.id, user.auth_epoch, now);
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|err| database_error(err, ctx, method))?;
    apply_tx_isolation(&mut tx, state.db_tx_isolation)
        .await
        .map_err(|err| database_error(err, ctx, method))?;
    SessionRepo::guard_account_in(&mut tx, user.id, user.auth_epoch)
        .await
        .map_err(|err| session_error(err, ctx, method))?;
    DeviceRepo::create_in(&mut tx, device)
        .await
        .map_err(|err| database_error(err, ctx, method))?;
    SessionRepo::create_in(&mut tx, &tokens.session)
        .await
        .map_err(|err| session_error(err, ctx, method))?;
    ensure_personal_vault_tx(state, &mut tx, user.id, now)
        .await
        .map_err(|err| database_error(err, ctx, method))?;
    tx.commit()
        .await
        .map_err(|err| database_error(err, ctx, method))?;
    Ok(tokens)
}
fn session_error(
    error: zann_db::repo::SessionWriteError,
    ctx: &AuthRequestContext,
    method: &str,
) -> AuthError {
    match error {
        zann_db::repo::SessionWriteError::Invalidated => AuthError::Unauthorized("account_changed"),
        zann_db::repo::SessionWriteError::Database(error) => database_error(error, ctx, method),
    }
}
fn database_error(error: sqlx_core::Error, ctx: &AuthRequestContext, method: &str) -> AuthError {
    metrics::auth_login("db_error", method);
    tracing::error!(event="auth_login_failed",error=%error,method,request_id=%ctx.request_id.as_deref().unwrap_or("unknown"));
    AuthError::DbError
}
