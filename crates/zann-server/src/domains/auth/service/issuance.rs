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
    factor: LoginFactor<'_>,
) -> Result<SessionTokens, AuthError> {
    let method = factor.label();
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|err| database_error(err, ctx, method))?;
    apply_tx_isolation(&mut tx, state.db_tx_isolation)
        .await
        .map_err(|err| database_error(err, ctx, method))?;
    let tokens = issue_login_session_in(state, &mut tx, user, device, now, factor)
        .await
        .map_err(|error| match error {
            SessionIssueError::Session(error) => session_error(error, ctx, method),
            SessionIssueError::Database(error) => database_error(error, ctx, method),
        })?;
    tx.commit()
        .await
        .map_err(|err| database_error(err, ctx, method))?;
    Ok(tokens)
}
#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionIssueError {
    #[error("session issue database failed")]
    Database(#[from] sqlx_core::Error),
    #[error("session issue authority changed")]
    Session(#[from] zann_db::repo::SessionWriteError),
}

pub(crate) async fn issue_login_session_in(
    state: &AppState,
    conn: &mut sqlx_postgres::PgConnection,
    user: &User,
    device: &Device,
    now: chrono::DateTime<Utc>,
    factor: LoginFactor<'_>,
) -> Result<SessionTokens, SessionIssueError> {
    let tokens = create_session_for_user(state, user.id, device.id, user.auth_epoch, now);
    SessionRepo::guard_account_in(conn, user.id, user.auth_epoch).await?;
    if matches!(factor, LoginFactor::Password) {
        SessionRepo::guard_password_in(conn, user).await?;
    }
    DeviceRepo::create_in(conn, device).await?;
    if let LoginFactor::Passkey(id) = factor {
        SessionRepo::create_passkey_in(conn, &tokens.session, id).await?;
    } else {
        SessionRepo::create_in(conn, &tokens.session).await?;
    }
    ensure_personal_vault_tx(state, conn, user.id, now).await?;
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

#[derive(Clone, Copy)]
pub(crate) enum LoginFactor<'a> {
    Password,
    Oidc,
    Passkey(&'a [u8]),
}
impl LoginFactor<'_> {
    fn label(self) -> &'static str {
        match self {
            Self::Password => "internal",
            Self::Oidc => "oidc",
            Self::Passkey(_) => "passkey",
        }
    }
}
