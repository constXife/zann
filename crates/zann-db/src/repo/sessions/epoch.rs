use super::super::prelude::*;
use sqlx_postgres::PgConnection;

#[derive(Debug, thiserror::Error)]
pub enum SessionWriteError {
    #[error("account session authority is no longer current")]
    Invalidated,
    #[error("session persistence failed: {0}")]
    Database(#[from] sqlx_core::Error),
}

pub(super) async fn lock_account(
    connection: &mut PgConnection,
    user_id: Uuid,
    expected_epoch: i64,
) -> Result<(), SessionWriteError> {
    let present = sqlx_core::query::query::<sqlx_postgres::Postgres>(
        "SELECT auth_epoch, active_recovery_id, status, deleted_at FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(connection)
    .await?;
    let Some(row) = present else {
        return Err(SessionWriteError::Invalidated);
    };
    if row.try_get::<i64, _>("auth_epoch")? != expected_epoch
        || row
            .try_get::<Option<Uuid>, _>("active_recovery_id")?
            .is_some()
        || row.try_get::<i16, _>("status")? != UserStatus::Active.as_i32() as i16
        || row
            .try_get::<Option<DateTime<Utc>>, _>("deleted_at")?
            .is_some()
    {
        return Err(SessionWriteError::Invalidated);
    }
    Ok(())
}

pub(super) async fn create_in(
    connection: &mut PgConnection,
    session: &Session,
) -> Result<(), SessionWriteError> {
    if session.passkey_credential_id.is_some() || session.passkey_session_epoch.is_some() {
        return Err(SessionWriteError::Invalidated);
    }
    lock_account(connection, session.user_id, session.auth_epoch).await?;
    let result = sqlx_core::query::query::<sqlx_postgres::Postgres>(
        r#"
        INSERT INTO sessions (id, user_id, device_id, auth_epoch, access_token_hash,
            access_expires_at, refresh_token_hash, expires_at, created_at)
        SELECT $1, u.id, d.id, u.auth_epoch, $5, $6, $7, $8, $9
        FROM users u JOIN devices d ON d.user_id = u.id
        WHERE u.id = $2 AND d.id = $3 AND u.auth_epoch = $4
            AND u.status = 1 AND u.deleted_at IS NULL AND u.active_recovery_id IS NULL
            AND d.revoked_at IS NULL
    "#,
    )
    .bind(session.id)
    .bind(session.user_id)
    .bind(session.device_id)
    .bind(session.auth_epoch)
    .bind(&session.access_token_hash)
    .bind(session.access_expires_at)
    .bind(&session.refresh_token_hash)
    .bind(session.expires_at)
    .bind(session.created_at)
    .execute(connection)
    .await?;
    if result.rows_affected() != 1 {
        return Err(SessionWriteError::Invalidated);
    }
    Ok(())
}

pub(super) async fn create(pool: &PgPool, session: &Session) -> Result<(), SessionWriteError> {
    let mut tx = pool.begin().await?;
    create_in(&mut tx, session).await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn rotate(
    pool: &PgPool,
    session: &Session,
    access_hash: &str,
    access_expires_at: DateTime<Utc>,
    refresh_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), SessionWriteError> {
    let mut tx = pool.begin().await?;
    let owner = sqlx_core::query::query::<sqlx_postgres::Postgres>(
        "SELECT user_id FROM sessions WHERE id = $1",
    )
    .bind(session.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(owner) = owner else {
        return Err(SessionWriteError::Invalidated);
    };
    let user_id: Uuid = owner.try_get("user_id")?;
    lock_account(&mut tx, user_id, session.auth_epoch).await?;
    let result = sqlx_core::query::query::<sqlx_postgres::Postgres>(
        r#"
        UPDATE sessions s SET access_token_hash = $4, access_expires_at = $5,
            refresh_token_hash = $6, expires_at = $7
        FROM users u, devices d
        WHERE s.id = $1 AND s.refresh_token_hash = $2 AND s.auth_epoch = $3
            AND s.user_id = u.id AND u.auth_epoch = s.auth_epoch
            AND u.status = 1 AND u.deleted_at IS NULL AND u.active_recovery_id IS NULL
            AND d.id = s.device_id AND d.user_id = u.id AND d.revoked_at IS NULL
            AND s.expires_at > CURRENT_TIMESTAMP
            AND (s.passkey_credential_id IS NULL OR EXISTS (SELECT 1 FROM account_passkeys p WHERE p.credential_id=s.passkey_credential_id AND p.session_epoch=s.passkey_session_epoch))
    "#,
    )
    .bind(session.id)
    .bind(&session.refresh_token_hash)
    .bind(session.auth_epoch)
    .bind(access_hash)
    .bind(access_expires_at)
    .bind(refresh_hash)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(SessionWriteError::Invalidated);
    }
    tx.commit().await?;
    Ok(())
}

/// Constant-cardinality revocation for password/admin changes. Caller holds the
/// target user lock as part of its mutation transaction. Active recovery is
/// terminalized without restoring an old code or scanning interactive sessions.
pub(super) async fn invalidate_user_in(
    conn: &mut PgConnection,
    user: Uuid,
    keep: Option<Uuid>,
) -> Result<(), sqlx_core::Error> {
    let row = sqlx_core::query::query::<sqlx_postgres::Postgres>(
        "SELECT active_recovery_id FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(user)
    .fetch_one(&mut *conn)
    .await?;
    let active: Option<Uuid> = row.try_get("active_recovery_id")?;
    if let Some(id) = active {
        let changed=sqlx_core::query::query::<sqlx_postgres::Postgres>("UPDATE account_recovery_operations SET state=6,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND user_id=$2 AND state IN (1,2)").bind(id).bind(user).execute(&mut *conn).await?.rows_affected();
        if changed == 1 {
            sqlx_core::query::query::<sqlx_postgres::Postgres>(
                "UPDATE account_recovery_quota SET active_count=active_count-1 WHERE singleton",
            )
            .execute(&mut *conn)
            .await?;
        }
        sqlx_core::query::query::<sqlx_postgres::Postgres>(
            "UPDATE account_access_slots SET expires_at=CURRENT_TIMESTAMP WHERE operation_id=$1",
        )
        .bind(id)
        .execute(&mut *conn)
        .await?;
    }
    sqlx_core::query::query::<sqlx_postgres::Postgres>(
        "DELETE FROM account_custody_nonces WHERE user_id=$1",
    )
    .bind(user)
    .execute(&mut *conn)
    .await?;
    let row=sqlx_core::query::query::<sqlx_postgres::Postgres>("UPDATE users SET auth_epoch=auth_epoch+1,security_revision=security_revision+1,active_recovery_id=NULL,row_version=row_version+1 WHERE id=$1 RETURNING auth_epoch").bind(user).fetch_one(&mut *conn).await?;
    if let Some(id) = keep {
        sqlx_core::query::query::<sqlx_postgres::Postgres>(
            "UPDATE sessions SET auth_epoch=$3 WHERE id=$1 AND user_id=$2",
        )
        .bind(id)
        .bind(user)
        .bind(row.try_get::<i64, _>("auth_epoch")?)
        .execute(conn)
        .await?;
    }
    Ok(())
}
