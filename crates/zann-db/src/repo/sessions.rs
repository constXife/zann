mod epoch;
use super::prelude::*;
pub use epoch::SessionWriteError;
use tracing::{instrument, Span};

pub struct SessionRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> SessionRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    /// Recheck exact bearer authority inside a protected mutation transaction.
    pub async fn guard_session_in(
        conn: &mut sqlx_postgres::PgConnection,
        session: &Session,
    ) -> Result<(), SessionWriteError> {
        epoch::lock_account(conn, session.user_id, session.auth_epoch).await?;
        let row=sqlx_core::query::query::<sqlx_postgres::Postgres>("SELECT s.id FROM sessions s JOIN devices d ON d.id=s.device_id AND d.user_id=s.user_id LEFT JOIN account_passkeys p ON p.credential_id=s.passkey_credential_id WHERE s.id=$1 AND s.user_id=$2 AND s.auth_epoch=$3 AND s.access_token_hash=$4 AND s.access_expires_at>CURRENT_TIMESTAMP AND d.revoked_at IS NULL AND (s.passkey_credential_id IS NULL OR p.session_epoch=s.passkey_session_epoch)")
            .bind(session.id).bind(session.user_id).bind(session.auth_epoch).bind(&session.access_token_hash).fetch_optional(conn).await?;
        if row.is_none() {
            return Err(SessionWriteError::Invalidated);
        }
        Ok(())
    }

    pub async fn create_passkey_in(
        conn: &mut sqlx_postgres::PgConnection,
        session: &Session,
        credential: &[u8],
    ) -> Result<(), SessionWriteError> {
        epoch::create_in(conn, session).await?;
        let changed=sqlx_core::query::query::<sqlx_postgres::Postgres>("UPDATE sessions s SET passkey_credential_id=p.credential_id,passkey_session_epoch=p.session_epoch FROM account_passkeys p WHERE s.id=$1 AND p.credential_id=$2 AND p.user_id=s.user_id AND p.revoked_at IS NULL")
            .bind(session.id).bind(credential).execute(conn).await?;
        if changed.rows_affected() != 1 {
            return Err(SessionWriteError::Invalidated);
        }
        Ok(())
    }

    #[instrument(
        level = "debug",
        skip_all,
        fields(
            session_id = %session.id,
            user_id = %session.user_id,
            db.system = "postgresql",
            db.operation = "INSERT",
            db.query = "sessions.create"
        )
    )]
    pub async fn create(&self, session: &Session) -> Result<(), SessionWriteError> {
        epoch::create(self.pool, session).await
    }

    pub async fn guard_account_in(
        connection: &mut sqlx_postgres::PgConnection,
        user_id: Uuid,
        expected_epoch: i64,
    ) -> Result<(), SessionWriteError> {
        epoch::lock_account(connection, user_id, expected_epoch).await
    }

    pub async fn create_in(
        connection: &mut sqlx_postgres::PgConnection,
        session: &Session,
    ) -> Result<(), SessionWriteError> {
        epoch::create_in(connection, session).await
    }

    #[instrument(
        level = "debug",
        skip_all,
        fields(session_id = %id, db.system = "postgresql", db.operation = "SELECT", db.query = "sessions.get_by_id")
    )]
    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<Session>, sqlx_core::Error> {
        query_as!(
            Session,
            r#"
            SELECT
                id as "id",
                user_id as "user_id",
                device_id as "device_id",
                auth_epoch,
                passkey_credential_id,
                passkey_session_epoch,
                access_token_hash,
                access_expires_at as "access_expires_at",
                refresh_token_hash,
                expires_at as "expires_at",
                created_at as "created_at"
            FROM sessions
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    #[instrument(
        level = "debug",
        skip_all,
        fields(user_id = %user_id, db.system = "postgresql", db.operation = "SELECT", db.query = "sessions.list_by_user")
    )]
    pub async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<Session>, sqlx_core::Error> {
        query_as!(
            Session,
            r#"
            SELECT
                id as "id",
                user_id as "user_id",
                device_id as "device_id",
                auth_epoch,
                passkey_credential_id,
                passkey_session_epoch,
                access_token_hash,
                access_expires_at as "access_expires_at",
                refresh_token_hash,
                expires_at as "expires_at",
                created_at as "created_at"
            FROM sessions
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(self.pool)
        .await
        .inspect(|sessions| {
            Span::current().record("db.rows", sessions.len() as i64);
        })
    }

    #[instrument(
        level = "debug",
        skip_all,
        fields(db.system = "postgresql", db.operation = "SELECT", db.query = "sessions.get_by_refresh_token_hash")
    )]
    pub async fn get_by_refresh_token_hash(
        &self,
        refresh_token_hash: &str,
    ) -> Result<Option<Session>, sqlx_core::Error> {
        query_as!(
            Session,
            r#"
            SELECT
                s.id as "id",
                s.user_id as "user_id",
                s.device_id as "device_id",
                s.auth_epoch,
                s.passkey_credential_id,
                s.passkey_session_epoch,
                s.access_token_hash,
                s.access_expires_at as "access_expires_at",
                s.refresh_token_hash,
                s.expires_at as "expires_at",
                s.created_at as "created_at"
            FROM sessions s
            JOIN devices d ON d.id = s.device_id AND d.user_id = s.user_id
            JOIN users u ON u.id = s.user_id AND u.auth_epoch = s.auth_epoch
            LEFT JOIN account_passkeys p ON p.credential_id = s.passkey_credential_id
            WHERE s.refresh_token_hash = $1
              AND d.revoked_at IS NULL
              AND (s.passkey_credential_id IS NULL OR p.session_epoch = s.passkey_session_epoch)
              AND u.status = 1 AND u.deleted_at IS NULL AND u.active_recovery_id IS NULL
            "#,
            refresh_token_hash
        )
        .fetch_optional(self.pool)
        .await
    }

    #[instrument(
        level = "debug",
        skip_all,
        fields(db.system = "postgresql", db.operation = "SELECT", db.query = "sessions.get_by_access_token_hash")
    )]
    pub async fn get_by_access_token_hash(
        &self,
        access_token_hash: &str,
    ) -> Result<Option<Session>, sqlx_core::Error> {
        query_as!(
            Session,
            r#"
            SELECT
                s.id as "id",
                s.user_id as "user_id",
                s.device_id as "device_id",
                s.auth_epoch,
                s.passkey_credential_id,
                s.passkey_session_epoch,
                s.access_token_hash,
                s.access_expires_at as "access_expires_at",
                s.refresh_token_hash,
                s.expires_at as "expires_at",
                s.created_at as "created_at"
            FROM sessions s
            JOIN devices d ON d.id = s.device_id AND d.user_id = s.user_id
            JOIN users u ON u.id = s.user_id AND u.auth_epoch = s.auth_epoch
            LEFT JOIN account_passkeys p ON p.credential_id = s.passkey_credential_id
            WHERE s.access_token_hash = $1
              AND d.revoked_at IS NULL
              AND (s.passkey_credential_id IS NULL OR p.session_epoch = s.passkey_session_epoch)
              AND u.status = 1 AND u.deleted_at IS NULL AND u.active_recovery_id IS NULL
            "#,
            access_token_hash
        )
        .fetch_optional(self.pool)
        .await
    }

    #[instrument(
        level = "debug",
        skip_all,
        fields(session_id = %session.id, db.system = "postgresql", db.operation = "UPDATE", db.query = "sessions.update_refresh_token")
    )]
    pub async fn update_refresh_token(
        &self,
        session: &Session,
        access_token_hash: &str,
        access_expires_at: DateTime<Utc>,
        refresh_token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), SessionWriteError> {
        epoch::rotate(
            self.pool,
            session,
            access_token_hash,
            access_expires_at,
            refresh_token_hash,
            expires_at,
        )
        .await
    }

    #[instrument(
        level = "debug",
        skip_all,
        fields(db.system = "postgresql", db.operation = "DELETE", db.query = "sessions.delete_by_refresh_token_hash")
    )]
    pub async fn delete_by_refresh_token_hash(
        &self,
        refresh_token_hash: &str,
    ) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            DELETE FROM sessions
            WHERE refresh_token_hash = $1
            "#,
            refresh_token_hash
        )
        .execute(self.pool)
        .await
        .map(|result| {
            Span::current().record("db.rows", result.rows_affected() as i64);
        })
    }

    #[instrument(
        level = "debug",
        skip_all,
        fields(device_id = %device_id, db.system = "postgresql", db.operation = "DELETE", db.query = "sessions.delete_by_device")
    )]
    pub async fn delete_by_device(&self, device_id: Uuid) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            DELETE FROM sessions
            WHERE device_id = $1
            "#,
            device_id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    /// Deletes every session of a user except the ones belonging to
    /// `keep_device_id`; used when a password change must cut off other
    /// devices while the caller stays signed in.
    #[instrument(
        level = "debug",
        skip_all,
        fields(user_id = %user_id, db.system = "postgresql", db.operation = "DELETE", db.query = "sessions.delete_for_user_except_device")
    )]
    pub async fn delete_for_user_except_device(
        &self,
        user_id: Uuid,
        keep_device_id: Option<Uuid>,
    ) -> Result<u64, sqlx_core::Error> {
        match keep_device_id {
            Some(keep_device_id) => {
                query!(
                    r#"
                    DELETE FROM sessions
                    WHERE user_id = $1
                      AND device_id != $2
                    "#,
                    user_id,
                    keep_device_id
                )
                .execute(self.pool)
                .await
            }
            None => {
                query!(
                    r#"
                    DELETE FROM sessions
                    WHERE user_id = $1
                    "#,
                    user_id
                )
                .execute(self.pool)
                .await
            }
        }
        .map(|result| result.rows_affected())
    }
}

impl SessionRepo<'_> {
    /// Must run before any other mutation lock and in the mutation transaction.
    /// JWT/machine authority is admitted by its own policy; never implicitly
    /// give an internal interactive identity such authority when its capture is absent.
    pub async fn guard_identity_in(
        conn: &mut sqlx_postgres::PgConnection,
        identity: &zann_core::Identity,
    ) -> Result<(), SessionWriteError> {
        if !identity.source.is_internal_interactive() {
            return Ok(());
        }
        let authority = identity
            .session_authority
            .as_ref()
            .ok_or(SessionWriteError::Invalidated)?;
        epoch::lock_account(conn, identity.user_id, authority.auth_epoch).await?;
        let row=sqlx_core::query::query::<sqlx_postgres::Postgres>("SELECT s.id FROM sessions s JOIN devices d ON d.id=s.device_id AND d.user_id=s.user_id LEFT JOIN account_passkeys p ON p.credential_id=s.passkey_credential_id WHERE s.id=$1 AND s.user_id=$2 AND s.auth_epoch=$3 AND s.device_id=$4 AND s.access_expires_at>CURRENT_TIMESTAMP AND d.revoked_at IS NULL AND (s.passkey_credential_id IS NULL OR p.session_epoch=s.passkey_session_epoch)")
            .bind(authority.session_id).bind(identity.user_id).bind(authority.auth_epoch).bind(identity.device_id).fetch_optional(conn).await?;
        if row.is_none() {
            return Err(SessionWriteError::Invalidated);
        }
        Ok(())
    }
}
impl SessionRepo<'_> {
    pub async fn invalidate_user_in(
        conn: &mut sqlx_postgres::PgConnection,
        user: Uuid,
        keep: Option<Uuid>,
    ) -> Result<(), sqlx_core::Error> {
        epoch::invalidate_user_in(conn, user, keep).await
    }
}
impl SessionRepo<'_> {
    /// The verified password/KDF snapshot must still be the active verifier at
    /// issuance, including when password-only login was just disabled without
    /// logging out the account's already-authorized devices.
    pub async fn guard_password_in(
        conn: &mut sqlx_postgres::PgConnection,
        user: &User,
    ) -> Result<(), SessionWriteError> {
        epoch::lock_account(conn, user.id, user.auth_epoch).await?;
        let hash = user
            .password_hash
            .as_deref()
            .ok_or(SessionWriteError::Invalidated)?;
        let row=sqlx_core::query::query::<sqlx_postgres::Postgres>("SELECT id FROM users WHERE id=$1 AND password_hash=$2 AND kdf_salt=$3 AND kdf_algorithm=$4 AND kdf_iterations=$5 AND kdf_memory_kb=$6 AND kdf_parallelism=$7")
            .bind(user.id).bind(hash).bind(&user.kdf_salt).bind(&user.kdf_algorithm).bind(user.kdf_iterations).bind(user.kdf_memory_kb).bind(user.kdf_parallelism).fetch_optional(conn).await?;
        if row.is_none() {
            return Err(SessionWriteError::Invalidated);
        }
        Ok(())
    }
}
