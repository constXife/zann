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
                s.access_token_hash,
                s.access_expires_at as "access_expires_at",
                s.refresh_token_hash,
                s.expires_at as "expires_at",
                s.created_at as "created_at"
            FROM sessions s
            JOIN devices d ON d.id = s.device_id AND d.user_id = s.user_id
            JOIN users u ON u.id = s.user_id AND u.auth_epoch = s.auth_epoch
            WHERE s.refresh_token_hash = $1
              AND d.revoked_at IS NULL
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
                s.access_token_hash,
                s.access_expires_at as "access_expires_at",
                s.refresh_token_hash,
                s.expires_at as "expires_at",
                s.created_at as "created_at"
            FROM sessions s
            JOIN devices d ON d.id = s.device_id AND d.user_id = s.user_id
            JOIN users u ON u.id = s.user_id AND u.auth_epoch = s.auth_epoch
            WHERE s.access_token_hash = $1
              AND d.revoked_at IS NULL
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
