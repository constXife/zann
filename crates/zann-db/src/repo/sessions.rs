use super::prelude::*;
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
        skip(self, session),
        fields(
            session_id = %session.id,
            user_id = %session.user_id,
            db.system = "postgresql",
            db.operation = "INSERT",
            db.query = "sessions.create"
        )
    )]
    pub async fn create(&self, session: &Session) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO sessions (
                id, user_id, device_id, access_token_hash, access_expires_at,
                refresh_token_hash, expires_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            session.id,
            session.user_id,
            session.device_id,
            session.access_token_hash.as_str(),
            session.access_expires_at,
            session.refresh_token_hash.as_str(),
            session.expires_at,
            session.created_at
        )
        .execute(self.pool)
        .await
        .map(|result| {
            Span::current().record("db.rows", result.rows_affected() as i64);
        })
    }

    #[instrument(
        level = "debug",
        skip(self),
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
        skip(self),
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
        skip(self),
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
                s.access_token_hash,
                s.access_expires_at as "access_expires_at",
                s.refresh_token_hash,
                s.expires_at as "expires_at",
                s.created_at as "created_at"
            FROM sessions s
            JOIN devices d ON d.id = s.device_id
            WHERE s.refresh_token_hash = $1
              AND d.revoked_at IS NULL
            "#,
            refresh_token_hash
        )
        .fetch_optional(self.pool)
        .await
    }

    #[instrument(
        level = "debug",
        skip(self),
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
                s.access_token_hash,
                s.access_expires_at as "access_expires_at",
                s.refresh_token_hash,
                s.expires_at as "expires_at",
                s.created_at as "created_at"
            FROM sessions s
            JOIN devices d ON d.id = s.device_id
            WHERE s.access_token_hash = $1
              AND d.revoked_at IS NULL
            "#,
            access_token_hash
        )
        .fetch_optional(self.pool)
        .await
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(session_id = %session_id, db.system = "postgresql", db.operation = "UPDATE", db.query = "sessions.update_refresh_token")
    )]
    pub async fn update_refresh_token(
        &self,
        session_id: Uuid,
        access_token_hash: &str,
        access_expires_at: DateTime<Utc>,
        refresh_token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            UPDATE sessions
            SET
                access_token_hash = $2,
                access_expires_at = $3,
                refresh_token_hash = $4,
                expires_at = $5
            WHERE id = $1
            "#,
            session_id,
            access_token_hash,
            access_expires_at,
            refresh_token_hash,
            expires_at
        )
        .execute(self.pool)
        .await
        .map(|result| {
            Span::current().record("db.rows", result.rows_affected() as i64);
        })
    }

    #[instrument(
        level = "debug",
        skip(self),
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
        skip(self),
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
        skip(self),
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
