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
                id as "id",
                user_id as "user_id",
                device_id as "device_id",
                access_token_hash,
                access_expires_at as "access_expires_at",
                refresh_token_hash,
                expires_at as "expires_at",
                created_at as "created_at"
            FROM sessions
            WHERE refresh_token_hash = $1
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
                id as "id",
                user_id as "user_id",
                device_id as "device_id",
                access_token_hash,
                access_expires_at as "access_expires_at",
                refresh_token_hash,
                expires_at as "expires_at",
                created_at as "created_at"
            FROM sessions
            WHERE access_token_hash = $1
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
            ()
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
            ()
        })
    }
}

pub struct AppliedOpRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> AppliedOpRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    #[instrument(
        level = "debug",
        skip(self, op),
        fields(op_id = %op.op_id, db.system = "postgresql", db.operation = "INSERT", db.query = "applied_ops.create")
    )]
    pub async fn create(&self, op: &AppliedOp) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO applied_ops (op_id, device_id, vault_id, item_id, applied_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            op.op_id,
            op.device_id,
            op.vault_id,
            op.item_id,
            op.applied_at
        )
        .execute(self.pool)
        .await
        .map(|result| {
            Span::current().record("db.rows", result.rows_affected() as i64);
            ()
        })
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(op_id = %op_id, db.system = "postgresql", db.operation = "SELECT", db.query = "applied_ops.get_by_id")
    )]
    pub async fn get_by_id(&self, op_id: Uuid) -> Result<Option<AppliedOp>, sqlx_core::Error> {
        query_as!(
            AppliedOp,
            r#"
            SELECT
                op_id as "op_id",
                device_id as "device_id",
                vault_id as "vault_id",
                item_id as "item_id",
                applied_at as "applied_at"
            FROM applied_ops
            WHERE op_id = $1
            "#,
            op_id
        )
        .fetch_optional(self.pool)
        .await
    }
}

pub struct InviteRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> InviteRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, invite: &Invite) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO invites (id, vault_id, token_hash, role, uses_left, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            invite.id,
            invite.vault_id,
            invite.token_hash.as_str(),
            invite.role.as_str(),
            invite.uses_left,
            invite.expires_at,
            invite.created_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<Invite>, sqlx_core::Error> {
        query_as!(
            Invite,
            r#"
            SELECT
                id as "id",
                vault_id as "vault_id",
                token_hash,
                role as "role",
                uses_left as "uses_left",
                expires_at as "expires_at",
                created_at as "created_at"
            FROM invites
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn get_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Invite>, sqlx_core::Error> {
        query_as!(
            Invite,
            r#"
            SELECT
                id as "id",
                vault_id as "vault_id",
                token_hash,
                role as "role",
                uses_left as "uses_left",
                expires_at as "expires_at",
                created_at as "created_at"
            FROM invites
            WHERE token_hash = $1
            "#,
            token_hash
        )
        .fetch_optional(self.pool)
        .await
    }
}
