use super::prelude::*;

pub struct DeviceRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> DeviceRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, device: &Device) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO devices (
                id, user_id, name, fingerprint, os, os_version, app_version,
                last_seen_at, last_ip, revoked_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            device.id,
            device.user_id,
            device.name.as_str(),
            device.fingerprint.as_str(),
            device.os.as_deref(),
            device.os_version.as_deref(),
            device.app_version.as_deref(),
            device.last_seen_at,
            device.last_ip.as_deref(),
            device.revoked_at,
            device.created_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<Device>, sqlx_core::Error> {
        query_as!(
            Device,
            r#"
            SELECT
                id as "id",
                user_id as "user_id",
                name,
                fingerprint,
                os,
                os_version,
                app_version,
                last_seen_at as "last_seen_at",
                last_ip,
                revoked_at as "revoked_at",
                created_at as "created_at"
            FROM devices
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn list_by_user(
        &self,
        user_id: Uuid,
        limit: i64,
        offset: i64,
        sort: &str,
    ) -> Result<Vec<Device>, sqlx_core::Error> {
        let order_by = if sort.eq_ignore_ascii_case("asc") {
            "ASC"
        } else {
            "DESC"
        };
        let query = format!(
            r#"
            SELECT
                id as "id",
                user_id as "user_id",
                name,
                fingerprint,
                os,
                os_version,
                app_version,
                last_seen_at as "last_seen_at",
                last_ip,
                revoked_at as "revoked_at",
                created_at as "created_at"
            FROM devices
            WHERE user_id = $1
            ORDER BY created_at {}
            LIMIT $2 OFFSET $3
            "#,
            order_by
        );
        query_as!(Device, &query, user_id, limit, offset)
            .fetch_all(self.pool)
            .await
    }

    pub async fn revoke(
        &self,
        device_id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE devices
            SET revoked_at = $2
            WHERE id = $1
            "#,
            device_id,
            revoked_at
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}

pub struct ServiceAccountRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> ServiceAccountRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, account: &ServiceAccount) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO service_accounts (
                id, owner_user_id, name, description, token_hash, token_prefix, scopes,
                allowed_ips, expires_at, last_used_at, last_used_ip, last_used_user_agent, use_count, created_at, revoked_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            "#,
            account.id,
            account.owner_user_id,
            account.name.as_str(),
            account.description.as_deref(),
            account.token_hash.as_str(),
            account.token_prefix.as_str(),
            &account.scopes,
            account.allowed_ips.as_ref(),
            account.expires_at,
            account.last_used_at,
            account.last_used_ip.as_deref(),
            account.last_used_user_agent.as_deref(),
            account.use_count,
            account.created_at,
            account.revoked_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<ServiceAccount>, sqlx_core::Error> {
        query_as!(
            ServiceAccount,
            r#"
            SELECT
                id as "id",
                owner_user_id as "owner_user_id",
                name,
                description,
                token_hash,
                token_prefix,
                scopes as "scopes",
                allowed_ips as "allowed_ips",
                expires_at as "expires_at",
                last_used_at as "last_used_at",
                last_used_ip as "last_used_ip",
                last_used_user_agent as "last_used_user_agent",
                use_count as "use_count",
                created_at as "created_at",
                revoked_at as "revoked_at"
            FROM service_accounts
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn list_by_owner(
        &self,
        owner_user_id: Uuid,
        limit: i64,
        offset: i64,
        sort: &str,
    ) -> Result<Vec<ServiceAccount>, sqlx_core::Error> {
        let order_by = if sort.eq_ignore_ascii_case("asc") {
            "ASC"
        } else {
            "DESC"
        };
        let query = format!(
            r#"
            SELECT
                id as "id",
                owner_user_id as "owner_user_id",
                name,
                description,
                token_hash,
                token_prefix,
                scopes as "scopes",
                allowed_ips as "allowed_ips",
                expires_at as "expires_at",
                last_used_at as "last_used_at",
                last_used_ip as "last_used_ip",
                last_used_user_agent as "last_used_user_agent",
                use_count as "use_count",
                created_at as "created_at",
                revoked_at as "revoked_at"
            FROM service_accounts
            WHERE owner_user_id = $1
            ORDER BY created_at {}
            LIMIT $2 OFFSET $3
            "#,
            order_by
        );
        query_as!(ServiceAccount, &query, owner_user_id, limit, offset)
            .fetch_all(self.pool)
            .await
    }

    pub async fn list_by_prefix(
        &self,
        token_prefix: &str,
    ) -> Result<Vec<ServiceAccount>, sqlx_core::Error> {
        query_as!(
            ServiceAccount,
            r#"
            SELECT
                id as "id",
                owner_user_id as "owner_user_id",
                name,
                description,
                token_hash,
                token_prefix,
                scopes as "scopes",
                allowed_ips as "allowed_ips",
                expires_at as "expires_at",
                last_used_at as "last_used_at",
                last_used_ip as "last_used_ip",
                last_used_user_agent as "last_used_user_agent",
                use_count as "use_count",
                created_at as "created_at",
                revoked_at as "revoked_at"
            FROM service_accounts
            WHERE token_prefix = $1
            "#,
            token_prefix
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn update_usage(
        &self,
        id: Uuid,
        last_used_at: DateTime<Utc>,
        last_used_ip: Option<&str>,
        last_used_user_agent: Option<&str>,
        increment: i64,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE service_accounts
            SET last_used_at = $2,
                last_used_ip = $3,
                last_used_user_agent = $4,
                use_count = use_count + $5
            WHERE id = $1
            "#,
            id,
            last_used_at,
            last_used_ip,
            last_used_user_agent,
            increment
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn update_token(
        &self,
        id: Uuid,
        token_hash: &str,
        token_prefix: &str,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE service_accounts
            SET token_hash = $2,
                token_prefix = $3
            WHERE id = $1
            "#,
            id,
            token_hash,
            token_prefix
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn update(&self, account: &ServiceAccount) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE service_accounts
            SET name = $2,
                description = $3,
                token_hash = $4,
                token_prefix = $5,
                scopes = $6,
                allowed_ips = $7,
                expires_at = $8,
                last_used_at = $9,
                last_used_ip = $10,
                last_used_user_agent = $11,
                use_count = $12,
                revoked_at = $13
            WHERE id = $1
            "#,
            account.id,
            account.name.as_str(),
            account.description.as_deref(),
            account.token_hash.as_str(),
            account.token_prefix.as_str(),
            &account.scopes,
            account.allowed_ips.as_ref(),
            account.expires_at,
            account.last_used_at,
            account.last_used_ip.as_deref(),
            account.last_used_user_agent.as_deref(),
            account.use_count,
            account.revoked_at
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }

    pub async fn revoke(
        &self,
        id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE service_accounts
            SET revoked_at = $2
            WHERE id = $1
            "#,
            id,
            revoked_at
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}

pub struct ServiceAccountSessionRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> ServiceAccountSessionRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, session: &ServiceAccountSession) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO service_account_sessions (
                id, service_account_id, access_token_hash, expires_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5)
            "#,
            session.id,
            session.service_account_id,
            session.access_token_hash.as_str(),
            session.expires_at,
            session.created_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get_by_access_token_hash(
        &self,
        access_token_hash: &str,
    ) -> Result<Option<ServiceAccountSession>, sqlx_core::Error> {
        query_as!(
            ServiceAccountSession,
            r#"
            SELECT
                id as "id",
                service_account_id as "service_account_id",
                access_token_hash,
                expires_at as "expires_at",
                created_at as "created_at"
            FROM service_account_sessions
            WHERE access_token_hash = $1
            "#,
            access_token_hash
        )
        .fetch_optional(self.pool)
        .await
    }

    pub async fn revoke_by_service_account(
        &self,
        service_account_id: Uuid,
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            DELETE FROM service_account_sessions
            WHERE service_account_id = $1
            "#,
            service_account_id
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}
