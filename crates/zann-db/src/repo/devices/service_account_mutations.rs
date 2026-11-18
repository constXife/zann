//! Transactional service-account and service-session mutations.
use super::*;
impl ServiceAccountRepo<'_> {
    pub async fn create_in<'e, E>(
        executor: E,
        account: &ServiceAccount,
    ) -> Result<(), sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
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
            sqlx_core::types::Json(&account.scopes),
            account.allowed_ips.as_ref().map(sqlx_core::types::Json),
            account.expires_at,
            account.last_used_at,
            account.last_used_ip.as_deref(),
            account.last_used_user_agent.as_deref(),
            account.use_count,
            account.created_at,
            account.revoked_at
        )
        .execute(executor)
        .await
        .map(|_| ())
    }
    pub async fn update_token_in<'e, E>(
        executor: E,
        id: Uuid,
        token_hash: &str,
        token_prefix: &str,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
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
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
    pub async fn update_in<'e, E>(
        executor: E,
        account: &ServiceAccount,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
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
            sqlx_core::types::Json(&account.scopes),
            account.allowed_ips.as_ref().map(sqlx_core::types::Json),
            account.expires_at,
            account.last_used_at,
            account.last_used_ip.as_deref(),
            account.last_used_user_agent.as_deref(),
            account.use_count,
            account.revoked_at
        )
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
    pub async fn revoke_in<'e, E>(
        executor: E,
        id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            UPDATE service_accounts
            SET revoked_at = $2
            WHERE id = $1
            "#,
            id,
            revoked_at
        )
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
}

impl ServiceAccountSessionRepo<'_> {
    pub async fn revoke_by_service_account_in<'e, E>(
        executor: E,
        service_account_id: Uuid,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            DELETE FROM service_account_sessions
            WHERE service_account_id = $1
            "#,
            service_account_id
        )
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
}
