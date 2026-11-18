use super::*;

impl VaultRepo<'_> {
    pub async fn update_key_by_id_in<'e, E>(
        executor: E,
        id: Uuid,
        vault_key_enc: &[u8],
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            UPDATE vaults
            SET vault_key_enc = $2,
                row_version = row_version + 1
            WHERE id = $1
              AND deleted_at IS NULL
              AND octet_length(vault_key_enc) = 0
            "#,
            id,
            vault_key_enc
        )
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
    }
    pub async fn delete_by_id_in<'e, E>(
        executor: E,
        id: Uuid,
        row_version: i64,
        deleted_at: DateTime<Utc>,
        deleted_by_user_id: Uuid,
        deleted_by_device_id: Option<Uuid>,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            r#"
            UPDATE vaults
            SET deleted_at = $3,
                deleted_by_user_id = $4,
                deleted_by_device_id = $5,
                row_version = row_version + 1
            WHERE id = $1 AND row_version = $2
            "#,
            id,
            row_version,
            deleted_at,
            deleted_by_user_id,
            deleted_by_device_id
        )
        .execute(executor)
        .await
        .map(|result| {
            let rows = result.rows_affected();
            Span::current().record("db.rows", rows as i64);
            rows
        })
    }
}

impl VaultRepo<'_> {
    pub async fn get_personal_by_user_in<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<Option<Vault>, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query_as!(
            Vault,
            r#"
            SELECT
                v.id as "id",
                v.slug,
                v.name,
                v.kind as "kind",
                v.encryption_type as "encryption_type",
                v.vault_key_enc,
                v.cache_policy as "cache_policy",
                v.tags as "tags",
                v.deleted_at as "deleted_at",
                v.deleted_by_user_id as "deleted_by_user_id",
                v.deleted_by_device_id as "deleted_by_device_id",
                v.row_version as "row_version",
                v.created_at as "created_at"
            FROM vaults v
            INNER JOIN vault_members vm ON vm.vault_id = v.id
            WHERE vm.user_id = $1 AND v.kind = $2 AND v.deleted_at IS NULL
            ORDER BY v.created_at ASC
            LIMIT 1
            "#,
            user_id,
            zann_core::VaultKind::Personal.as_i32()
        )
        .fetch_optional(executor)
        .await
    }
}

impl VaultMemberRepo<'_> {
    pub async fn get_in<'e, E>(
        executor: E,
        vault_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<VaultMember>, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query_as!(
            VaultMember,
            r#"
            SELECT
                vault_id as "vault_id",
                user_id as "user_id",
                role as "role",
                created_at as "created_at"
            FROM vault_members
            WHERE vault_id = $1 AND user_id = $2
            "#,
            vault_id,
            user_id
        )
        .fetch_optional(executor)
        .await
    }
}
