use super::prelude::*;
use tracing::{instrument, Span};

pub struct VaultRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> VaultRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    #[instrument(
        level = "debug",
        skip(self, vault),
        fields(
            vault_id = %vault.id,
            db.system = "postgresql",
            db.operation = "INSERT",
            db.query = "vaults.create"
        )
    )]
    pub async fn create(&self, vault: &Vault) -> Result<(), sqlx_core::Error> {
        let tags = vault
            .tags
            .clone()
            .unwrap_or_else(|| sqlx_core::types::Json(Vec::new()));
        query!(
            r#"
            INSERT INTO vaults (
                id, slug, name, kind, encryption_type, vault_key_enc, cache_policy, tags, deleted_at,
                deleted_by_user_id, deleted_by_device_id, row_version, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
            vault.id,
            vault.slug.as_str(),
            vault.name.as_str(),
            vault.kind.as_i32(),
            vault.encryption_type.as_i32(),
            &vault.vault_key_enc,
            vault.cache_policy.as_i32(),
            &tags,
            vault.deleted_at,
            vault.deleted_by_user_id,
            vault.deleted_by_device_id,
            vault.row_version,
            vault.created_at
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
        fields(vault_id = %id, db.system = "postgresql", db.operation = "SELECT", db.query = "vaults.get_by_id")
    )]
    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<Vault>, sqlx_core::Error> {
        query_as!(
            Vault,
            r#"
            SELECT
                id as "id",
                slug,
                name,
                kind as "kind",
                encryption_type as "encryption_type",
                vault_key_enc,
                cache_policy as "cache_policy",
                tags as "tags",
                deleted_at as "deleted_at",
                deleted_by_user_id as "deleted_by_user_id",
                deleted_by_device_id as "deleted_by_device_id",
                row_version as "row_version",
                created_at as "created_at"
            FROM vaults
            WHERE id = $1 AND deleted_at IS NULL
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(slug, db.system = "postgresql", db.operation = "SELECT", db.query = "vaults.get_by_slug")
    )]
    pub async fn get_by_slug(&self, slug: &str) -> Result<Option<Vault>, sqlx_core::Error> {
        query_as!(
            Vault,
            r#"
            SELECT
                id as "id",
                slug,
                name,
                kind as "kind",
                encryption_type as "encryption_type",
                vault_key_enc,
                cache_policy as "cache_policy",
                tags as "tags",
                deleted_at as "deleted_at",
                deleted_by_user_id as "deleted_by_user_id",
                deleted_by_device_id as "deleted_by_device_id",
                row_version as "row_version",
                created_at as "created_at"
            FROM vaults
            WHERE slug = $1 AND deleted_at IS NULL
            "#,
            slug
        )
        .fetch_optional(self.pool)
        .await
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(user_id = %user_id, limit, offset, sort, db.system = "postgresql", db.operation = "SELECT", db.query = "vaults.list_by_user")
    )]
    pub async fn list_by_user(
        &self,
        user_id: Uuid,
        limit: i64,
        offset: i64,
        sort: &str,
    ) -> Result<Vec<Vault>, sqlx_core::Error> {
        let order_by = if sort.eq_ignore_ascii_case("asc") {
            "ASC"
        } else {
            "DESC"
        };
        let query = format!(
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
            WHERE vm.user_id = $1 AND v.deleted_at IS NULL
            ORDER BY v.created_at {}
            LIMIT $2 OFFSET $3
            "#,
            order_by
        );
        let vaults = query_as!(Vault, &query, user_id, limit, offset)
            .fetch_all(self.pool)
            .await?;
        Span::current().record("db.rows", vaults.len() as i64);
        Ok(vaults)
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(user_id = %user_id, db.system = "postgresql", db.operation = "SELECT", db.query = "vaults.get_personal_by_user")
    )]
    pub async fn get_personal_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Option<Vault>, sqlx_core::Error> {
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
        .fetch_optional(self.pool)
        .await
    }

    #[instrument(level = "debug", skip(self), fields(db.system = "postgresql", db.operation = "SELECT", db.query = "vaults.list_all"))]
    pub async fn list_all(&self) -> Result<Vec<Vault>, sqlx_core::Error> {
        let vaults = query_as!(
            Vault,
            r#"
            SELECT
                id as "id",
                slug,
                name,
                kind as "kind",
                encryption_type as "encryption_type",
                vault_key_enc,
                cache_policy as "cache_policy",
                tags as "tags",
                deleted_at as "deleted_at",
                deleted_by_user_id as "deleted_by_user_id",
                deleted_by_device_id as "deleted_by_device_id",
                row_version as "row_version",
                created_at as "created_at"
            FROM vaults
            WHERE deleted_at IS NULL
            "#
        )
        .fetch_all(self.pool)
        .await?;
        Span::current().record("db.rows", vaults.len() as i64);
        Ok(vaults)
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(vault_id = %id, db.system = "postgresql", db.operation = "UPDATE", db.query = "vaults.delete_by_id")
    )]
    pub async fn delete_by_id(
        &self,
        id: Uuid,
        row_version: i64,
        deleted_at: DateTime<Utc>,
        deleted_by_user_id: Uuid,
        deleted_by_device_id: Option<Uuid>,
    ) -> Result<u64, sqlx_core::Error> {
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
        .execute(self.pool)
        .await
        .map(|result| {
            let rows = result.rows_affected();
            Span::current().record("db.rows", rows as i64);
            rows
        })
    }

    #[instrument(
        level = "debug",
        skip(self, vault_key_enc),
        fields(
            vault_id = %id,
            vault_key_len = vault_key_enc.len(),
            db.system = "postgresql",
            db.operation = "UPDATE",
            db.query = "vaults.update_key_by_id"
        )
    )]
    pub async fn update_key_by_id(
        &self,
        id: Uuid,
        vault_key_enc: &[u8],
    ) -> Result<u64, sqlx_core::Error> {
        query!(
            r#"
            UPDATE vaults
            SET vault_key_enc = $2,
                row_version = row_version + 1
            WHERE id = $1 AND deleted_at IS NULL
            "#,
            id,
            vault_key_enc
        )
        .execute(self.pool)
        .await
        .map(|result| result.rows_affected())
    }
}

pub struct VaultMemberRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> VaultMemberRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, member: &VaultMember) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO vault_members (vault_id, user_id, role, created_at)
            VALUES ($1, $2, $3, $4)
            "#,
            member.vault_id,
            member.user_id,
            member.role.as_i32(),
            member.created_at
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }

    pub async fn get(
        &self,
        vault_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<VaultMember>, sqlx_core::Error> {
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
        .fetch_optional(self.pool)
        .await
    }

    pub async fn list_by_vault(
        &self,
        vault_id: Uuid,
    ) -> Result<Vec<VaultMember>, sqlx_core::Error> {
        query_as!(
            VaultMember,
            r#"
            SELECT
                vault_id as "vault_id",
                user_id as "user_id",
                role as "role",
                created_at as "created_at"
            FROM vault_members
            WHERE vault_id = $1
            "#,
            vault_id
        )
        .fetch_all(self.pool)
        .await
    }

    pub async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<VaultMember>, sqlx_core::Error> {
        query_as!(
            VaultMember,
            r#"
            SELECT
                vault_id as "vault_id",
                user_id as "user_id",
                role as "role",
                created_at as "created_at"
            FROM vault_members
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(self.pool)
        .await
    }
}
