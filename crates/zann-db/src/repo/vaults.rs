use super::prelude::*;
use sqlx_core::types::Json as SqlxJson;
use tracing::{instrument, Span};

#[derive(Debug)]
pub struct VaultCatalogEntry {
    pub id: Uuid,
    pub slug: Option<String>,
    pub name: Option<String>,
    pub cache_policy: i16,
    pub tags: Option<SqlxJson<Vec<String>>>,
}

#[derive(Debug)]
pub struct VaultKeyMaterialEntry {
    pub id: Uuid,
    pub vault_key_enc: Option<Vec<u8>>,
}

impl<'row> sqlx_core::from_row::FromRow<'row, sqlx_postgres::PgRow> for VaultCatalogEntry {
    fn from_row(row: &'row sqlx_postgres::PgRow) -> Result<Self, sqlx_core::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            slug: row.try_get("slug")?,
            name: row.try_get("name")?,
            cache_policy: row.try_get("cache_policy")?,
            tags: row.try_get("tags")?,
        })
    }
}

impl<'row> sqlx_core::from_row::FromRow<'row, sqlx_postgres::PgRow> for VaultKeyMaterialEntry {
    fn from_row(row: &'row sqlx_postgres::PgRow) -> Result<Self, sqlx_core::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            vault_key_enc: row.try_get("vault_key_enc")?,
        })
    }
}

#[derive(Debug, Default)]
pub struct VaultCatalogScopeFilter {
    pub vault_ids: Vec<Uuid>,
    pub vault_slugs: Vec<String>,
    pub tags: Vec<String>,
    /// SQL LIKE patterns whose only wildcard was derived from the scope `*`.
    pub slug_patterns: Vec<String>,
}

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

    #[instrument(
        level = "debug",
        skip(self, filter),
        fields(limit, db.system = "postgresql", db.operation = "SELECT", db.query = "vaults.list_service_account_catalog")
    )]
    pub async fn list_service_account_catalog(
        &self,
        filter: &VaultCatalogScopeFilter,
        limit: i64,
    ) -> Result<Vec<VaultCatalogEntry>, sqlx_core::Error> {
        let vaults = query_as!(
            VaultCatalogEntry,
            r#"
            SELECT
                v.id,
                CASE
                    WHEN octet_length(v.slug) BETWEEN 1 AND 128
                     AND v.slug = btrim(v.slug)
                     AND v.slug !~ '[^A-Za-z0-9_-]'
                    THEN v.slug
                END AS slug,
                CASE
                    WHEN octet_length(v.name) BETWEEN 1 AND 200
                     AND v.name = btrim(v.name)
                     AND v.name !~ '^[[:space:]]'
                     AND v.name !~ '[[:space:]]$'
                    THEN v.name
                END AS name,
                v.cache_policy,
                CASE
                    WHEN octet_length(v.tags::text) <= 65536
                    THEN v.tags
                END AS tags
            FROM vaults AS v
            WHERE v.deleted_at IS NULL
              AND v.kind = $1
              AND v.encryption_type = $2
              AND (
                    v.id = ANY($3::uuid[])
                    OR v.slug COLLATE "C" = ANY($4::text[])
                    OR v.tags ?| $5::text[]
                    OR EXISTS (
                        SELECT 1
                        FROM unnest($6::text[]) AS allowed(pattern)
                        WHERE v.slug COLLATE "C" LIKE allowed.pattern COLLATE "C" ESCAPE '\'
                    )
              )
            ORDER BY v.created_at ASC, v.id ASC
            LIMIT $7
            "#,
            zann_core::VaultKind::Shared.as_i32(),
            zann_core::VaultEncryptionType::Server.as_i32(),
            &filter.vault_ids,
            &filter.vault_slugs,
            &filter.tags,
            &filter.slug_patterns,
            limit
        )
        .fetch_all(self.pool)
        .await?;
        Span::current().record("db.rows", vaults.len() as i64);
        Ok(vaults)
    }

    #[instrument(
        level = "debug",
        skip(self, filter),
        fields(limit, db.system = "postgresql", db.operation = "SELECT", db.query = "vaults.list_service_account_key_material")
    )]
    pub async fn list_service_account_key_material(
        &self,
        filter: &VaultCatalogScopeFilter,
        limit: i64,
    ) -> Result<Vec<VaultKeyMaterialEntry>, sqlx_core::Error> {
        let vaults = query_as!(
            VaultKeyMaterialEntry,
            r#"
            SELECT
                v.id,
                CASE
                    WHEN octet_length(v.vault_key_enc) BETWEEN 1 AND 65536
                    THEN v.vault_key_enc
                END AS vault_key_enc
            FROM vaults AS v
            WHERE v.deleted_at IS NULL
              AND v.kind = $1
              AND v.encryption_type = $2
              AND (
                    v.id = ANY($3::uuid[])
                    OR v.slug COLLATE "C" = ANY($4::text[])
                    OR v.tags ?| $5::text[]
                    OR EXISTS (
                        SELECT 1
                        FROM unnest($6::text[]) AS allowed(pattern)
                        WHERE v.slug COLLATE "C" LIKE allowed.pattern COLLATE "C" ESCAPE '\'
                    )
              )
            ORDER BY v.created_at ASC, v.id ASC
            LIMIT $7
            "#,
            zann_core::VaultKind::Shared.as_i32(),
            zann_core::VaultEncryptionType::Server.as_i32(),
            &filter.vault_ids,
            &filter.vault_slugs,
            &filter.tags,
            &filter.slug_patterns,
            limit
        )
        .fetch_all(self.pool)
        .await?;
        Span::current().record("db.rows", vaults.len() as i64);
        Ok(vaults)
    }

    #[instrument(
        level = "debug",
        skip(self),
        fields(limit, db.system = "postgresql", db.operation = "SELECT", db.query = "vaults.list_shared_server_bounded")
    )]
    pub async fn list_shared_server_bounded(
        &self,
        limit: i64,
    ) -> Result<Vec<Vault>, sqlx_core::Error> {
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
              AND kind = $1
              AND encryption_type = $2
              AND octet_length(slug) BETWEEN 1 AND 128
              AND octet_length(name) BETWEEN 1 AND 200
              AND octet_length(vault_key_enc) BETWEEN 1 AND 65536
              AND octet_length(tags::text) <= 65536
            ORDER BY created_at ASC, id ASC
            LIMIT $3
            "#,
            zann_core::VaultKind::Shared.as_i32(),
            zann_core::VaultEncryptionType::Server.as_i32(),
            limit
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
            WHERE id = $1
              AND deleted_at IS NULL
              AND octet_length(vault_key_enc) = 0
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
