//! Bounded backup reads share the caller's snapshot; no plaintext lives here.
use super::prelude::*;
use sqlx_postgres::PgConnection;

pub struct ServerBackupRepo;

impl ServerBackupRepo {
    pub const PAGE_SIZE: i64 = 32;

    pub async fn vault_page(
        connection: &mut PgConnection,
        after: Option<Uuid>,
    ) -> Result<Vec<Vault>, sqlx_core::Error> {
        Self::check_vault_bounds(connection, None, None, after).await?;
        query_as!(
            Vault,
            "SELECT * FROM vaults WHERE kind=2 AND encryption_type=2 AND deleted_at IS NULL
             AND ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT $2",
            after,
            Self::PAGE_SIZE
        )
        .fetch_all(connection)
        .await
    }

    pub async fn vault(
        connection: &mut PgConnection,
        selector: &str,
    ) -> Result<Option<Vault>, sqlx_core::Error> {
        Self::check_vault_bounds(
            connection,
            selector.parse::<Uuid>().ok(),
            Some(selector),
            None,
        )
        .await?;
        query_as!(Vault,
            "SELECT * FROM vaults WHERE (CASE WHEN $1::uuid IS NOT NULL THEN id=$1 ELSE slug=$2 END) AND deleted_at IS NULL",
            selector.parse::<Uuid>().ok(), selector).fetch_optional(connection).await
    }

    pub async fn target_vault(
        connection: &mut PgConnection,
        slug: &str,
    ) -> Result<Option<Vault>, sqlx_core::Error> {
        Self::check_vault_bounds(connection, None, Some(slug), None).await?;
        query_as!(Vault, "SELECT * FROM vaults WHERE slug=$1 FOR UPDATE", slug)
            .fetch_optional(connection)
            .await
    }

    pub async fn owner(
        connection: &mut PgConnection,
        email: &str,
    ) -> Result<Option<Uuid>, sqlx_core::Error> {
        query!(
            "SELECT id FROM users WHERE email=$1 AND status=1 AND deleted_at IS NULL FOR SHARE",
            email
        )
        .fetch_optional(connection)
        .await?
        .map(|row| row.try_get("id"))
        .transpose()
    }

    async fn check_vault_bounds(
        connection: &mut PgConnection,
        id: Option<Uuid>,
        slug: Option<&str>,
        after: Option<Uuid>,
    ) -> Result<(), sqlx_core::Error> {
        let row=query!("SELECT COALESCE(bool_and(valid),true) AS valid FROM (
            SELECT octet_length(slug) BETWEEN 1 AND 128 AND octet_length(name) BETWEEN 1 AND 200
             AND octet_length(vault_key_enc) BETWEEN 0 AND 65536 AND COALESCE(octet_length(tags::text),0)<=65536 AS valid
            FROM vaults WHERE CASE WHEN $1::uuid IS NOT NULL THEN id=$1
              WHEN $2::text IS NOT NULL THEN slug=$2
              ELSE kind=2 AND encryption_type=2 AND deleted_at IS NULL AND ($3::uuid IS NULL OR id>$3) END
            ORDER BY id LIMIT $4) AS page",id,slug,after,Self::PAGE_SIZE).fetch_one(connection).await?;
        if !row.try_get::<bool, _>("valid")? {
            return Err(sqlx_core::Error::Protocol(
                "backup source vault exceeds byte limits".into(),
            ));
        }
        Ok(())
    }

    pub async fn item_count(
        connection: &mut PgConnection,
        vault: Uuid,
        deleted: bool,
    ) -> Result<i64, sqlx_core::Error> {
        let row = query!("SELECT COUNT(*)::bigint AS count FROM items WHERE vault_id=$1 AND ($2 OR sync_status=1)", vault, deleted)
            .fetch_one(connection).await?;
        row.try_get("count")
    }

    pub async fn item_page(
        connection: &mut PgConnection,
        vault: Uuid,
        deleted: bool,
        after: Option<Uuid>,
    ) -> Result<Vec<Item>, sqlx_core::Error> {
        let row=query!("SELECT COALESCE(bool_and(valid),true) AS valid FROM (
            SELECT octet_length(payload_enc) BETWEEN 1 AND 262400 AND octet_length(path) BETWEEN 1 AND 500
              AND octet_length(name) BETWEEN 1 AND 200 AND octet_length(type_id) BETWEEN 1 AND 128
              AND octet_length(checksum)=64 AND COALESCE(octet_length(tags::text),0)<=65536 AS valid
            FROM items WHERE vault_id=$1 AND ($2 OR sync_status=1) AND ($3::uuid IS NULL OR id>$3)
            ORDER BY id LIMIT $4) AS page",vault,deleted,after,Self::PAGE_SIZE).fetch_one(&mut *connection).await?;
        if !row.try_get::<bool, _>("valid")? {
            return Err(sqlx_core::Error::Protocol(
                "backup source item exceeds byte limits".into(),
            ));
        }
        query_as!(
            Item,
            "SELECT id,vault_id,path,name,type_id,tags,favorite,payload_enc,checksum,version,row_version,
             device_id,sync_status,deleted_at,deleted_by_user_id,deleted_by_device_id,created_at,updated_at
             FROM items WHERE vault_id=$1 AND ($2 OR sync_status=1)
             AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4",
            vault,
            deleted,
            after,
            Self::PAGE_SIZE
        )
        .fetch_all(connection)
        .await
    }
}
