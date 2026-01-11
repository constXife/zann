use super::prelude::*;
use tracing::{instrument, Span};

pub struct ChangeRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> ChangeRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    #[instrument(
        level = "debug",
        skip(self, change),
        fields(
            vault_id = %change.vault_id,
            item_id = %change.item_id,
            db.system = "postgresql",
            db.operation = "INSERT",
            db.query = "changes.create"
        )
    )]
    pub async fn create(&self, change: &Change) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            change.vault_id,
            change.item_id,
            change.op.as_str(),
            change.version,
            change.device_id,
            change.created_at
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
        fields(vault_id = %vault_id, since_seq, db.system = "postgresql", db.operation = "SELECT", db.query = "changes.list_since_seq")
    )]
    pub async fn list_since_seq(
        &self,
        vault_id: Uuid,
        since_seq: i64,
    ) -> Result<Vec<Change>, sqlx_core::Error> {
        query_as!(
            Change,
            r#"
            SELECT
                seq as "seq",
                vault_id as "vault_id",
                item_id as "item_id",
                op as "op",
                version as "version",
                device_id as "device_id",
                created_at as "created_at"
            FROM changes
            WHERE vault_id = $1 AND seq > $2
            ORDER BY seq ASC
            "#,
            vault_id,
            since_seq
        )
        .fetch_all(self.pool)
        .await
        .inspect(|changes| {
            Span::current().record("db.rows", changes.len() as i64);
        })
    }

    #[instrument(level = "debug", skip(self), fields(vault_id = %vault_id, db.system = "postgresql", db.operation = "SELECT", db.query = "changes.last_seq_for_vault"))]
    pub async fn last_seq_for_vault(&self, vault_id: Uuid) -> Result<i64, sqlx_core::Error> {
        let row = query!(
            r#"
            SELECT MAX(seq) as seq
            FROM changes
            WHERE vault_id = $1
            "#,
            vault_id
        )
        .fetch_one(self.pool)
        .await?;
        let seq: Option<i64> = row.try_get("seq")?;
        Ok(seq.unwrap_or(0))
    }
}
