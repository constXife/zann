use super::prelude::*;
use sqlx_core::transaction::Transaction;
use sqlx_postgres::PgRow;
use sqlx_postgres::Postgres;
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
        if let Some(matches) = self.existing_generation_matches(change).await? {
            return if matches {
                Ok(())
            } else {
                Err(conflicting_generation_error())
            };
        }

        let result = query!(
            r#"
            INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (item_id, version) DO NOTHING
            "#,
            change.vault_id,
            change.item_id,
            change.op.as_i32(),
            change.version,
            change.device_id,
            change.created_at
        )
        .execute(self.pool)
        .await?;
        Span::current().record("db.rows", result.rows_affected() as i64);
        if result.rows_affected() == 1 {
            return Ok(());
        }

        match self.existing_generation_matches(change).await? {
            Some(true) => Ok(()),
            Some(false) | None => Err(conflicting_generation_error()),
        }
    }

    pub async fn create_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        change: &Change,
    ) -> Result<(), sqlx_core::Error> {
        if let Some(matches) = self.existing_generation_matches_in(tx, change).await? {
            return if matches {
                Ok(())
            } else {
                Err(conflicting_generation_error())
            };
        }

        let result = query!(
            r#"
            INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (item_id, version) DO NOTHING
            "#,
            change.vault_id,
            change.item_id,
            change.op.as_i32(),
            change.version,
            change.device_id,
            change.created_at
        )
        .execute(&mut **tx)
        .await?;
        Span::current().record("db.rows", result.rows_affected() as i64);
        if result.rows_affected() == 1 {
            return Ok(());
        }

        match self.existing_generation_matches_in(tx, change).await? {
            Some(true) => Ok(()),
            Some(false) | None => Err(conflicting_generation_error()),
        }
    }

    async fn existing_generation_matches(
        &self,
        change: &Change,
    ) -> Result<Option<bool>, sqlx_core::Error> {
        let row: Option<PgRow> = query!(
            r#"
            SELECT (
                vault_id IS NOT DISTINCT FROM $3
                AND op IS NOT DISTINCT FROM $4
                AND device_id IS NOT DISTINCT FROM $5
                AND created_at IS NOT DISTINCT FROM $6
            ) AS matches
            FROM changes
            WHERE item_id = $1 AND version = $2
            "#,
            change.item_id,
            change.version,
            change.vault_id,
            change.op.as_i32() as i16,
            change.device_id,
            change.created_at
        )
        .fetch_optional(self.pool)
        .await?;
        row.map(|row| row.try_get::<bool, _>("matches")).transpose()
    }

    async fn existing_generation_matches_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        change: &Change,
    ) -> Result<Option<bool>, sqlx_core::Error> {
        let row: Option<PgRow> = query!(
            r#"
            SELECT (
                vault_id IS NOT DISTINCT FROM $3
                AND op IS NOT DISTINCT FROM $4
                AND device_id IS NOT DISTINCT FROM $5
                AND created_at IS NOT DISTINCT FROM $6
            ) AS matches
            FROM changes
            WHERE item_id = $1 AND version = $2
            "#,
            change.item_id,
            change.version,
            change.vault_id,
            change.op.as_i32() as i16,
            change.device_id,
            change.created_at
        )
        .fetch_optional(&mut **tx)
        .await?;
        row.map(|row| row.try_get::<bool, _>("matches")).transpose()
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

fn conflicting_generation_error() -> sqlx_core::Error {
    sqlx_core::Error::Protocol("conflicting change generation semantics".to_string())
}
