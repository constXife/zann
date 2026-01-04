use sqlx_core::row::Row;

use crate::SqlitePool;

pub struct MetadataRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> MetadataRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get_value(&self, key: &str) -> Result<Option<String>, sqlx_core::Error> {
        let row = query!(
            r#"
            SELECT value
            FROM metadata
            WHERE key = ?1
            "#,
            key
        )
        .fetch_optional(self.pool)
        .await?;
        match row {
            Some(row) => Ok(Some(row.try_get::<String, _>("value")?)),
            None => Ok(None),
        }
    }

    pub async fn set_value(&self, key: &str, value: &str) -> Result<(), sqlx_core::Error> {
        query!(
            r#"
            INSERT INTO metadata (key, value)
            VALUES (?1, ?2)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            "#,
            key,
            value
        )
        .execute(self.pool)
        .await
        .map(|_| ())
    }
}
