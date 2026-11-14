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
    /// Atomic exact-source CAS. A stale writer never overwrites another generation.
    pub async fn compare_exchange_value(
        &self,
        key: &str,
        expected: Option<&str>,
        replacement: &str,
    ) -> Result<bool, sqlx_core::Error> {
        let result = match expected {
            None => {
                query!(
                    "INSERT INTO metadata (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO NOTHING",
                    key,
                    replacement
                )
                .execute(self.pool)
                .await?
            }
            Some(expected) => {
                query!(
                    "UPDATE metadata SET value = ?1 WHERE key = ?2 AND value = ?3",
                    replacement,
                    key,
                    expected
                )
                .execute(self.pool)
                .await?
            }
        };
        Ok(result.rows_affected() == 1)
    }

    /// Bounds persisted values before the driver allocates their contents.
    pub async fn get_value_bounded(
        &self,
        key: &str,
        maximum: i64,
    ) -> Result<Option<String>, sqlx_core::Error> {
        let row = query!("SELECT CASE WHEN length(CAST(value AS BLOB)) <= ?2 THEN value ELSE NULL END AS value FROM metadata WHERE key = ?1", key, maximum).fetch_optional(self.pool).await?;
        match row {
            None => Ok(None),
            Some(row) => row
                .try_get::<Option<String>, _>("value")?
                .map(Some)
                .ok_or_else(|| {
                    sqlx_core::Error::Protocol("metadata exceeds its size limit".into())
                }),
        }
    }
}
