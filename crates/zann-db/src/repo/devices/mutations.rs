use super::*;

impl DeviceRepo<'_> {
    pub async fn revoke_in<'e, E>(
        executor: E,
        device_id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64, sqlx_core::Error>
    where
        E: sqlx_core::executor::Executor<'e, Database = sqlx_postgres::Postgres>,
    {
        query!(
            "UPDATE devices SET revoked_at=$2 WHERE id=$1",
            device_id,
            revoked_at
        )
        .execute(executor)
        .await
        .map(|r| r.rows_affected())
    }
}
