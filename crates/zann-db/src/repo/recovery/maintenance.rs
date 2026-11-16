use super::*;

impl RecoveryRepo<'_> {
    /// At most one indexed page for expiry and one for retention per call.
    pub async fn maintain(&self) -> Result<u64, RecoveryStoreError> {
        let expired=sqlx_core::query::query::<Postgres>("SELECT id,user_id,revision FROM account_recovery_operations WHERE state IN (1,2) AND expires_at <= CURRENT_TIMESTAMP ORDER BY expires_at,id LIMIT 100")
            .fetch_all(self.pool).await?;
        for row in expired {
            match self
                .end(
                    row.try_get("user_id")?,
                    row.try_get("id")?,
                    row.try_get("revision")?,
                    RecoveryState::Expired,
                )
                .await
            {
                Ok(_) | Err(RecoveryStoreError::Conflict) => {}
                Err(error) => return Err(error),
            }
        }
        let old=sqlx_core::query::query::<Postgres>("SELECT id,user_id FROM account_recovery_operations WHERE state NOT IN (1,2) AND updated_at < CURRENT_TIMESTAMP - INTERVAL '7 days' ORDER BY updated_at,id LIMIT 100")
            .fetch_all(self.pool).await?;
        let mut removed = 0;
        for row in old {
            let id: Uuid = row.try_get("id")?;
            let user_id: Uuid = row.try_get("user_id")?;
            let mut tx = self.pool.begin().await?;
            let account = lock_account(&mut tx, user_id).await?;
            if account.try_get::<Option<Uuid>, _>("active_recovery_id")? == Some(id) {
                return Err(RecoveryStoreError::Conflict);
            }
            let deleted=sqlx_core::query::query::<Postgres>("DELETE FROM account_recovery_operations WHERE id=$1 AND user_id=$2 AND state NOT IN (1,2) AND updated_at < CURRENT_TIMESTAMP - INTERVAL '7 days'")
                .bind(id).bind(user_id).execute(&mut *tx).await?.rows_affected();
            if deleted == 1 {
                sqlx_core::query::query::<Postgres>("UPDATE account_recovery_quota SET retained_count=retained_count-1 WHERE singleton").execute(&mut *tx).await?;
            }
            tx.commit().await?;
            removed += deleted;
        }
        Ok(removed)
    }
}
