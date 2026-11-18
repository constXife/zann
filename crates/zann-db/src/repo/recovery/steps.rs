use super::*;
use zann_core::recovery::MAX_RECOVERY_RECEIPTS;

pub struct RecoveryMutation {
    pub user_id: Uuid,
    pub operation_id: Uuid,
    pub mutation_id: Uuid,
    pub expected_revision: i64,
    pub request_digest: [u8; 32],
}

impl RecoveryRepo<'_> {
    /// Persists an idempotent storage step. Phase/RP admission stays in auth.
    /// This does not mark a credential ready or activate a factor/session.
    pub async fn record_step(
        &self,
        input: RecoveryMutation,
    ) -> Result<RecoveryReceipt, RecoveryStoreError> {
        let mut tx = self.pool.begin().await?;
        let account = lock_account(&mut tx, input.user_id).await?;
        let row = sqlx_core::query::query::<Postgres>("SELECT *, expires_at > CURRENT_TIMESTAMP AS live FROM account_recovery_operations WHERE id = $1 AND user_id = $2 FOR UPDATE")
            .bind(input.operation_id).bind(input.user_id).fetch_optional(&mut *tx).await?.ok_or(RecoveryStoreError::Conflict)?;
        if let Some(receipt) = sqlx_core::query::query::<Postgres>(
            "SELECT * FROM account_recovery_receipts WHERE operation_id = $1 AND mutation_id = $2",
        )
        .bind(input.operation_id)
        .bind(input.mutation_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            let digest: Vec<u8> = receipt.try_get("request_digest")?;
            if !zann_crypto::tokens::constant_time_equal(&digest, &input.request_digest) {
                return Err(RecoveryStoreError::Conflict);
            }
            return decode_receipt(receipt).map_err(Into::into);
        }
        let active: Option<Uuid> = account.try_get("active_recovery_id")?;
        if active != Some(input.operation_id)
            || !row.try_get::<bool, _>("live")?
            || account.try_get::<i64, _>("auth_epoch")? != row.try_get::<i64, _>("auth_epoch")?
            || row.try_get::<i64, _>("revision")? != input.expected_revision
            || !matches!(row.try_get::<i16, _>("state")?, 1 | 2)
        {
            return Err(RecoveryStoreError::Conflict);
        }
        if row.try_get::<i16, _>("receipt_count")? >= MAX_RECOVERY_RECEIPTS {
            return Err(RecoveryStoreError::Capacity);
        }
        let row = sqlx_core::query::query::<Postgres>("UPDATE account_recovery_operations SET revision = revision + 1, receipt_count = receipt_count + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING revision, state")
            .bind(input.operation_id).fetch_one(&mut *tx).await?;
        let receipt = sqlx_core::query::query::<Postgres>("INSERT INTO account_recovery_receipts (operation_id,mutation_id,request_digest,revision,state,committed_at) VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP) RETURNING *")
            .bind(input.operation_id).bind(input.mutation_id).bind(input.request_digest.as_slice())
            .bind(row.try_get::<i64,_>("revision")?).bind(row.try_get::<i16,_>("state")?).fetch_one(&mut *tx).await?;
        let receipt = decode_receipt(receipt)?;
        tx.commit().await?;
        Ok(receipt)
    }

    /// A terminal operation never reactivates the successor code or old sessions.
    pub async fn end(
        &self,
        user_id: Uuid,
        id: Uuid,
        expected_revision: i64,
        state: RecoveryState,
    ) -> Result<RecoveryStatus, RecoveryStoreError> {
        let mut tx = self.pool.begin().await?;
        let status = Self::end_in(&mut tx, user_id, id, expected_revision, state).await?;
        tx.commit().await?;
        Ok(status)
    }
    pub async fn end_in(
        conn: &mut PgConnection,
        user_id: Uuid,
        id: Uuid,
        expected_revision: i64,
        state: RecoveryState,
    ) -> Result<RecoveryStatus, RecoveryStoreError> {
        if !matches!(
            state,
            RecoveryState::Expired | RecoveryState::Abandoned | RecoveryState::Superseded
        ) {
            return Err(RecoveryStoreError::InvalidInput);
        }
        let account = lock_account(&mut *conn, user_id).await?;
        let row = sqlx_core::query::query::<Postgres>("SELECT *, expires_at <= CURRENT_TIMESTAMP AS expired FROM account_recovery_operations WHERE id = $1 AND user_id = $2 FOR UPDATE")
            .bind(id).bind(user_id).fetch_optional(&mut *conn).await?.ok_or(RecoveryStoreError::Conflict)?;
        let expired: bool = row.try_get("expired")?;
        let record = decode_record(row)?;
        if record.status.state == state {
            return Ok(record.status);
        }
        if record.status.state.is_terminal()
            || record.status.revision != expected_revision
            || account.try_get::<Option<Uuid>, _>("active_recovery_id")? != Some(id)
            || (state == RecoveryState::Expired && !expired)
        {
            return Err(RecoveryStoreError::Conflict);
        }
        let row = sqlx_core::query::query::<Postgres>("UPDATE account_recovery_operations SET state = $2, revision = revision + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *")
            .bind(id).bind(state as i16).fetch_one(&mut *conn).await?;
        sqlx_core::query::query::<Postgres>("UPDATE users SET active_recovery_id = NULL, security_revision = security_revision + 1, row_version = row_version + 1 WHERE id = $1")
            .bind(user_id).execute(&mut *conn).await?;
        sqlx_core::query::query::<Postgres>(
            "UPDATE account_recovery_quota SET active_count = active_count - 1 WHERE singleton",
        )
        .execute(&mut *conn)
        .await?;
        let status = decode_record(row)?.status;
        Ok(status)
    }
}

fn decode_receipt(row: PgRow) -> Result<RecoveryReceipt, sqlx_core::Error> {
    Ok(RecoveryReceipt {
        mutation_id: row.try_get("mutation_id")?,
        revision: row.try_get("revision")?,
        state: RecoveryState::from_code(row.try_get("state")?)
            .ok_or_else(|| sqlx_core::Error::Decode("invalid recovery receipt state".into()))?,
        committed_at: row.try_get("committed_at")?,
    })
}
