use super::*;
use zann_core::recovery::{MAX_ACTIVE_RECOVERY_OPERATIONS, MAX_RETAINED_RECOVERY_OPERATIONS};

/// Already verified, immutable consume inputs; never contains a raw code/token.
/// The HTTP auth owner must additionally revoke its future passkey/grant catalog.
pub struct RecoveryStart<'a> {
    pub operation_id: Uuid,
    pub user_id: Uuid,
    pub expected_auth_epoch: i64,
    pub expected_security_revision: i64,
    pub expected_code_version: i64,
    pub expected_code_hash: &'a str,
    pub successor_code_hash: &'a str,
    pub resume_token_hash: &'a str,
    pub consume_digest: [u8; 32],
    pub account_key_epoch: Option<i64>,
}

impl RecoveryRepo<'_> {
    pub async fn start(
        &self,
        input: RecoveryStart<'_>,
    ) -> Result<RecoveryStatus, RecoveryStoreError> {
        if input.operation_id.get_version_num() != 4
            || input.expected_code_hash == input.successor_code_hash
            || !valid_hash(input.resume_token_hash)
            || input.successor_code_hash.is_empty()
            || input.successor_code_hash.len() > 512
            || input.expected_code_hash.len() > 512
            || input.account_key_epoch.is_some_and(|epoch| epoch <= 0)
        {
            return Err(RecoveryStoreError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let account = lock_account(&mut tx, input.user_id).await?;
        if let Some(row) = sqlx_core::query::query::<Postgres>(
            "SELECT * FROM account_recovery_operations WHERE id = $1 FOR UPDATE",
        )
        .bind(input.operation_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            let record = decode_record(row)?;
            if record.status.user_id != input.user_id
                || !zann_crypto::tokens::constant_time_equal(
                    record.resume_token_hash.as_bytes(),
                    input.resume_token_hash.as_bytes(),
                )
                || !zann_crypto::tokens::constant_time_equal(
                    &record.consume_digest,
                    &input.consume_digest,
                )
            {
                return Err(RecoveryStoreError::Conflict);
            }
            return Ok(record.status);
        }
        let old_hash: Option<String> = account.try_get("recovery_key_hash")?;
        let deleted: Option<DateTime<Utc>> = account.try_get("deleted_at")?;
        if account.try_get::<i16, _>("status")? != UserStatus::Active.as_i32() as i16
            || deleted.is_some()
            || account.try_get::<i64, _>("auth_epoch")? != input.expected_auth_epoch
            || account.try_get::<i64, _>("security_revision")? != input.expected_security_revision
            || account.try_get::<i64, _>("recovery_key_version")? != input.expected_code_version
            || old_hash.as_deref() != Some(input.expected_code_hash)
        {
            return Err(RecoveryStoreError::Conflict);
        }
        let old_id: Option<Uuid> = account.try_get("active_recovery_id")?;
        if let Some(old_id) = old_id {
            let changed = sqlx_core::query::query::<Postgres>("UPDATE account_recovery_operations SET state = 6, revision = revision + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND user_id = $2 AND state IN (1,2)")
                .bind(old_id).bind(input.user_id).execute(&mut *tx).await?;
            if changed.rows_affected() != 1 {
                return Err(RecoveryStoreError::Conflict);
            }
        }
        let quota = sqlx_core::query::query::<Postgres>("SELECT active_count, retained_count FROM account_recovery_quota WHERE singleton FOR UPDATE")
            .fetch_one(&mut *tx).await?;
        let active =
            i64::from(quota.try_get::<i32, _>("active_count")?) - i64::from(old_id.is_some());
        if active < 0 {
            return Err(RecoveryStoreError::Conflict);
        }
        if active >= MAX_ACTIVE_RECOVERY_OPERATIONS
            || i64::from(quota.try_get::<i32, _>("retained_count")?)
                >= MAX_RETAINED_RECOVERY_OPERATIONS
        {
            return Err(RecoveryStoreError::Capacity);
        }
        let account = sqlx_core::query::query::<Postgres>("UPDATE users SET auth_epoch = auth_epoch + 1, security_revision = security_revision + 1, recovery_key_version = recovery_key_version + 1, recovery_key_hash = $2, active_recovery_id = $3, row_version = row_version + 1 WHERE id = $1 RETURNING auth_epoch, recovery_key_version")
            .bind(input.user_id).bind(input.successor_code_hash).bind(input.operation_id).fetch_one(&mut *tx).await?;
        let epoch: i64 = account.try_get("auth_epoch")?;
        let code_version: i64 = account.try_get("recovery_key_version")?;
        let row = sqlx_core::query::query::<Postgres>(
            r#"
            INSERT INTO account_recovery_operations (id,user_id,resume_token_hash,consume_digest,
                consumed_code_version,successor_code_version,auth_epoch,account_key_epoch,state,
                revision,created_at,expires_at,updated_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1,1,CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP + INTERVAL '24 hours',CURRENT_TIMESTAMP) RETURNING *
        "#,
        )
        .bind(input.operation_id)
        .bind(input.user_id)
        .bind(input.resume_token_hash)
        .bind(input.consume_digest.as_slice())
        .bind(input.expected_code_version)
        .bind(code_version)
        .bind(epoch)
        .bind(input.account_key_epoch)
        .fetch_one(&mut *tx)
        .await?;
        sqlx_core::query::query::<Postgres>("UPDATE account_recovery_quota SET active_count = $1, retained_count = retained_count + 1 WHERE singleton")
            .bind(i32::try_from(active + 1).map_err(|_| RecoveryStoreError::Capacity)?).execute(&mut *tx).await?;
        let status = decode_record(row)?.status;
        tx.commit().await?;
        Ok(status)
    }
}
