//! Transactional restricted-protocol admission and bounded historical replies.
use super::*;
pub enum RecoveryAdmission {
    Replay(Vec<u8>),
    Current(RecoveryStatus),
}
impl RecoveryRepo<'_> {
    pub async fn get_in(
        conn: &mut PgConnection,
        id: Uuid,
    ) -> Result<Option<RecoveryRecord>, RecoveryStoreError> {
        sqlx_core::query::query::<Postgres>(
            "SELECT * FROM account_recovery_operations WHERE id=$1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(conn)
        .await?
        .map(decode_record)
        .transpose()
        .map_err(Into::into)
    }
    pub async fn admit_step_in(
        conn: &mut PgConnection,
        input: &RecoveryMutation,
        resume_hash: &str,
    ) -> Result<RecoveryAdmission, RecoveryStoreError> {
        if input.mutation_id.get_version_num() != 4 || !valid_hash(resume_hash) {
            return Err(RecoveryStoreError::InvalidInput);
        }
        let account = lock_account(conn, input.user_id).await?;
        let row=sqlx_core::query::query::<Postgres>("SELECT *,expires_at>CURRENT_TIMESTAMP AS live FROM account_recovery_operations WHERE id=$1 AND user_id=$2 FOR UPDATE")
            .bind(input.operation_id).bind(input.user_id).fetch_optional(&mut *conn).await?.ok_or(RecoveryStoreError::Conflict)?;
        if !zann_crypto::tokens::constant_time_equal(
            row.try_get::<String, _>("resume_token_hash")?.as_bytes(),
            resume_hash.as_bytes(),
        ) {
            return Err(RecoveryStoreError::Conflict);
        }
        if let Some(receipt)=sqlx_core::query::query::<Postgres>("SELECT request_digest,reply FROM account_recovery_receipts WHERE operation_id=$1 AND mutation_id=$2")
            .bind(input.operation_id).bind(input.mutation_id).fetch_optional(&mut *conn).await? {
            if !zann_crypto::tokens::constant_time_equal(&receipt.try_get::<Vec<u8>,_>("request_digest")?,&input.request_digest) {return Err(RecoveryStoreError::Conflict);}
            let reply:Option<Vec<u8>>=receipt.try_get("reply")?;
            return Ok(RecoveryAdmission::Replay(reply.ok_or(RecoveryStoreError::Conflict)?));
        }
        if !row.try_get::<bool, _>("live")? || !matches!(row.try_get::<i16, _>("state")?, 1 | 2) {
            return Err(RecoveryStoreError::Ended);
        }
        if account.try_get::<Option<Uuid>, _>("active_recovery_id")? != Some(input.operation_id)
            || account.try_get::<i64, _>("auth_epoch")? != row.try_get::<i64, _>("auth_epoch")?
            || account.try_get::<i16, _>("status")? != UserStatus::Active.as_i32() as i16
            || account
                .try_get::<Option<DateTime<Utc>>, _>("deleted_at")?
                .is_some()
            || row.try_get::<i64, _>("revision")? != input.expected_revision
        {
            return Err(RecoveryStoreError::Conflict);
        }
        if row.try_get::<i16, _>("receipt_count")? >= zann_core::recovery::MAX_RECOVERY_RECEIPTS {
            return Err(RecoveryStoreError::Capacity);
        }
        Ok(RecoveryAdmission::Current(decode_record(row)?.status))
    }
    pub async fn advance_step_in(
        conn: &mut PgConnection,
        input: &RecoveryMutation,
        state: RecoveryState,
    ) -> Result<RecoveryStatus, RecoveryStoreError> {
        if !matches!(
            state,
            RecoveryState::Consumed
                | RecoveryState::CredentialReady
                | RecoveryState::Completed
                | RecoveryState::Abandoned
        ) {
            return Err(RecoveryStoreError::InvalidInput);
        }
        let row=sqlx_core::query::query::<Postgres>("UPDATE account_recovery_operations SET state=$3,revision=revision+1,receipt_count=receipt_count+1,updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND user_id=$2 AND revision=$4 AND state IN (1,2) AND receipt_count<32 AND expires_at>CURRENT_TIMESTAMP RETURNING *")
            .bind(input.operation_id).bind(input.user_id).bind(state as i16).bind(input.expected_revision).fetch_optional(&mut *conn).await?.ok_or(RecoveryStoreError::Conflict)?;
        if state.is_terminal() {
            let changed=sqlx_core::query::query::<Postgres>("UPDATE users SET active_recovery_id=NULL,security_revision=security_revision+1,row_version=row_version+1 WHERE id=$1 AND active_recovery_id=$2")
                .bind(input.user_id).bind(input.operation_id).execute(&mut *conn).await?;
            if changed.rows_affected() != 1 {
                return Err(RecoveryStoreError::Conflict);
            }
            sqlx_core::query::query::<Postgres>(
                "UPDATE account_recovery_quota SET active_count=active_count-1 WHERE singleton",
            )
            .execute(conn)
            .await?;
        }
        Ok(decode_record(row)?.status)
    }
    pub async fn record_reply_in(
        conn: &mut PgConnection,
        input: &RecoveryMutation,
        status: &RecoveryStatus,
        reply: &[u8],
    ) -> Result<(), RecoveryStoreError> {
        if reply.len() > 3072
            || status.operation_id != input.operation_id
            || status.user_id != input.user_id
            || status.revision != input.expected_revision + 1
        {
            return Err(RecoveryStoreError::InvalidInput);
        }
        sqlx_core::query::query::<Postgres>("INSERT INTO account_recovery_receipts(operation_id,mutation_id,request_digest,revision,state,committed_at,reply) VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP,$6)")
            .bind(input.operation_id).bind(input.mutation_id).bind(input.request_digest.as_slice()).bind(status.revision).bind(status.state as i16).bind(reply).execute(conn).await?;
        Ok(())
    }
}
