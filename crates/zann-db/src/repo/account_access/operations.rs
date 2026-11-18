use super::*;
pub struct AccessOperation {
    pub operation_id: Uuid,
    pub user_id: Option<Uuid>,
    pub authority_kind: i16,
    pub authority_id: Option<Uuid>,
    pub auth_epoch: Option<i64>,
    pub security_revision: Option<i64>,
    pub request_digest: [u8; 32],
    pub payload: Vec<u8>,
    pub revision: i64,
    pub expires_at: DateTime<Utc>,
}
impl AccountAccessRepo<'_> {
    pub async fn operation(&self, id: Uuid) -> AccessStoreResult<Option<AccessOperation>> {
        sqlx_core::query::query::<Postgres>(
            "SELECT * FROM account_access_slots WHERE operation_id=$1",
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?
        .map(decode)
        .transpose()
    }
    pub async fn lock_operation_in(
        conn: &mut PgConnection,
        id: Uuid,
    ) -> AccessStoreResult<AccessOperation> {
        let row = sqlx_core::query::query::<Postgres>(
            "SELECT * FROM account_access_slots WHERE operation_id=$1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(conn)
        .await?
        .ok_or(AccountAccessStoreError::Conflict)?;
        decode(row)
    }
    pub async fn allocate_in(
        conn: &mut PgConnection,
        op: &AccessOperation,
    ) -> AccessStoreResult<()> {
        if op.operation_id.get_version_num() != 4
            || op.payload.len() > 65536
            || !matches!(op.authority_kind, 1..=3)
        {
            return Err(AccountAccessStoreError::Invalid);
        }
        if let Some(user) = op.user_id {
            let count=sqlx_core::query::query::<Postgres>("SELECT slot FROM account_access_slots WHERE user_id=$1 AND expires_at>CURRENT_TIMESTAMP LIMIT 4")
                .bind(user).fetch_all(&mut *conn).await?.len();
            if count >= 4 {
                return Err(AccountAccessStoreError::Capacity);
            }
        }
        let changed=sqlx_core::query::query::<Postgres>("UPDATE account_access_slots SET operation_id=$1,user_id=$2,authority_kind=$3,authority_id=$4,auth_epoch=$5,security_revision=$6,request_digest=$7,payload=$8,revision=revision+1,expires_at=$9 WHERE slot=(SELECT slot FROM account_access_slots WHERE expires_at<CURRENT_TIMESTAMP ORDER BY expires_at,slot FOR UPDATE SKIP LOCKED LIMIT 1)")
            .bind(op.operation_id).bind(op.user_id).bind(op.authority_kind).bind(op.authority_id).bind(op.auth_epoch).bind(op.security_revision)
            .bind(op.request_digest.as_slice()).bind(&op.payload).bind(op.expires_at).execute(conn).await?;
        if changed.rows_affected() != 1 {
            return Err(AccountAccessStoreError::Capacity);
        }
        Ok(())
    }
    pub async fn save_operation_in(
        conn: &mut PgConnection,
        op: &AccessOperation,
    ) -> AccessStoreResult<()> {
        if op.payload.len() > 65536 {
            return Err(AccountAccessStoreError::Invalid);
        }
        let changed=sqlx_core::query::query::<Postgres>("UPDATE account_access_slots SET payload=$3,revision=revision+1,expires_at=$4 WHERE operation_id=$1 AND revision=$2 AND expires_at>CURRENT_TIMESTAMP")
            .bind(op.operation_id).bind(op.revision).bind(&op.payload).bind(op.expires_at).execute(conn).await?;
        if changed.rows_affected() != 1 {
            return Err(AccountAccessStoreError::Conflict);
        }
        Ok(())
    }
}
fn decode(row: sqlx_postgres::PgRow) -> AccessStoreResult<AccessOperation> {
    let digest: Vec<u8> = row.try_get("request_digest")?;
    Ok(AccessOperation {
        operation_id: row.try_get("operation_id")?,
        user_id: row.try_get("user_id")?,
        authority_kind: row.try_get("authority_kind")?,
        authority_id: row.try_get("authority_id")?,
        auth_epoch: row.try_get("auth_epoch")?,
        security_revision: row.try_get("security_revision")?,
        request_digest: digest
            .try_into()
            .map_err(|_| AccountAccessStoreError::Invalid)?,
        payload: row.try_get("payload")?,
        revision: row.try_get("revision")?,
        expires_at: row.try_get("expires_at")?,
    })
}
