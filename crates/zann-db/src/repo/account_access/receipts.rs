use super::*;
use zann_core::api::account_access::SecurityReceipt;
impl AccountAccessRepo<'_> {
    // Caller holds the account lock. Lookup precedes revision/nonce checks.
    pub async fn receipt_in(
        conn: &mut PgConnection,
        user: Uuid,
        id: Uuid,
        digest: &[u8; 32],
    ) -> AccessStoreResult<Option<Vec<u8>>> {
        let row=sqlx_core::query::query::<Postgres>("SELECT request_digest,reply FROM account_security_receipts WHERE user_id=$1 AND mutation_id=$2 AND committed_at>CURRENT_TIMESTAMP-INTERVAL '7 days'")
            .bind(user).bind(id).fetch_optional(conn).await?;
        row.map(|row| {
            let stored: Vec<u8> = row.try_get("request_digest")?;
            if !zann_crypto::tokens::constant_time_equal(&stored, digest) {
                return Err(AccountAccessStoreError::Conflict);
            }
            Ok(row.try_get("reply")?)
        })
        .transpose()
    }
    pub async fn save_receipt_in(
        conn: &mut PgConnection,
        user: Uuid,
        id: Uuid,
        digest: &[u8; 32],
        reply: &[u8],
    ) -> AccessStoreResult<()> {
        if reply.len() > 2048 || id.get_version_num() != 4 {
            return Err(AccountAccessStoreError::Invalid);
        }
        sqlx_core::query::query::<Postgres>("DELETE FROM account_security_receipts WHERE user_id=$1 AND committed_at<=CURRENT_TIMESTAMP-INTERVAL '7 days'").bind(user).execute(&mut *conn).await?;
        let count = sqlx_core::query::query::<Postgres>(
            "SELECT mutation_id FROM account_security_receipts WHERE user_id=$1 LIMIT 32",
        )
        .bind(user)
        .fetch_all(&mut *conn)
        .await?
        .len();
        if count >= 32 {
            return Err(AccountAccessStoreError::Capacity);
        }
        sqlx_core::query::query::<Postgres>("INSERT INTO account_security_receipts(user_id,mutation_id,request_digest,reply) VALUES ($1,$2,$3,$4)")
            .bind(user).bind(id).bind(digest.as_slice()).bind(reply).execute(conn).await?;
        Ok(())
    }
    pub async fn activate_code_in(
        conn: &mut PgConnection,
        user: Uuid,
        revision: i64,
        candidate: Uuid,
        hash: &str,
        disable: bool,
    ) -> AccessStoreResult<SecurityReceipt> {
        if hash.len() != 44 {
            return Err(AccountAccessStoreError::Invalid);
        }
        let row=sqlx_core::query::query::<Postgres>("UPDATE users SET recovery_key_hash=$4,recovery_key_version=recovery_key_version+1,recovery_candidate_id=$3,password_hash=CASE WHEN $5 THEN NULL ELSE password_hash END,security_revision=security_revision+1,row_version=row_version+1 WHERE id=$1 AND security_revision=$2 AND active_recovery_id IS NULL RETURNING security_revision,recovery_key_version")
            .bind(user).bind(revision).bind(candidate).bind(hash).bind(disable).fetch_optional(conn).await?.ok_or(AccountAccessStoreError::Conflict)?;
        Ok(SecurityReceipt {
            mutation_id: candidate,
            security_revision: row.try_get("security_revision")?,
            credential_id: None,
            recovery_key_version: Some(row.try_get("recovery_key_version")?),
            recovery_candidate_id: Some(candidate),
        })
    }
}
