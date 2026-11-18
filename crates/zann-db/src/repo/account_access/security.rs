use super::*;
pub struct SecurityAccount {
    pub user_id: Uuid,
    pub auth_epoch: i64,
    pub security_revision: i64,
    pub recovery_key_version: i64,
    pub recovery_candidate_id: Option<Uuid>,
    pub active_recovery_id: Option<Uuid>,
    pub descriptor: Option<Vec<u8>>,
    pub password_enabled: bool,
    pub row_version: i64,
    pub active: bool,
}
impl AccountAccessRepo<'_> {
    pub async fn account(&self, user: Uuid) -> AccessStoreResult<Option<SecurityAccount>> {
        sqlx_core::query::query::<Postgres>("SELECT id,auth_epoch,security_revision,recovery_key_version,recovery_candidate_id,active_recovery_id,account_key_descriptor,password_hash IS NOT NULL AS password_enabled,row_version,status=1 AND deleted_at IS NULL AS active FROM users WHERE id=$1")
            .bind(user).fetch_optional(self.pool).await?.map(decode_account).transpose()
    }
    pub async fn lock_account_in(
        conn: &mut PgConnection,
        user: Uuid,
    ) -> AccessStoreResult<SecurityAccount> {
        let row=sqlx_core::query::query::<Postgres>("SELECT id,auth_epoch,security_revision,recovery_key_version,recovery_candidate_id,active_recovery_id,account_key_descriptor,password_hash IS NOT NULL AS password_enabled,row_version,status=1 AND deleted_at IS NULL AS active FROM users WHERE id=$1 FOR UPDATE")
            .bind(user).fetch_optional(conn).await?.ok_or(AccountAccessStoreError::Conflict)?;
        decode_account(row)
    }
    pub async fn bind_descriptor_in(
        conn: &mut PgConnection,
        user: Uuid,
        revision: i64,
        descriptor: &[u8],
    ) -> AccessStoreResult<()> {
        if descriptor.len() > 1024 {
            return Err(AccountAccessStoreError::Invalid);
        }
        let changed=sqlx_core::query::query::<Postgres>("UPDATE users SET account_key_descriptor=$3,security_revision=security_revision+1,row_version=row_version+1 WHERE id=$1 AND security_revision=$2 AND account_key_descriptor IS NULL AND active_recovery_id IS NULL AND status=1 AND deleted_at IS NULL")
            .bind(user).bind(revision).bind(descriptor).execute(conn).await?;
        if changed.rows_affected() != 1 {
            return Err(AccountAccessStoreError::Conflict);
        }
        Ok(())
    }
    pub async fn advance_revision_in(
        conn: &mut PgConnection,
        user: Uuid,
        revision: i64,
    ) -> AccessStoreResult<i64> {
        let row=sqlx_core::query::query::<Postgres>("UPDATE users SET security_revision=security_revision+1,row_version=row_version+1 WHERE id=$1 AND security_revision=$2 RETURNING security_revision")
            .bind(user).bind(revision).fetch_optional(conn).await?.ok_or(AccountAccessStoreError::Conflict)?;
        Ok(row.try_get("security_revision")?)
    }
    pub async fn stage_nonce_in(
        conn: &mut PgConnection,
        user: Uuid,
        authority: Uuid,
        revision: i64,
        nonce: &[u8; 32],
        purpose: &str,
        digest: &[u8; 32],
    ) -> AccessStoreResult<()> {
        sqlx_core::query::query::<Postgres>("INSERT INTO account_custody_nonces (user_id,authority_id,nonce,purpose,body_digest,security_revision,expires_at) VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP+INTERVAL '120 seconds') ON CONFLICT (user_id) DO UPDATE SET authority_id=EXCLUDED.authority_id,nonce=EXCLUDED.nonce,purpose=EXCLUDED.purpose,body_digest=EXCLUDED.body_digest,security_revision=EXCLUDED.security_revision,expires_at=EXCLUDED.expires_at")
            .bind(user).bind(authority).bind(nonce.as_slice()).bind(purpose).bind(digest.as_slice()).bind(revision).execute(conn).await?;
        Ok(())
    }
    pub async fn consume_nonce_in(
        conn: &mut PgConnection,
        user: Uuid,
        authority: Uuid,
        revision: i64,
        nonce: &[u8; 32],
        purpose: &str,
        digest: &[u8; 32],
    ) -> AccessStoreResult<()> {
        let changed=sqlx_core::query::query::<Postgres>("DELETE FROM account_custody_nonces WHERE user_id=$1 AND authority_id=$2 AND security_revision=$3 AND nonce=$4 AND purpose=$5 AND body_digest=$6 AND expires_at>CURRENT_TIMESTAMP")
            .bind(user).bind(authority).bind(revision).bind(nonce.as_slice()).bind(purpose).bind(digest.as_slice()).execute(conn).await?;
        if changed.rows_affected() != 1 {
            return Err(AccountAccessStoreError::Conflict);
        }
        Ok(())
    }
    pub async fn revoke_in(
        conn: &mut PgConnection,
        user: Uuid,
        id: &[u8],
        revoke_sessions: bool,
    ) -> AccessStoreResult<()> {
        let changed=sqlx_core::query::query::<Postgres>("UPDATE account_passkeys SET revoked_at=CURRENT_TIMESTAMP,session_epoch=session_epoch+$3,revision=revision+1,key_grant=NULL,mode=1 WHERE user_id=$1 AND credential_id=$2 AND revoked_at IS NULL")
            .bind(user).bind(id).bind(i64::from(revoke_sessions)).execute(conn).await?;
        if changed.rows_affected() != 1 {
            return Err(AccountAccessStoreError::Conflict);
        }
        Ok(())
    }
}
fn decode_account(row: sqlx_postgres::PgRow) -> AccessStoreResult<SecurityAccount> {
    Ok(SecurityAccount {
        user_id: row.try_get("id")?,
        auth_epoch: row.try_get("auth_epoch")?,
        security_revision: row.try_get("security_revision")?,
        recovery_key_version: row.try_get("recovery_key_version")?,
        recovery_candidate_id: row.try_get("recovery_candidate_id")?,
        active_recovery_id: row.try_get("active_recovery_id")?,
        descriptor: row.try_get("account_key_descriptor")?,
        password_enabled: row.try_get("password_enabled")?,
        row_version: row.try_get("row_version")?,
        active: row.try_get("active")?,
    })
}
