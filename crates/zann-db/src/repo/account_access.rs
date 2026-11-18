//! Bounded public RP/custody storage. RP verification belongs to server auth.
use super::prelude::*;
use sqlx_postgres::{PgConnection, Postgres};
use zann_core::api::account_access::PasskeyMode;

mod admin;
mod operations;
mod receipts;
mod security;
pub use operations::AccessOperation;
pub use security::SecurityAccount;

#[derive(Debug, thiserror::Error)]
pub enum AccountAccessStoreError {
    #[error("account access state conflict")]
    Conflict,
    #[error("account access capacity exhausted")]
    Capacity,
    #[error("invalid account access storage input")]
    Invalid,
    #[error("account access persistence failed")]
    Database(#[from] sqlx_core::Error),
}
pub type AccessStoreResult<T> = Result<T, AccountAccessStoreError>;
pub struct AccountAccessRepo<'a> {
    pool: &'a PgPool,
}
pub struct NewPasskey {
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub name: String,
    pub mode: PasskeyMode,
    pub credential: Vec<u8>,
    pub grant: Option<Vec<u8>>,
    pub auth_epoch: i64,
}
pub struct PasskeyRecord {
    pub creation_generation: i64,
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub name: String,
    pub mode: PasskeyMode,
    pub credential: Vec<u8>,
    pub grant: Option<Vec<u8>>,
    pub auth_epoch: i64,
    pub revision: i64,
    pub session_epoch: i64,
}
impl<'a> AccountAccessRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }
    pub async fn credentials(&self, user: Uuid) -> AccessStoreResult<Vec<PasskeyRecord>> {
        sqlx_core::query::query::<Postgres>("SELECT * FROM account_passkeys WHERE user_id=$1 AND revoked_at IS NULL ORDER BY credential_id LIMIT 17")
            .bind(user).fetch_all(self.pool).await?.into_iter().map(decode_passkey).collect()
    }
    pub async fn credential(&self, id: &[u8]) -> AccessStoreResult<Option<PasskeyRecord>> {
        sqlx_core::query::query::<Postgres>(
            "SELECT * FROM account_passkeys WHERE credential_id=$1 AND revoked_at IS NULL",
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?
        .map(decode_passkey)
        .transpose()
    }
    pub async fn credential_in(
        conn: &mut PgConnection,
        id: &[u8],
    ) -> AccessStoreResult<Option<PasskeyRecord>> {
        sqlx_core::query::query::<Postgres>(
            "SELECT * FROM account_passkeys WHERE credential_id=$1 AND revoked_at IS NULL",
        )
        .bind(id)
        .fetch_optional(conn)
        .await?
        .map(decode_passkey)
        .transpose()
    }
    pub async fn has_credentials_in(
        conn: &mut PgConnection,
        user: Uuid,
    ) -> AccessStoreResult<bool> {
        Ok(sqlx_core::query::query::<Postgres>(
            "SELECT 1 FROM account_passkeys WHERE user_id=$1 AND revoked_at IS NULL LIMIT 1",
        )
        .bind(user)
        .fetch_optional(conn)
        .await?
        .is_some())
    }
    pub async fn create_in(conn: &mut PgConnection, key: &NewPasskey) -> AccessStoreResult<()> {
        if key.credential_id.is_empty()
            || key.credential_id.len() > 1024
            || key.credential.len() > 8192
            || key.name.is_empty()
            || key.name.len() > 128
            || key.grant.as_ref().is_some_and(|g| g.len() > 4096)
            || (key.mode == PasskeyMode::VaultUnlock) != key.grant.is_some()
        {
            return Err(AccountAccessStoreError::Invalid);
        }
        let count = sqlx_core::query::query::<Postgres>("SELECT credential_id FROM account_passkeys WHERE user_id=$1 AND revoked_at IS NULL LIMIT 16")
            .bind(key.user_id).fetch_all(&mut *conn).await?.len();
        if count >= 16 {
            return Err(AccountAccessStoreError::Capacity);
        }
        let fence=sqlx_core::query::query::<Postgres>("UPDATE account_credential_fence SET generation=generation+1 WHERE singleton RETURNING generation").fetch_one(&mut *conn).await?;
        let generation: i64 = fence.try_get("generation")?;
        sqlx_core::query::query::<Postgres>("INSERT INTO account_passkeys (credential_id,user_id,name,mode,credential,key_grant,auth_epoch,creation_generation) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&key.credential_id).bind(key.user_id).bind(&key.name).bind(if key.mode==PasskeyMode::VaultUnlock {2i16}else{1i16})
            .bind(&key.credential).bind(&key.grant).bind(key.auth_epoch).bind(generation).execute(conn).await?;
        Ok(())
    }
    pub async fn update_credential_in(
        conn: &mut PgConnection,
        key: &PasskeyRecord,
        verified: &[u8],
    ) -> AccessStoreResult<()> {
        if verified.len() > 8192 {
            return Err(AccountAccessStoreError::Invalid);
        }
        let changed=sqlx_core::query::query::<Postgres>("UPDATE account_passkeys SET credential=$3,revision=revision+1 WHERE credential_id=$1 AND user_id=$2 AND revision=$4 AND auth_epoch=$5 AND revoked_at IS NULL")
            .bind(&key.credential_id).bind(key.user_id).bind(verified).bind(key.revision).bind(key.auth_epoch).execute(conn).await?;
        if changed.rows_affected() != 1 {
            return Err(AccountAccessStoreError::Conflict);
        }
        Ok(())
    }
    pub async fn revoke_all_in(conn: &mut PgConnection, user: Uuid) -> AccessStoreResult<()> {
        // Epoch checks already invalidate sessions; this removes RP/grant authority
        // in the same account-locked consume/reset transaction.
        sqlx_core::query::query::<Postgres>("UPDATE account_passkeys SET revoked_at=CURRENT_TIMESTAMP,session_epoch=session_epoch+1,revision=revision+1,key_grant=NULL,mode=1 WHERE user_id=$1 AND revoked_at IS NULL").bind(user).execute(&mut *conn).await?;
        sqlx_core::query::query::<Postgres>("DELETE FROM account_custody_nonces WHERE user_id=$1")
            .bind(user)
            .execute(&mut *conn)
            .await?;
        sqlx_core::query::query::<Postgres>("UPDATE account_access_slots SET operation_id=NULL,user_id=NULL,authority_kind=NULL,authority_id=NULL,auth_epoch=NULL,security_revision=NULL,request_digest=NULL,payload=NULL,revision=revision+1,expires_at='-infinity' WHERE user_id=$1 AND expires_at>CURRENT_TIMESTAMP")
            .bind(user).execute(conn).await?;
        Ok(())
    }
}
fn decode_passkey(row: sqlx_postgres::PgRow) -> AccessStoreResult<PasskeyRecord> {
    let mode = match row.try_get::<i16, _>("mode")? {
        1 => PasskeyMode::AuthOnly,
        2 => PasskeyMode::VaultUnlock,
        _ => return Err(AccountAccessStoreError::Invalid),
    };
    Ok(PasskeyRecord {
        creation_generation: row.try_get("creation_generation")?,
        credential_id: row.try_get("credential_id")?,
        user_id: row.try_get("user_id")?,
        name: row.try_get("name")?,
        mode,
        credential: row.try_get("credential")?,
        grant: row.try_get("key_grant")?,
        auth_epoch: row.try_get("auth_epoch")?,
        revision: row.try_get("revision")?,
        session_epoch: row.try_get("session_epoch")?,
    })
}

impl AccountAccessRepo<'_> {
    /// A non-locking MVCC read. The global fence is written only for rare factor
    /// activation, never for login/session/sync. It survives ordinary DB restore.
    pub async fn credential_fence_in(conn: &mut PgConnection) -> AccessStoreResult<i64> {
        let row = sqlx_core::query::query::<Postgres>(
            "SELECT generation FROM account_credential_fence WHERE singleton",
        )
        .fetch_one(conn)
        .await?;
        Ok(row.try_get("generation")?)
    }
}
