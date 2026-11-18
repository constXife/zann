//! Transactional recovery storage. No code verifier, HTTP authority or RP admission.
//! Callers must verify credentials before `start`; a consuming route must not be
//! exposed until future passkey/grant revocation is part of that transaction.
use super::prelude::*;
use sqlx_postgres::{PgConnection, PgRow, Postgres};
use zann_core::recovery::{RecoveryState, RecoveryStatus};

mod maintenance;
mod protocol;
mod start;
mod steps;
pub use protocol::RecoveryAdmission;
pub use start::RecoveryStart;
pub use steps::RecoveryMutation;

pub struct RecoveryRepo<'a> {
    pool: &'a PgPool,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryStoreError {
    #[error("recovery generation or operation conflict")]
    Conflict,
    #[error("recovery operation has ended")]
    Ended,
    #[error("recovery capacity is exhausted")]
    Capacity,
    #[error("invalid recovery storage input")]
    InvalidInput,
    #[error("recovery database operation failed: {0}")]
    Database(#[from] sqlx_core::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountAuthState {
    pub auth_epoch: i64,
    pub security_revision: i64,
    pub recovery_key_version: i64,
    pub active_recovery_id: Option<Uuid>,
}

pub struct RecoveryRecord {
    pub status: RecoveryStatus,
    pub resume_token_hash: String,
    pub consume_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReceipt {
    pub mutation_id: Uuid,
    pub revision: i64,
    pub state: RecoveryState,
    pub committed_at: DateTime<Utc>,
}

impl<'a> RecoveryRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }
    pub async fn account_state(
        &self,
        user_id: Uuid,
    ) -> Result<Option<AccountAuthState>, RecoveryStoreError> {
        sqlx_core::query::query::<Postgres>("SELECT auth_epoch, security_revision, recovery_key_version, active_recovery_id FROM users WHERE id = $1")
            .bind(user_id).fetch_optional(self.pool).await?.map(|row| Ok(AccountAuthState {
                auth_epoch: row.try_get("auth_epoch")?, security_revision: row.try_get("security_revision")?,
                recovery_key_version: row.try_get("recovery_key_version")?, active_recovery_id: row.try_get("active_recovery_id")?,
            })).transpose()
    }
    pub async fn get(&self, id: Uuid) -> Result<Option<RecoveryRecord>, RecoveryStoreError> {
        sqlx_core::query::query::<Postgres>(
            "SELECT * FROM account_recovery_operations WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?
        .map(decode_record)
        .transpose()
        .map_err(Into::into)
    }
}

async fn lock_account(conn: &mut PgConnection, user_id: Uuid) -> Result<PgRow, RecoveryStoreError> {
    sqlx_core::query::query::<Postgres>("SELECT auth_epoch, security_revision, recovery_key_version, recovery_key_hash, active_recovery_id, status, deleted_at FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id).fetch_optional(conn).await?.ok_or(RecoveryStoreError::Conflict)
}

fn decode_record(row: PgRow) -> Result<RecoveryRecord, sqlx_core::Error> {
    let code: i16 = row.try_get("state")?;
    let state = RecoveryState::from_code(code)
        .ok_or_else(|| sqlx_core::Error::Decode("invalid recovery state".into()))?;
    let digest: Vec<u8> = row.try_get("consume_digest")?;
    let consume_digest = digest
        .try_into()
        .map_err(|_| sqlx_core::Error::Decode("invalid recovery digest".into()))?;
    Ok(RecoveryRecord {
        status: RecoveryStatus {
            operation_id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            auth_epoch: row.try_get("auth_epoch")?,
            account_key_epoch: row.try_get("account_key_epoch")?,
            successor_code_version: row.try_get("successor_code_version")?,
            state,
            revision: row.try_get("revision")?,
            expires_at: row.try_get("expires_at")?,
        },
        resume_token_hash: row.try_get("resume_token_hash")?,
        consume_digest,
    })
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
