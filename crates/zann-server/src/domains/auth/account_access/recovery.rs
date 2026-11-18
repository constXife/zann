//! Restricted recovery authority is accepted only by the recovery router.
use super::{common::*, model::*, *};
use crate::app::AppState;
use chrono::Utc;
use uuid::Uuid;
use zann_core::{
    api::account_access::*,
    recovery::{RecoveryState, RecoveryStatus},
};
use zann_crypto::account_access::{array, decode, encode, Authority, Transcript};
use zann_db::repo::{
    AccessOperation, AccountAccessRepo, RecoveryAdmission, RecoveryMutation, RecoveryRepo,
    RecoveryStart, UserRepo,
};
use zeroize::Zeroizing;
mod consume;
mod credential;
mod data;
mod finish;
mod http;
pub(super) use http::router;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    candidate: Option<OperationData>,
    enrollments: u8,
    nonce: Option<MutationContext>,
    nonce_revision: Option<i64>,
    nonce_expires_at: Option<chrono::DateTime<Utc>>,
}
struct ResumeAuthority {
    id: Uuid,
    user: Uuid,
    hash: Zeroizing<String>,
}
impl ResumeAuthority {
    async fn authenticate(state: &AppState, id: Uuid, hash: Zeroizing<String>) -> Result<Self> {
        let record = RecoveryRepo::new(&state.db)
            .get(id)
            .await?
            .ok_or(AccessError::Rejected)?;
        if !zann_crypto::tokens::constant_time_equal(
            record.resume_token_hash.as_bytes(),
            hash.as_bytes(),
        ) {
            return Err(AccessError::Rejected);
        }
        Ok(Self {
            id,
            user: record.status.user_id,
            hash,
        })
    }
}
fn step(
    authority: &ResumeAuthority,
    id: Uuid,
    revision: i64,
    label: &'static str,
    digest: [u8; 32],
) -> RecoveryMutation {
    RecoveryMutation {
        user_id: authority.user,
        operation_id: authority.id,
        mutation_id: id,
        expected_revision: revision,
        request_digest: Transcript::new(label)
            .field(authority.id.as_bytes())
            .field(&revision.to_be_bytes())
            .field(&digest)
            .digest(),
    }
}
async fn payload_in(
    conn: &mut sqlx_postgres::PgConnection,
    authority: &ResumeAuthority,
    status: &RecoveryStatus,
) -> Result<(AccessOperation, Payload)> {
    let op = AccountAccessRepo::lock_operation_in(conn, authority.id).await?;
    if op.authority_kind != 2
        || op.authority_id != Some(authority.id)
        || op.user_id != Some(authority.user)
        || op.auth_epoch != Some(status.auth_epoch)
        || op.expires_at <= Utc::now()
    {
        return Err(AccessError::Rejected);
    }
    let payload = serde_json::from_slice(&op.payload)?;
    Ok((op, payload))
}
async fn commit_step(
    mut tx: sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    input: &RecoveryMutation,
    mut op: AccessOperation,
    payload: Payload,
    state: RecoveryState,
    result: RecoveryStepResult,
) -> Result<RecoveryStepReply> {
    let status = RecoveryRepo::advance_step_in(&mut tx, input, state).await?;
    if status.state.is_terminal() {
        op.expires_at = Utc::now();
    }
    op.payload = serde_json::to_vec(&payload)?;
    AccountAccessRepo::save_operation_in(&mut tx, &op).await?;
    let reply = RecoveryStepReply {
        mutation_id: input.mutation_id,
        status,
        result,
    };
    RecoveryRepo::record_reply_in(&mut tx, input, &reply.status, &serde_json::to_vec(&reply)?)
        .await?;
    tx.commit().await?;
    Ok(reply)
}
fn candidate_state(payload: &Payload) -> RecoveryState {
    if payload.candidate.as_ref().is_some_and(|data| {
        data.receipt
            .as_ref()
            .is_some_and(|r| r.tested && (r.mode == PasskeyMode::AuthOnly || data.grant.is_some()))
    }) {
        RecoveryState::CredentialReady
    } else {
        RecoveryState::Consumed
    }
}
async fn view(state: &AppState, authority: &ResumeAuthority) -> Result<RecoveryView> {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        let mut account = AccountAccessRepo::lock_account_in(&mut tx, authority.user).await?;
        let mut record = RecoveryRepo::get_in(&mut tx, authority.id)
            .await?
            .ok_or(AccessError::Rejected)?;
        if record.status.user_id != authority.user
            || !zann_crypto::tokens::constant_time_equal(
                record.resume_token_hash.as_bytes(),
                authority.hash.as_bytes(),
            )
        {
            return Err(AccessError::Rejected);
        }
        if !record.status.state.is_terminal() && record.status.expires_at <= Utc::now() {
            record.status = RecoveryRepo::end_in(
                &mut tx,
                authority.user,
                authority.id,
                record.status.revision,
                RecoveryState::Expired,
            )
            .await?;
            account = AccountAccessRepo::lock_account_in(&mut tx, authority.user).await?;
        }
        let user = UserRepo::get_by_id_in(&mut *tx, authority.user)
            .await?
            .ok_or(AccessError::Rejected)?;
        let live = record.status.is_active_at(Utc::now())
            && account.active
            && account.auth_epoch == record.status.auth_epoch
            && account.active_recovery_id == Some(authority.id);
        let candidate = if live {
            let (_, payload) = payload_in(&mut tx, authority, &record.status).await?;
            payload.candidate
        } else {
            None
        };
        let params = crate::domains::auth::core::passwords::kdf_params_from_user(&user);
        let fingerprint = zann_crypto::passwords::kdf_fingerprint(&user.kdf_salt, &params)
            .map_err(AccessError::Kdf)?;
        let (descriptor, descriptor_issue) = descriptor_metadata(state, &account);
        let summary = match &candidate {
            Some(data) => {
                let OperationKind::Enrollment { name, mode } = &data.kind else {
                    return Err(AccessError::Rejected);
                };
                Some(RecoveryCandidate {
                    name: name.clone(),
                    mode: *mode,
                    registered_credential_id: data
                        .credential
                        .as_ref()
                        .map(|credential| encode(credential.cred_id.as_ref())),
                })
            }
            None => None,
        };
        let result = RecoveryView {
            status: record.status,
            security_revision: account.security_revision,
            descriptor,
            descriptor_issue,
            candidate: summary,
            receipt: candidate.as_ref().and_then(|c| c.receipt.clone()),
            grant: candidate.and_then(|c| c.grant),
            kdf: zann_core::api::auth::PreloginResponse {
                kdf_salt: user.kdf_salt,
                kdf_params: zann_core::api::auth::KdfParams {
                    algorithm: params.algorithm,
                    iterations: params.iterations,
                    memory_kb: params.memory_kb,
                    parallelism: params.parallelism,
                },
                salt_fingerprint: fingerprint,
            },
        };
        tx.commit().await?;
        Ok(result)
    })
    .await
    .map_err(|_| AccessError::Timeout)?
}
