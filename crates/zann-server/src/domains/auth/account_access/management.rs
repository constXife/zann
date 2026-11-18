//! Ordinary security mutations share current-session guards and bounded receipts.
use super::{common::*, security::management_proof_in, *};
use crate::app::AppState;
use sqlx_postgres::Postgres;
use zann_core::{api::account_access::*, Session};
use zann_crypto::account_access::{decode, Transcript};
use zann_db::repo::{AccountAccessRepo, SessionRepo, UserRepo};

fn request_digest(label: &'static str, revision: i64, body: [u8; 32]) -> [u8; 32] {
    Transcript::new(label)
        .field(&revision.to_be_bytes())
        .field(&body)
        .digest()
}
pub async fn revoke(
    state: &AppState,
    session: &Session,
    input: &RevokeCredential,
) -> Result<SecurityReceipt> {
    relying_party(state)?;
    if input.mutation_id.get_version_num() != 4 {
        return Err(AccessError::Rejected);
    }
    let id = decode(&input.credential_id, 1024)?;
    let body = input.digest()?;
    let digest = request_digest(
        "zann account revoke request v1",
        input.expected_revision,
        body,
    );
    tokio::time::timeout(std::time::Duration::from_secs(2),async {
        let mut tx=begin(state).await?;
        SessionRepo::guard_session_in(&mut tx,session).await?;
        if let Some(reply)=AccountAccessRepo::receipt_in(&mut tx,session.user_id,input.mutation_id,&digest).await? {
            return Ok(serde_json::from_slice(&reply)?);
        }
        let account=guarded(&mut tx,session,input.expected_revision).await?;
        let keys=sqlx_core::query::query::<Postgres>("SELECT credential_id FROM account_passkeys WHERE user_id=$1 AND revoked_at IS NULL LIMIT 17")
            .bind(session.user_id).fetch_all(&mut *tx).await?;
        if keys.len()<=1||keys.len()>MAX_CREDENTIALS {return Err(AccessError::Rejected);}
        management_proof_in(&mut tx,state,session,&account,&input.proof,MutationPurpose::CredentialRevoke,body).await?;
        AccountAccessRepo::revoke_in(&mut tx,session.user_id,&id,input.revoke_sessions).await?;
        let revision=AccountAccessRepo::advance_revision_in(&mut tx,session.user_id,account.security_revision).await?;
        let reply=SecurityReceipt{mutation_id:input.mutation_id,security_revision:revision,credential_id:Some(input.credential_id.clone()),recovery_key_version:None,recovery_candidate_id:None};
        AccountAccessRepo::save_receipt_in(&mut tx,session.user_id,input.mutation_id,&digest,&serde_json::to_vec(&reply)?).await?;
        tx.commit().await?;
        Ok(reply)
    }).await.map_err(|_|AccessError::Timeout)?
}
pub async fn activate_code(
    state: &AppState,
    session: &Session,
    input: &ActivateRecoveryCode,
) -> Result<SecurityReceipt> {
    relying_party(state)?;
    let body = input.digest()?;
    let digest = request_digest(
        "zann recovery activation request v1",
        input.expected_revision,
        body,
    );
    // Replays need not run Argon2, but must still prove a current session.
    {
        let mut tx = begin(state).await?;
        SessionRepo::guard_session_in(&mut tx, session).await?;
        if let Some(reply) =
            AccountAccessRepo::receipt_in(&mut tx, session.user_id, input.candidate_id, &digest)
                .await?
        {
            return Ok(serde_json::from_slice(&reply)?);
        }
    }
    let user = UserRepo::new(&state.db)
        .get_by_id(session.user_id)
        .await?
        .ok_or(AccessError::Rejected)?;
    let hash = super::codes::user_code_hash(state, &user, &input.recovery_key).await?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        SessionRepo::guard_session_in(&mut tx, session).await?;
        if let Some(reply) =
            AccountAccessRepo::receipt_in(&mut tx, session.user_id, input.candidate_id, &digest)
                .await?
        {
            return Ok(serde_json::from_slice(&reply)?);
        }
        let account = guarded(&mut tx, session, input.expected_revision).await?;
        if account.row_version != user.row_version {
            return Err(AccessError::Conflict);
        }
        if !AccountAccessRepo::has_credentials_in(&mut tx, session.user_id).await? {
            return Err(AccessError::Rejected);
        }
        if state.config.server.personal_vaults_enabled
            && (descriptor(&account)?.is_none()
                || !matches!(input.proof, ManagementProof::Custody { .. }))
        {
            return Err(AccessError::Rejected);
        }
        management_proof_in(
            &mut tx,
            state,
            session,
            &account,
            &input.proof,
            MutationPurpose::CodeRotate,
            body,
        )
        .await?;
        let reply = AccountAccessRepo::activate_code_in(
            &mut tx,
            session.user_id,
            account.security_revision,
            input.candidate_id,
            &hash,
            input.disable_password,
        )
        .await?;
        AccountAccessRepo::save_receipt_in(
            &mut tx,
            session.user_id,
            input.candidate_id,
            &digest,
            &serde_json::to_vec(&reply)?,
        )
        .await?;
        tx.commit().await?;
        Ok(reply)
    })
    .await
    .map_err(|_| AccessError::Timeout)?
}
