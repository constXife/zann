use super::{
    common::*,
    model::*,
    security::{load_operation, management_proof_in},
    *,
};
use crate::app::AppState;
use zann_core::api::account_access::*;
use zann_core::{Session, User};
use zann_crypto::account_access::{decode, Transcript};
use zann_db::repo::{AccountAccessRepo, NewPasskey, SessionRepo, UserRepo};

pub async fn options(
    state: &AppState,
    session: &Session,
    user: &User,
    input: &EnrollmentRequest,
) -> Result<CeremonyOptions> {
    let rp = relying_party(state)?;
    if input.operation_id.get_version_num() != 4
        || input.name.is_empty()
        || input.name.len() > 128
        || input.name.chars().any(char::is_control)
        || (!state.config.server.personal_vaults_enabled && input.mode == PasskeyMode::VaultUnlock)
    {
        return Err(AccessError::Rejected);
    }
    let digest = json_digest("zann account enrollment request v1", input)?;
    if let Some(op) = AccountAccessRepo::new(&state.db)
        .operation(input.operation_id)
        .await?
    {
        check_operation(&op, session)?;
        if op.request_digest != digest {
            return Err(AccessError::Conflict);
        }
        let data: OperationData = serde_json::from_slice(&op.payload)?;
        return Ok(data.options);
    }
    let keys = AccountAccessRepo::new(&state.db)
        .credentials(session.user_id)
        .await?;
    if keys.len() >= MAX_CREDENTIALS {
        return Err(AccessError::Capacity);
    }
    let credentials = keys
        .iter()
        .map(|key| serde_json::from_slice(&key.credential))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (options, registration) = rp.registration(
        input.operation_id,
        session.user_id,
        &user.email,
        credentials,
    )?;
    let mut data = OperationData::new(
        OperationKind::Enrollment {
            name: input.name.clone(),
            mode: input.mode,
        },
        options.clone(),
    );
    data.registration = Some(registration);
    let slot = new_slot(
        input.operation_id,
        session,
        input.expected_revision,
        digest,
        &data,
    )?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        let account = guarded(&mut tx, session, input.expected_revision).await?;
        if state.config.server.personal_vaults_enabled
            && bound_descriptor(state, &account)?.is_none()
        {
            return Err(AccessError::Rejected);
        }
        AccountAccessRepo::allocate_in(&mut tx, &slot).await?;
        tx.commit().await?;
        Ok::<_, AccessError>(())
    })
    .await
    .map_err(|_| AccessError::Timeout)??;
    Ok(options)
}
pub async fn register(
    state: &AppState,
    session: &Session,
    input: &CeremonyFinish,
) -> Result<CeremonyOptions> {
    let rp = relying_party(state)?;
    let (mut op, mut data) = load_operation(state, session, input.operation_id).await?;
    let options = super::candidate::register(&rp, &mut data, op.operation_id, &input.response)?;
    op.payload = serde_json::to_vec(&data)?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        guarded(
            &mut tx,
            session,
            op.security_revision.ok_or(AccessError::Rejected)?,
        )
        .await?;
        AccountAccessRepo::save_operation_in(&mut tx, &op).await?;
        tx.commit().await?;
        Ok::<_, AccessError>(())
    })
    .await
    .map_err(|_| AccessError::Timeout)??;
    Ok(options)
}
pub async fn test(
    state: &AppState,
    session: &Session,
    input: &CeremonyFinish,
) -> Result<CandidateReceipt> {
    let rp = relying_party(state)?;
    let (mut op, mut data) = load_operation(state, session, input.operation_id).await?;
    let receipt = super::candidate::test(
        &rp,
        &mut data,
        op.operation_id,
        session.user_id,
        &input.response,
    )?;
    op.payload = serde_json::to_vec(&data)?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        guarded(
            &mut tx,
            session,
            op.security_revision.ok_or(AccessError::Rejected)?,
        )
        .await?;
        AccountAccessRepo::save_operation_in(&mut tx, &op).await?;
        tx.commit().await?;
        Ok::<_, AccessError>(())
    })
    .await
    .map_err(|_| AccessError::Timeout)??;
    Ok(receipt)
}
pub async fn grant(
    state: &AppState,
    session: &Session,
    input: &StageGrant,
) -> Result<CandidateReceipt> {
    let (mut op, mut data) = load_operation(state, session, input.operation_id).await?;
    let receipt = data.receipt.clone().ok_or(AccessError::Rejected)?;
    if receipt.mode != PasskeyMode::VaultUnlock
        || receipt.credential_id != input.grant.credential_id
        || input.grant.rp_id != configuration_rp(state)?
    {
        return Err(AccessError::Rejected);
    }
    if let Some(existing) = &data.grant {
        if existing == &input.grant {
            return Ok(receipt);
        }
        return Err(AccessError::Conflict);
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        let account = guarded(
            &mut tx,
            session,
            op.security_revision.ok_or(AccessError::Rejected)?,
        )
        .await?;
        input
            .grant
            .verify(&bound_descriptor(state, &account)?.ok_or(AccessError::Rejected)?)?;
        verify_custody(
            &mut tx,
            state,
            session,
            &account,
            &input.proof,
            MutationPurpose::GrantAdd,
            input.grant.body_digest()?,
        )
        .await?;
        data.grant = Some(input.grant.clone());
        op.payload = serde_json::to_vec(&data)?;
        AccountAccessRepo::save_operation_in(&mut tx, &op).await?;
        tx.commit().await?;
        Ok::<_, AccessError>(())
    })
    .await
    .map_err(|_| AccessError::Timeout)??;
    Ok(receipt)
}
pub async fn activate(
    state: &AppState,
    session: &Session,
    input: &ActivateCredential,
) -> Result<SecurityReceipt> {
    relying_party(state)?;
    let request_digest = Transcript::new("zann account credential activation request v1")
        .field(input.operation_id.as_bytes())
        .field(&input.expected_revision.to_be_bytes())
        .digest();
    {
        let mut tx = begin(state).await?;
        SessionRepo::guard_session_in(&mut tx, session).await?;
        if let Some(reply) = AccountAccessRepo::receipt_in(
            &mut tx,
            session.user_id,
            input.operation_id,
            &request_digest,
        )
        .await?
        {
            return Ok(serde_json::from_slice(&reply)?);
        }
    }
    let (mut op, data) = load_operation(state, session, input.operation_id).await?;
    if op.security_revision != Some(input.expected_revision) {
        return Err(AccessError::Conflict);
    }
    let receipt = data.receipt.clone().ok_or(AccessError::Rejected)?;
    let digest = receipt.activation_digest()?;
    let OperationKind::Enrollment { name, mode } = &data.kind else {
        return Err(AccessError::Rejected);
    };
    if *mode == PasskeyMode::VaultUnlock && data.grant.is_none() {
        return Err(AccessError::Rejected);
    }
    let initial_password_user =
        if let ManagementProof::InitialPassword { server_password } = &input.proof {
            if *mode == PasskeyMode::VaultUnlock
                || !AccountAccessRepo::new(&state.db)
                    .credentials(session.user_id)
                    .await?
                    .is_empty()
            {
                return Err(AccessError::Rejected);
            }
            let user = UserRepo::new(&state.db)
                .get_by_id(session.user_id)
                .await?
                .ok_or(AccessError::Rejected)?;
            verify_server_password(state, &user, server_password).await?;
            Some(user)
        } else {
            None
        };
    let key = NewPasskey {
        credential_id: decode(&receipt.credential_id, 1024)?,
        user_id: session.user_id,
        name: name.clone(),
        mode: *mode,
        credential: serde_json::to_vec(data.credential.as_ref().ok_or(AccessError::Rejected)?)?,
        grant: data.grant.as_ref().map(serde_json::to_vec).transpose()?,
        auth_epoch: session.auth_epoch,
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        SessionRepo::guard_session_in(&mut tx, session).await?;
        if let Some(reply) = AccountAccessRepo::receipt_in(
            &mut tx,
            session.user_id,
            input.operation_id,
            &request_digest,
        )
        .await?
        {
            return Ok(serde_json::from_slice(&reply)?);
        }
        let account = guarded(&mut tx, session, input.expected_revision).await?;
        if op.security_revision != Some(account.security_revision) {
            return Err(AccessError::Conflict);
        }
        if let Some(user) = initial_password_user {
            if account.row_version != user.row_version
                || AccountAccessRepo::has_credentials_in(&mut tx, session.user_id).await?
            {
                return Err(AccessError::Conflict);
            }
        } else {
            management_proof_in(
                &mut tx,
                state,
                session,
                &account,
                &input.proof,
                MutationPurpose::CredentialAdd,
                digest,
            )
            .await?;
        }
        AccountAccessRepo::create_in(&mut tx, &key).await?;
        let revision = AccountAccessRepo::advance_revision_in(
            &mut tx,
            session.user_id,
            account.security_revision,
        )
        .await?;
        let reply = SecurityReceipt {
            mutation_id: op.operation_id,
            security_revision: revision,
            credential_id: Some(receipt.credential_id.clone()),
            recovery_key_version: None,
            recovery_candidate_id: None,
        };
        AccountAccessRepo::save_receipt_in(
            &mut tx,
            session.user_id,
            input.operation_id,
            &request_digest,
            &serde_json::to_vec(&reply)?,
        )
        .await?;
        op.expires_at = chrono::Utc::now();
        AccountAccessRepo::save_operation_in(&mut tx, &op).await?;
        tx.commit().await?;
        Ok::<_, AccessError>(reply)
    })
    .await
    .map_err(|_| AccessError::Timeout)?
}
fn configuration_rp(state: &AppState) -> Result<&str> {
    Ok(&state
        .config
        .auth
        .passkey
        .as_ref()
        .ok_or(AccessError::Disabled)?
        .rp_id)
}

pub async fn test_options(
    state: &AppState,
    session: &Session,
    input: &CandidateTestOptions,
) -> Result<CeremonyOptions> {
    let rp = relying_party(state)?;
    let (mut op, mut data) = load_operation(state, session, input.operation_id).await?;
    let options =
        super::candidate::refresh_test(&rp, &mut data, op.operation_id, input.request_id)?;
    op.payload = serde_json::to_vec(&data)?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        guarded(
            &mut tx,
            session,
            op.security_revision.ok_or(AccessError::Rejected)?,
        )
        .await?;
        AccountAccessRepo::save_operation_in(&mut tx, &op).await?;
        tx.commit().await?;
        Ok::<_, AccessError>(())
    })
    .await
    .map_err(|_| AccessError::Timeout)??;
    Ok(options)
}
