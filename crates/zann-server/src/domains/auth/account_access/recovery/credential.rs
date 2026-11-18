use super::*;
pub(super) async fn options(
    state: &AppState,
    authority: &ResumeAuthority,
    input: &RecoveryCredentialOptions,
) -> Result<RecoveryStepReply> {
    let rp = relying_party(state)?;
    let mutation = step(
        authority,
        input.mutation_id,
        input.expected_revision,
        "zann recovery credential options v1",
        json_digest("zann recovery options body v1", &input.action)?,
    );
    let user = UserRepo::new(&state.db)
        .get_by_id(authority.user)
        .await?
        .ok_or(AccessError::Rejected)?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        let status = match RecoveryRepo::admit_step_in(&mut tx, &mutation, &authority.hash).await? {
            RecoveryAdmission::Replay(reply) => return Ok(serde_json::from_slice(&reply)?),
            RecoveryAdmission::Current(status) => status,
        };
        let (op, mut payload) = payload_in(&mut tx, authority, &status).await?;
        let account = AccountAccessRepo::lock_account_in(&mut tx, authority.user).await?;
        let result = match &input.action {
            RecoveryOptionsPhase::Register { name, mode } => {
                if name.is_empty()
                    || name.len() > 128
                    || name.chars().any(char::is_control)
                    || payload.enrollments >= 16
                {
                    return Err(AccessError::Rejected);
                }
                if *mode == PasskeyMode::VaultUnlock
                    && (!state.config.server.personal_vaults_enabled
                        || bound_descriptor(state, &account)?.is_none())
                {
                    return Err(AccessError::Rejected);
                }
                let (options, registration) =
                    rp.registration(authority.id, authority.user, &user.email, Vec::new())?;
                let mut data = OperationData::new(
                    OperationKind::Enrollment {
                        name: name.clone(),
                        mode: *mode,
                    },
                    options.clone(),
                );
                data.registration = Some(registration);
                payload.candidate = Some(data);
                payload.enrollments += 1;
                RecoveryStepResult::Ceremony { options }
            }
            RecoveryOptionsPhase::Test => {
                let data = payload.candidate.as_mut().ok_or(AccessError::Rejected)?;
                let options = super::super::candidate::refresh_test(
                    &rp,
                    data,
                    authority.id,
                    input.mutation_id,
                )?;
                RecoveryStepResult::Ceremony { options }
            }
            RecoveryOptionsPhase::Grant { body_digest } => {
                let digest = array::<32>(body_digest)?;
                let data = payload.candidate.as_ref().ok_or(AccessError::Rejected)?;
                let receipt = data.receipt.as_ref().ok_or(AccessError::Rejected)?;
                if receipt.mode != PasskeyMode::VaultUnlock
                    || data.grant.is_some()
                    || bound_descriptor(state, &account)?.is_none()
                {
                    return Err(AccessError::Rejected);
                }
                let context = MutationContext {
                    server_id: server_id(state),
                    user_id: authority.user,
                    authority: Authority::Recovery,
                    authority_id: authority.id,
                    security_revision: account.security_revision as u64,
                    nonce: encode(&zann_crypto::ipc_signatures::random_nonce()),
                    purpose: MutationPurpose::GrantAdd,
                    body_digest: encode(&digest),
                };
                payload.nonce = Some(context.clone());
                payload.nonce_revision = Some(status.revision + 1);
                payload.nonce_expires_at = Some(Utc::now() + chrono::Duration::seconds(120));
                RecoveryStepResult::Custody { context }
            }
        };
        if !matches!(input.action, RecoveryOptionsPhase::Grant { .. }) {
            payload.nonce = None;
            payload.nonce_revision = None;
            payload.nonce_expires_at = None;
        }
        let next = candidate_state(&payload);
        commit_step(tx, &mutation, op, payload, next, result).await
    })
    .await
    .map_err(|_| AccessError::Timeout)?
}
pub(super) async fn finish(
    state: &AppState,
    authority: &ResumeAuthority,
    input: &RecoveryCredentialFinish,
) -> Result<RecoveryStepReply> {
    let rp = relying_party(state)?;
    let mutation = step(
        authority,
        input.mutation_id,
        input.expected_revision,
        "zann recovery credential finish v1",
        json_digest("zann recovery finish body v1", &input.action)?,
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        let status = match RecoveryRepo::admit_step_in(&mut tx, &mutation, &authority.hash).await? {
            RecoveryAdmission::Replay(reply) => return Ok(serde_json::from_slice(&reply)?),
            RecoveryAdmission::Current(status) => status,
        };
        let (op, mut payload) = payload_in(&mut tx, authority, &status).await?;
        let data = payload.candidate.as_mut().ok_or(AccessError::Rejected)?;
        let result = match &input.action {
            RecoveryFinishPhase::Register { response } => RecoveryStepResult::Ceremony {
                options: super::super::candidate::register(&rp, data, authority.id, response)?,
            },
            RecoveryFinishPhase::Test { response } => RecoveryStepResult::Tested {
                receipt: super::super::candidate::test(
                    &rp,
                    data,
                    authority.id,
                    authority.user,
                    response,
                )?,
            },
            RecoveryFinishPhase::Grant { grant, proof } => {
                let account = AccountAccessRepo::lock_account_in(&mut tx, authority.user).await?;
                let descriptor = bound_descriptor(state, &account)?.ok_or(AccessError::Rejected)?;
                let receipt = data.receipt.as_ref().ok_or(AccessError::Rejected)?;
                if receipt.mode != PasskeyMode::VaultUnlock
                    || grant.credential_id != receipt.credential_id
                    || grant.rp_id
                        != state
                            .config
                            .auth
                            .passkey
                            .as_ref()
                            .ok_or(AccessError::Disabled)?
                            .rp_id
                    || payload.nonce.as_ref() != Some(&proof.context)
                    || payload.nonce_revision != Some(status.revision)
                    || payload
                        .nonce_expires_at
                        .is_none_or(|expiry| expiry <= Utc::now())
                    || proof.context.security_revision != account.security_revision as u64
                    || proof.context.body_digest != encode(&grant.body_digest()?)
                {
                    return Err(AccessError::Rejected);
                }
                grant.verify(&descriptor)?;
                proof.context.verify(&descriptor, &proof.signature)?;
                data.grant = Some(*grant.clone());
                RecoveryStepResult::GrantReady {
                    grant_id: grant.grant_id,
                }
            }
        };
        payload.nonce = None;
        payload.nonce_revision = None;
        payload.nonce_expires_at = None;
        let next = candidate_state(&payload);
        commit_step(tx, &mutation, op, payload, next, result).await
    })
    .await
    .map_err(|_| AccessError::Timeout)?
}
