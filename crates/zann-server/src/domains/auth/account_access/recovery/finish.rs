use super::*;
use zann_db::repo::NewPasskey;
pub(super) async fn complete(
    state: &AppState,
    authority: &ResumeAuthority,
    input: &RecoveryComplete,
) -> Result<RecoveryStepReply> {
    if !zann_crypto::recovery::valid_recovery_code(&input.next_recovery_key) {
        return Err(AccessError::Rejected);
    }
    let digest = Transcript::new("zann recovery completion body v1")
        .field(&input.successor_code_version.to_be_bytes())
        .field(
            &Transcript::new("zann recovery code commitment v1")
                .field(input.next_recovery_key.as_bytes())
                .digest(),
        )
        .digest();
    let mutation = step(
        authority,
        input.mutation_id,
        input.expected_revision,
        "zann recovery complete v1",
        digest,
    );
    {
        // Historical replies are reconciled before any fresh KDF/revision check.
        let mut tx = begin(state).await?;
        if let RecoveryAdmission::Replay(reply) =
            RecoveryRepo::admit_step_in(&mut tx, &mutation, &authority.hash).await?
        {
            return Ok(serde_json::from_slice(&reply)?);
        }
    }
    let user = UserRepo::new(&state.db)
        .get_by_id(authority.user)
        .await?
        .ok_or(AccessError::Rejected)?;
    let hash = super::super::codes::user_code_hash(state, &user, &input.next_recovery_key).await?;
    if !user.recovery_key_hash.as_ref().is_some_and(|stored| {
        zann_crypto::tokens::constant_time_equal(stored.as_bytes(), hash.as_bytes())
    }) {
        return Err(AccessError::Rejected);
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        let status = match RecoveryRepo::admit_step_in(&mut tx, &mutation, &authority.hash).await? {
            RecoveryAdmission::Replay(reply) => return Ok(serde_json::from_slice(&reply)?),
            RecoveryAdmission::Current(status) => status,
        };
        let (op, mut payload) = payload_in(&mut tx, authority, &status).await?;
        let account = AccountAccessRepo::lock_account_in(&mut tx, authority.user).await?;
        if status.state != RecoveryState::CredentialReady
            || candidate_state(&payload) != RecoveryState::CredentialReady
            || account.row_version != user.row_version
            || account.recovery_key_version != input.successor_code_version
            || status.successor_code_version != input.successor_code_version
        {
            return Err(AccessError::Conflict);
        }
        let data = payload.candidate.as_ref().ok_or(AccessError::Rejected)?;
        let OperationKind::Enrollment { name, mode } = &data.kind else {
            return Err(AccessError::Rejected);
        };
        let receipt = data.receipt.as_ref().ok_or(AccessError::Rejected)?;
        let key = NewPasskey {
            credential_id: decode(&receipt.credential_id, 1024)?,
            user_id: authority.user,
            name: name.clone(),
            mode: *mode,
            credential: serde_json::to_vec(data.credential.as_ref().ok_or(AccessError::Rejected)?)?,
            grant: data.grant.as_ref().map(serde_json::to_vec).transpose()?,
            auth_epoch: status.auth_epoch,
        };
        let status =
            RecoveryRepo::advance_step_in(&mut tx, &mutation, RecoveryState::Completed).await?;
        AccountAccessRepo::create_in(&mut tx, &key).await?;
        payload.candidate = None;
        payload.nonce = None;
        payload.nonce_revision = None;
        payload.nonce_expires_at = None;
        let mut op = op;
        op.expires_at = Utc::now();
        op.payload = serde_json::to_vec(&payload)?;
        AccountAccessRepo::save_operation_in(&mut tx, &op).await?;
        let reply = RecoveryStepReply {
            mutation_id: mutation.mutation_id,
            status,
            result: RecoveryStepResult::Completed,
        };
        RecoveryRepo::record_reply_in(
            &mut tx,
            &mutation,
            &reply.status,
            &serde_json::to_vec(&reply)?,
        )
        .await?;
        tx.commit().await?;
        Ok(reply)
    })
    .await
    .map_err(|_| AccessError::Timeout)?
}
pub(super) async fn abandon(
    state: &AppState,
    authority: &ResumeAuthority,
    input: &RecoveryAbandon,
) -> Result<RecoveryStepReply> {
    let mutation = step(
        authority,
        input.mutation_id,
        input.expected_revision,
        "zann recovery abandon v1",
        Transcript::new("zann recovery abandon body v1").digest(),
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        let status = match RecoveryRepo::admit_step_in(&mut tx, &mutation, &authority.hash).await? {
            RecoveryAdmission::Replay(reply) => return Ok(serde_json::from_slice(&reply)?),
            RecoveryAdmission::Current(status) => status,
        };
        let (op, mut payload) = payload_in(&mut tx, authority, &status).await?;
        payload.candidate = None;
        payload.nonce = None;
        payload.nonce_revision = None;
        payload.nonce_expires_at = None;
        commit_step(
            tx,
            &mutation,
            op,
            payload,
            RecoveryState::Abandoned,
            RecoveryStepResult::Abandoned,
        )
        .await
    })
    .await
    .map_err(|_| AccessError::Timeout)?
}
