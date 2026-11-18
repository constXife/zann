use super::*;
use std::sync::Arc;
use zann_core::UserStatus;
pub(super) async fn consume(
    state: &AppState,
    input: &RecoveryConsume,
    resume_hash: Zeroizing<String>,
) -> Result<RecoveryConsumeReceipt> {
    relying_party(state)?;
    check_device(&input.device)?;
    let digest = input.digest(&server_id(state))?;
    // Resume proof precedes KDF/verifier checks: a burned code is never verified
    // again merely to resolve the immutable result of this exact operation.
    if let Some(record) = RecoveryRepo::new(&state.db).get(input.operation_id).await? {
        return replay(&record, &resume_hash, &digest);
    }
    let user = UserRepo::new(&state.db)
        .get_by_email(&input.locator)
        .await?;
    let profile = user
        .as_ref()
        .map(|u| Arc::new(super::super::runtime::CodeProfile::user(u)))
        .unwrap_or_else(|| state.account_access.dummy(state));
    let old = super::super::codes::hash_code(state, profile, &input.recovery_key).await?;
    // A synthetic valid-format verifier receives the configured KDF work for an
    // unknown subject. It can never authenticate one, including on a hash match.
    let expected = user
        .as_ref()
        .and_then(|u| u.recovery_key_hash.as_deref())
        .unwrap_or("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    if !zann_crypto::tokens::constant_time_equal(old.as_bytes(), expected.as_bytes()) {
        return Err(AccessError::Rejected);
    }
    let user = user.ok_or(AccessError::Rejected)?;
    if user.status != UserStatus::Active || user.deleted_at.is_some() {
        return Err(AccessError::Rejected);
    }
    let account = AccountAccessRepo::new(&state.db)
        .account(user.id)
        .await?
        .ok_or(AccessError::Rejected)?;
    if account.recovery_candidate_id.is_none() || account.recovery_key_version <= 0 {
        return Err(AccessError::Rejected);
    }
    let next = super::super::codes::user_code_hash(state, &user, &input.next_recovery_key).await?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        let locked = AccountAccessRepo::lock_account_in(&mut tx, user.id).await?;
        if let Some(record) = RecoveryRepo::get_in(&mut tx, input.operation_id).await? {
            return replay(&record, &resume_hash, &digest);
        }
        if locked.auth_epoch != account.auth_epoch
            || locked.security_revision != account.security_revision
        {
            return Err(AccessError::Rejected);
        }
        let key_epoch = descriptor_metadata(state, &locked)
            .0
            .map(|d| i64::try_from(d.key_epoch).map_err(|_| AccessError::Rejected))
            .transpose()?;
        let status = RecoveryRepo::start_in(
            &mut tx,
            RecoveryStart {
                operation_id: input.operation_id,
                user_id: user.id,
                expected_auth_epoch: user.auth_epoch,
                expected_security_revision: account.security_revision,
                expected_code_version: account.recovery_key_version,
                expected_code_hash: user
                    .recovery_key_hash
                    .as_deref()
                    .ok_or(AccessError::Rejected)?,
                successor_code_hash: &next,
                resume_token_hash: &resume_hash,
                consume_digest: digest,
                account_key_epoch: key_epoch,
            },
        )
        .await
        .map_err(|error| match error {
            zann_db::repo::RecoveryStoreError::Conflict => AccessError::Rejected,
            other => AccessError::Recovery(other),
        })?;
        // Slot/quota failure rolls back the entire burn and all revocations.
        let payload = Payload {
            candidate: None,
            enrollments: 0,
            nonce: None,
            nonce_revision: None,
            nonce_expires_at: None,
        };
        let op = AccessOperation {
            operation_id: status.operation_id,
            user_id: Some(user.id),
            authority_kind: 2,
            authority_id: Some(status.operation_id),
            auth_epoch: Some(status.auth_epoch),
            security_revision: Some(account.security_revision + 1),
            request_digest: digest,
            payload: serde_json::to_vec(&payload)?,
            revision: 0,
            expires_at: status.expires_at,
        };
        AccountAccessRepo::allocate_in(&mut tx, &op).await?;
        tx.commit().await?;
        Ok(RecoveryConsumeReceipt::from(&status))
    })
    .await
    .map_err(|_| AccessError::Timeout)?
}
fn replay(
    record: &zann_db::repo::RecoveryRecord,
    hash: &str,
    digest: &[u8; 32],
) -> Result<RecoveryConsumeReceipt> {
    if !zann_crypto::tokens::constant_time_equal(
        record.resume_token_hash.as_bytes(),
        hash.as_bytes(),
    ) {
        return Err(AccessError::Rejected);
    }
    if !zann_crypto::tokens::constant_time_equal(&record.consume_digest, digest) {
        return Err(AccessError::Conflict);
    }
    Ok(RecoveryConsumeReceipt::from(&record.status))
}
