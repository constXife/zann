//! Pure RP candidate transitions shared by ordinary and restricted authority.
use super::{common::json_digest, model::*, *};
use chrono::Utc;
use zann_core::api::account_access::*;
use zann_crypto::account_access::encode;
pub(super) fn register(
    rp: &super::rp::RelyingParty,
    data: &mut OperationData,
    id: uuid::Uuid,
    response: &CeremonyResponse,
) -> Result<CeremonyOptions> {
    let digest = response.registration_digest()?;
    if let Some(existing) = data.register_response_digest {
        if existing != digest {
            return Err(AccessError::Conflict);
        }
        return data.register_reply.clone().ok_or(AccessError::Conflict);
    }
    if data.challenge_expires_at <= Utc::now()
        || !matches!(data.kind, OperationKind::Enrollment { .. })
    {
        return Err(AccessError::Rejected);
    }
    let credential = rp.finish_registration(
        response,
        data.registration.as_ref().ok_or(AccessError::Rejected)?,
    )?;
    let (options, assertion) = rp.assertion(id, CeremonyPhase::Test, vec![credential.clone()])?;
    data.register_response_digest = Some(digest);
    data.register_reply = Some(options.clone());
    data.options = options.clone();
    data.registration = None;
    data.assertion = Some(assertion);
    data.credential = Some(credential);
    data.challenge_expires_at = Utc::now() + chrono::Duration::seconds(CHALLENGE_SECONDS);
    data.test_rounds = 1;
    Ok(options)
}
pub(super) fn test(
    rp: &super::rp::RelyingParty,
    data: &mut OperationData,
    id: uuid::Uuid,
    user: uuid::Uuid,
    response: &CeremonyResponse,
) -> Result<CandidateReceipt> {
    let digest = json_digest("zann account candidate assertion v1", response)?;
    if let Some(existing) = data.test_response_digest {
        if existing != digest {
            return Err(AccessError::Conflict);
        }
        return data.receipt.clone().ok_or(AccessError::Conflict);
    }
    if data.challenge_expires_at <= Utc::now() {
        return Err(AccessError::Rejected);
    }
    let OperationKind::Enrollment { mode, .. } = data.kind else {
        return Err(AccessError::Rejected);
    };
    let verified = rp.finish_assertion(
        response,
        data.assertion.take().ok_or(AccessError::Rejected)?,
        data.credential.take().ok_or(AccessError::Rejected)?,
        user,
        true,
    )?;
    let receipt = CandidateReceipt {
        operation_id: id,
        receipt_id: data
            .receipt
            .as_ref()
            .map(|r| r.receipt_id)
            .unwrap_or_else(uuid::Uuid::new_v4),
        credential_id: encode(verified.cred_id.as_ref()),
        registration_digest: encode(&data.register_response_digest.ok_or(AccessError::Rejected)?),
        tested: true,
        mode,
    };
    data.credential = Some(verified);
    data.test_response_digest = Some(digest);
    data.receipt = Some(receipt.clone());
    Ok(receipt)
}

pub(super) fn refresh_test(
    rp: &super::rp::RelyingParty,
    data: &mut OperationData,
    id: uuid::Uuid,
    request_id: uuid::Uuid,
) -> Result<CeremonyOptions> {
    if let Some((_, options)) = data
        .test_refreshes
        .iter()
        .find(|(existing, _)| *existing == request_id)
    {
        return Ok(options.clone());
    }
    if request_id.get_version_num() != 4 || data.test_rounds >= 16 {
        return Err(AccessError::Capacity);
    }
    let credential = data.credential.as_ref().ok_or(AccessError::Rejected)?;
    let (options, assertion) = rp.assertion(id, CeremonyPhase::Test, vec![credential.clone()])?;
    data.options = options.clone();
    data.assertion = Some(assertion);
    data.test_response_digest = None;
    data.challenge_expires_at = Utc::now() + chrono::Duration::seconds(CHALLENGE_SECONDS);
    data.test_rounds += 1;
    data.test_refreshes.push((request_id, options.clone()));
    Ok(options)
}
