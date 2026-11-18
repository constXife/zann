use super::{common::*, model::*, *};
use crate::app::AppState;
use crate::domains::auth::{
    helpers::{build_device, build_login_response},
    service::issuance::issue_login_session_in,
};
use chrono::Utc;
use uuid::Uuid;
use zann_core::api::account_access::*;
use zann_crypto::account_access::{decode, encode};
use zann_db::repo::{AccessOperation, AccountAccessRepo, SessionRepo, UserRepo};

pub async fn options(state: &AppState, input: &PasskeyLoginOptions) -> Result<CeremonyOptions> {
    let rp = relying_party(state)?;
    check_device(&input.device)?;
    if input.operation_id.get_version_num() != 4 {
        return Err(AccessError::Rejected);
    }
    // A login attempt is never re-dispatched as a new authority after ambiguity.
    let digest = json_digest("zann account passkey login request v1", input)?;
    if let Some(op) = AccountAccessRepo::new(&state.db)
        .operation(input.operation_id)
        .await?
    {
        if op.authority_kind != 3 || op.request_digest != digest || op.expires_at <= Utc::now() {
            return Err(AccessError::Conflict);
        }
        let data: OperationData = serde_json::from_slice(&op.payload)?;
        if data.login_consumed {
            return Err(AccessError::Conflict);
        }
        return Ok(data.options);
    }
    let (options, assertion) =
        rp.assertion(input.operation_id, CeremonyPhase::Login, Vec::new())?;
    let mut data = OperationData::new(
        OperationKind::Login {
            device: input.device.clone(),
        },
        options.clone(),
    );
    data.assertion = Some(assertion);
    let mut op = AccessOperation {
        operation_id: input.operation_id,
        user_id: None,
        authority_kind: 3,
        authority_id: None,
        auth_epoch: None,
        security_revision: None,
        request_digest: digest,
        payload: serde_json::to_vec(&data)?,
        revision: 0,
        expires_at: data.challenge_expires_at,
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        data.credential_fence = Some(AccountAccessRepo::credential_fence_in(&mut tx).await?);
        op.payload = serde_json::to_vec(&data)?;
        AccountAccessRepo::allocate_in(&mut tx, &op).await?;
        tx.commit().await?;
        Ok::<_, AccessError>(())
    })
    .await
    .map_err(|_| AccessError::Timeout)??;
    Ok(options)
}
pub async fn finish(state: &AppState, input: &CeremonyFinish) -> Result<PasskeyLogin> {
    let rp = relying_party(state)?;
    let op = AccountAccessRepo::new(&state.db)
        .operation(input.operation_id)
        .await?
        .ok_or(AccessError::Rejected)?;
    if op.authority_kind != 3 || op.expires_at <= Utc::now() {
        return Err(AccessError::Rejected);
    }
    let mut data: OperationData = serde_json::from_slice(&op.payload)?;
    if data.login_consumed || data.challenge_expires_at <= Utc::now() {
        return Err(AccessError::Conflict);
    }
    let OperationKind::Login { device } = &data.kind else {
        return Err(AccessError::Rejected);
    };
    let CeremonyResponse::Assertion {
        credential_id,
        user_handle: Some(handle),
        ..
    } = &input.response
    else {
        return Err(AccessError::Rejected);
    };
    let user_id = Uuid::from_slice(&decode(handle, 16)?).map_err(|_| AccessError::Rejected)?;
    let id = decode(credential_id, 1024)?;
    let record = AccountAccessRepo::new(&state.db)
        .credential(&id)
        .await?
        .ok_or(AccessError::Rejected)?;
    if record.user_id != user_id
        || data
            .credential_fence
            .is_none_or(|fence| record.creation_generation > fence)
    {
        return Err(AccessError::Rejected);
    }
    let user = UserRepo::new(&state.db)
        .get_by_id(user_id)
        .await?
        .ok_or(AccessError::Rejected)?;
    let verified = rp.finish_assertion(
        &input.response,
        data.assertion.take().ok_or(AccessError::Rejected)?,
        serde_json::from_slice(&record.credential)?,
        user_id,
        true,
    )?;
    let now = Utc::now();
    let device = build_device(
        user_id,
        Some(device.name.clone()),
        Some(device.platform.clone()),
        device.fingerprint.clone(),
        device.os.clone(),
        device.os_version.clone(),
        device.app_version.clone(),
        "",
        "",
        now,
    );
    data.login_consumed = true;
    data.assertion = None;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        SessionRepo::guard_account_in(&mut tx, user_id, user.auth_epoch).await?;
        let locked = AccountAccessRepo::lock_operation_in(&mut tx, op.operation_id).await?;
        if locked.revision != op.revision
            || locked.payload != op.payload
            || locked.expires_at <= Utc::now()
        {
            return Err(AccessError::Conflict);
        }
        AccountAccessRepo::update_credential_in(&mut tx, &record, &serde_json::to_vec(&verified)?)
            .await?;
        let tokens = issue_login_session_in(
            state,
            &mut tx,
            &user,
            &device,
            now,
            crate::domains::auth::service::issuance::LoginFactor::Passkey(&id),
        )
        .await?;
        let account = AccountAccessRepo::lock_account_in(&mut tx, user_id).await?;
        let key_access = key_access(state, &account, &record);
        let mut consumed = locked;
        consumed.payload = serde_json::to_vec(&data)?;
        AccountAccessRepo::save_operation_in(&mut tx, &consumed).await?;
        tx.commit().await?;
        Ok(PasskeyLogin {
            tokens: build_login_response(state, tokens.access_token, tokens.refresh_token),
            user_id,
            credential_id: encode(&id),
            auth_epoch: account.auth_epoch,
            security_revision: account.security_revision,
            key_access,
        })
    })
    .await
    .map_err(|_| AccessError::Timeout)?
}

// Authentication remains usable when E2EE metadata is damaged. The client must
// explicitly choose its independent encryption-password flow for Unavailable.
fn key_access(
    state: &AppState,
    account: &zann_db::repo::SecurityAccount,
    key: &zann_db::repo::PasskeyRecord,
) -> AccountKeyAccess {
    let (descriptor, issue) = descriptor_metadata(state, account);
    if issue.is_some() {
        return AccountKeyAccess::Unavailable {
            reason: GrantIssue::Descriptor,
        };
    }
    if key.mode == PasskeyMode::AuthOnly {
        return AccountKeyAccess::AuthOnly { descriptor };
    }
    let Some(descriptor) = descriptor else {
        return AccountKeyAccess::Unavailable {
            reason: GrantIssue::Descriptor,
        };
    };
    let Some(bytes) = &key.grant else {
        return AccountKeyAccess::Unavailable {
            reason: GrantIssue::Missing,
        };
    };
    let grant: AccountGrant = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(error = ?error, "invalid account grant encoding");
            return AccountKeyAccess::Unavailable {
                reason: GrantIssue::Encoding,
            };
        }
    };
    if grant.rp_id
        != match state.config.auth.passkey.as_ref() {
            Some(config) => config.rp_id.clone(),
            None => {
                return AccountKeyAccess::Unavailable {
                    reason: GrantIssue::Verification,
                }
            }
        }
        || grant.credential_id != encode(&key.credential_id)
    {
        return AccountKeyAccess::Unavailable {
            reason: GrantIssue::Verification,
        };
    }
    if let Err(error) = grant.verify(&descriptor) {
        tracing::warn!(error = ?error, "invalid account grant proof");
        return AccountKeyAccess::Unavailable {
            reason: GrantIssue::Verification,
        };
    }
    AccountKeyAccess::Ready {
        descriptor,
        grant: Box::new(grant),
    }
}
