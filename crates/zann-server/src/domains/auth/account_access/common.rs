use super::*;
use crate::{app::AppState, config::AuthMode};
use chrono::Utc;
use sqlx_core::transaction::Transaction;
use sqlx_postgres::{PgConnection, Postgres};
use uuid::Uuid;
use zann_core::api::account_access::*;
use zann_core::{Session, User};
use zann_crypto::account_access::{array, encode, Authority};
use zann_db::repo::{AccessOperation, AccountAccessRepo, SecurityAccount, SessionRepo};

pub(super) fn relying_party(state: &AppState) -> Result<rp::RelyingParty> {
    if !state.config.auth.internal.enabled || matches!(state.config.auth.mode, AuthMode::Oidc) {
        return Err(AccessError::Disabled);
    }
    let config = state
        .config
        .auth
        .passkey
        .as_ref()
        .ok_or(AccessError::Disabled)?;
    rp::RelyingParty::new(config, server_id(state))
}
pub(super) fn server_id(state: &AppState) -> String {
    crate::infra::server_identity::server_id(&state.identity_key.verifying_key())
}
pub(super) async fn begin(state: &AppState) -> Result<Transaction<'_, Postgres>> {
    let mut tx = state.db.begin().await?;
    sqlx_core::query::query::<Postgres>("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    sqlx_core::query::query::<Postgres>("SET LOCAL lock_timeout='500ms'")
        .execute(&mut *tx)
        .await?;
    sqlx_core::query::query::<Postgres>("SET LOCAL statement_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
pub(super) async fn guarded(
    conn: &mut PgConnection,
    session: &Session,
    revision: i64,
) -> Result<SecurityAccount> {
    SessionRepo::guard_session_in(conn, session).await?;
    let account = AccountAccessRepo::lock_account_in(conn, session.user_id).await?;
    if !account.active
        || account.active_recovery_id.is_some()
        || account.auth_epoch != session.auth_epoch
        || account.security_revision != revision
    {
        return Err(AccessError::Conflict);
    }
    Ok(account)
}
pub(super) fn descriptor(account: &SecurityAccount) -> Result<Option<AccountDescriptor>> {
    account
        .descriptor
        .as_deref()
        .map(serde_json::from_slice)
        .transpose()
        .map_err(Into::into)
}
pub(super) fn check_operation(op: &AccessOperation, session: &Session) -> Result<()> {
    if op.authority_kind != 1
        || op.authority_id != Some(session.id)
        || op.user_id != Some(session.user_id)
        || op.auth_epoch != Some(session.auth_epoch)
        || op.expires_at <= Utc::now()
    {
        return Err(AccessError::Rejected);
    }
    Ok(())
}
pub(super) fn check_device(device: &DeviceDescriptor) -> Result<()> {
    let fields = [
        Some(device.name.as_str()),
        Some(device.platform.as_str()),
        device.fingerprint.as_deref(),
        device.os.as_deref(),
        device.os_version.as_deref(),
        device.app_version.as_deref(),
    ];
    if device.name.is_empty()
        || device.platform.is_empty()
        || fields
            .into_iter()
            .flatten()
            .any(|v| v.len() > 128 || v.chars().any(char::is_control))
    {
        return Err(AccessError::Rejected);
    }
    Ok(())
}
pub(super) fn json_digest<T: serde::Serialize>(label: &'static str, value: &T) -> Result<[u8; 32]> {
    // Internal request DTOs have fixed fields and order; secret-bearing protocol
    // transcripts (consume/code activation) have separate typed encoders.
    Ok(zann_crypto::account_access::Transcript::new(label)
        .field(&serde_json::to_vec(value)?)
        .digest())
}
pub(super) async fn verify_custody(
    conn: &mut PgConnection,
    state: &AppState,
    session: &Session,
    account: &SecurityAccount,
    proof: &CustodyProof,
    purpose: MutationPurpose,
    digest: [u8; 32],
) -> Result<()> {
    let context = &proof.context;
    if context.authority != Authority::Session
        || context.authority_id != session.id
        || context.server_id != server_id(state)
        || context.user_id != session.user_id
        || context.security_revision != account.security_revision as u64
        || context.purpose != purpose
        || array::<32>(&context.body_digest)? != digest
    {
        return Err(AccessError::Rejected);
    }
    context.verify(
        &bound_descriptor(state, account)?.ok_or(AccessError::Rejected)?,
        &proof.signature,
    )?;
    AccountAccessRepo::consume_nonce_in(
        conn,
        session.user_id,
        session.id,
        account.security_revision,
        &array::<32>(&context.nonce)?,
        purpose.as_str(),
        &digest,
    )
    .await?;
    Ok(())
}
pub(super) async fn verify_server_password(
    state: &AppState,
    user: &User,
    password: &str,
) -> Result<()> {
    if password.is_empty() || password.len() > 4096 {
        return Err(AccessError::Rejected);
    }
    let permit = state
        .argon2_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| AccessError::RateLimited)?;
    let user = user.clone();
    let password = zeroize::Zeroizing::new(password.to_owned());
    let pepper = zeroize::Zeroizing::new(state.password_pepper.clone());
    let valid = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        crate::domains::auth::core::passwords::verify_password(&user, &password, &pepper)
    })
    .await
    .map_err(AccessError::Worker)?
    .map_err(AccessError::Kdf)?;
    if !valid {
        return Err(AccessError::Rejected);
    }
    Ok(())
}
pub(super) fn new_slot(
    id: Uuid,
    session: &Session,
    revision: i64,
    digest: [u8; 32],
    data: &model::OperationData,
) -> Result<AccessOperation> {
    Ok(AccessOperation {
        operation_id: id,
        user_id: Some(session.user_id),
        authority_kind: 1,
        authority_id: Some(session.id),
        auth_epoch: Some(session.auth_epoch),
        security_revision: Some(revision),
        request_digest: digest,
        payload: serde_json::to_vec(data)?,
        revision: 0,
        expires_at: Utc::now() + chrono::Duration::minutes(15),
    })
}
pub(super) fn nonce_context(
    state: &AppState,
    session: &Session,
    revision: i64,
    purpose: MutationPurpose,
    digest: [u8; 32],
    nonce: [u8; 32],
) -> MutationContext {
    MutationContext {
        server_id: server_id(state),
        user_id: session.user_id,
        authority: Authority::Session,
        authority_id: session.id,
        security_revision: revision as u64,
        nonce: encode(&nonce),
        purpose,
        body_digest: encode(&digest),
    }
}

pub(super) fn bound_descriptor(
    state: &AppState,
    account: &SecurityAccount,
) -> Result<Option<AccountDescriptor>> {
    let value = descriptor(account)?;
    if let Some(value) = &value {
        value.validate()?;
        if value.user_id != account.user_id || value.server_id != server_id(state) {
            return Err(AccessError::Rejected);
        }
    }
    Ok(value)
}
pub(super) fn descriptor_metadata(
    state: &AppState,
    account: &SecurityAccount,
) -> (Option<AccountDescriptor>, Option<GrantIssue>) {
    match bound_descriptor(state, account) {
        Ok(value) => (value, None),
        Err(error) => {
            tracing::warn!(error=?error,"invalid account custody metadata");
            (None, Some(GrantIssue::Descriptor))
        }
    }
}
