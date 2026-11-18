use super::{common::*, model::*, *};
use crate::app::AppState;
use chrono::Utc;
use sqlx_postgres::PgConnection;
use uuid::Uuid;
use zann_core::api::account_access::*;
use zann_core::{Session, UserStatus};
use zann_crypto::account_access::{array, encode, prf_input};
use zann_db::repo::{AccessOperation, AccountAccessRepo, SessionRepo, UserRepo};

pub async fn configuration(state: &AppState) -> Result<PasskeyConfiguration> {
    relying_party(state)?;
    let config = state
        .config
        .auth
        .passkey
        .as_ref()
        .ok_or(AccessError::Disabled)?;
    let id = server_id(state);
    Ok(PasskeyConfiguration {
        prf_input: encode(&prf_input(&id, &config.rp_id)?),
        server_id: id,
        rp_id: config.rp_id.clone(),
        rp_name: config.rp_name.clone(),
        origins: config.origins.clone(),
    })
}
pub async fn snapshot(state: &AppState, session: &Session) -> Result<AccountSecurity> {
    relying_party(state)?;
    let account = AccountAccessRepo::new(&state.db)
        .account(session.user_id)
        .await?
        .ok_or(AccessError::Rejected)?;
    if !account.active
        || account.active_recovery_id.is_some()
        || account.auth_epoch != session.auth_epoch
    {
        return Err(AccessError::Rejected);
    }
    let keys = AccountAccessRepo::new(&state.db)
        .credentials(session.user_id)
        .await?;
    if keys.len() > MAX_CREDENTIALS {
        return Err(AccessError::Capacity);
    }
    let (descriptor, descriptor_issue) = descriptor_metadata(state, &account);
    Ok(AccountSecurity {
        user_id: session.user_id,
        auth_epoch: account.auth_epoch,
        security_revision: account.security_revision,
        descriptor,
        descriptor_issue,
        credentials: keys
            .into_iter()
            .map(|key| PasskeySummary {
                credential_id: encode(&key.credential_id),
                name: key.name,
                mode: key.mode,
            })
            .collect(),
        password_enabled: account.password_enabled,
        recovery_key_version: account.recovery_key_version,
        recovery_candidate_id: account.recovery_candidate_id,
    })
}
pub async fn bootstrap_descriptor(
    state: &AppState,
    session: &Session,
    input: &DescriptorBootstrap,
) -> Result<AccountSecurity> {
    relying_party(state)?;
    input.descriptor.validate()?;
    if !state.config.server.personal_vaults_enabled
        || input.descriptor.server_id != server_id(state)
        || input.descriptor.user_id != session.user_id
        || input.descriptor.key_epoch != 1
        || input.operation_id.get_version_num() != 4
    {
        return Err(AccessError::Rejected);
    }
    let user = UserRepo::new(&state.db)
        .get_by_id(session.user_id)
        .await?
        .ok_or(AccessError::Rejected)?;
    if user.status != UserStatus::Active {
        return Err(AccessError::Rejected);
    }
    if let ManagementProof::InitialPassword { server_password } = &input.proof {
        verify_server_password(state, &user, server_password).await?;
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        SessionRepo::guard_session_in(&mut tx, session).await?;
        let account = AccountAccessRepo::lock_account_in(&mut tx, session.user_id).await?;
        if let Some(existing) = bound_descriptor(state, &account)? {
            if existing != input.descriptor {
                return Err(AccessError::Conflict);
            }
        } else {
            if account.security_revision != input.expected_revision
                || account.row_version != user.row_version
            {
                return Err(AccessError::Conflict);
            }
            match &input.proof {
                ManagementProof::InitialPassword { .. } => {}
                ManagementProof::ExistingPasskey {
                    operation_id,
                    response,
                } => {
                    verify_uv_in(
                        &mut tx,
                        state,
                        session,
                        &account,
                        *operation_id,
                        response,
                        &UvAuthorizationIntent::Descriptor {
                            descriptor: input.descriptor.clone(),
                        },
                    )
                    .await?;
                }
                ManagementProof::Custody { .. } => return Err(AccessError::Rejected),
            }
            AccountAccessRepo::bind_descriptor_in(
                &mut tx,
                session.user_id,
                account.security_revision,
                &serde_json::to_vec(&input.descriptor)?,
            )
            .await?;
        }
        tx.commit().await?;
        Ok::<_, AccessError>(())
    })
    .await
    .map_err(|_| AccessError::Timeout)??;
    snapshot(state, session).await
}
pub async fn custody_options(
    state: &AppState,
    session: &Session,
    input: &MutationOptions,
) -> Result<MutationContext> {
    relying_party(state)?;
    let digest = array::<32>(&input.body_digest)?;
    let nonce = zann_crypto::ipc_signatures::random_nonce();
    let context = nonce_context(
        state,
        session,
        input.expected_revision,
        input.purpose,
        digest,
        nonce,
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        let account = guarded(&mut tx, session, input.expected_revision).await?;
        if bound_descriptor(state, &account)?.is_none() {
            return Err(AccessError::Rejected);
        }
        AccountAccessRepo::stage_nonce_in(
            &mut tx,
            session.user_id,
            session.id,
            account.security_revision,
            &nonce,
            input.purpose.as_str(),
            &digest,
        )
        .await?;
        tx.commit().await?;
        Ok::<_, AccessError>(())
    })
    .await
    .map_err(|_| AccessError::Timeout)??;
    Ok(context)
}
pub async fn uv_options(
    state: &AppState,
    session: &Session,
    id: Uuid,
    input: &UvAuthorizationRequest,
) -> Result<CeremonyOptions> {
    let rp = relying_party(state)?;
    let digest = json_digest("zann account UV request v1", input)?;
    if let Some(op) = AccountAccessRepo::new(&state.db).operation(id).await? {
        check_operation(&op, session)?;
        if op.request_digest != digest {
            return Err(AccessError::Conflict);
        }
        let data: OperationData = serde_json::from_slice(&op.payload)?;
        return Ok(data.options);
    }
    match &input.intent {
        UvAuthorizationIntent::Mutation { body_digest, .. } => {
            array::<32>(body_digest)?;
        }
        UvAuthorizationIntent::Descriptor { descriptor } => {
            descriptor.validate()?;
            if !state.config.server.personal_vaults_enabled
                || descriptor.server_id != server_id(state)
                || descriptor.user_id != session.user_id
                || descriptor.key_epoch != 1
            {
                return Err(AccessError::Rejected);
            }
        }
    }
    let keys = AccountAccessRepo::new(&state.db)
        .credentials(session.user_id)
        .await?;
    if keys.is_empty() || keys.len() > MAX_CREDENTIALS {
        return Err(AccessError::Rejected);
    }
    let credentials = keys
        .iter()
        .map(|key| serde_json::from_slice(&key.credential))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (options, assertion) = rp.assertion(id, CeremonyPhase::Authorize, credentials)?;
    let mut data = OperationData::new(
        OperationKind::Authorize {
            intent: input.intent.clone(),
        },
        options.clone(),
    );
    data.assertion = Some(assertion);
    let slot = new_slot(id, session, input.expected_revision, digest, &data)?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut tx = begin(state).await?;
        guarded(&mut tx, session, input.expected_revision).await?;
        AccountAccessRepo::allocate_in(&mut tx, &slot).await?;
        tx.commit().await?;
        Ok::<_, AccessError>(())
    })
    .await
    .map_err(|_| AccessError::Timeout)??;
    Ok(options)
}

pub(super) async fn management_proof_in(
    conn: &mut PgConnection,
    state: &AppState,
    session: &Session,
    account: &zann_db::repo::SecurityAccount,
    proof: &ManagementProof,
    purpose: MutationPurpose,
    digest: [u8; 32],
) -> Result<()> {
    match proof {
        ManagementProof::Custody { proof } => {
            verify_custody(conn, state, session, account, proof, purpose, digest).await
        }
        ManagementProof::ExistingPasskey {
            operation_id,
            response,
        } => {
            verify_uv_in(
                conn,
                state,
                session,
                account,
                *operation_id,
                response,
                &UvAuthorizationIntent::Mutation {
                    purpose,
                    body_digest: encode(&digest),
                },
            )
            .await
        }
        ManagementProof::InitialPassword { .. } => Err(AccessError::Rejected), // verified outside locks by the initial shared-only bootstrap caller
    }
}

async fn verify_uv_in(
    conn: &mut PgConnection,
    state: &AppState,
    session: &Session,
    account: &zann_db::repo::SecurityAccount,
    operation_id: Uuid,
    response: &CeremonyResponse,
    expected_intent: &UvAuthorizationIntent,
) -> Result<()> {
    let mut op = AccountAccessRepo::lock_operation_in(conn, operation_id).await?;
    check_operation(&op, session)?;
    if op.security_revision != Some(account.security_revision) {
        return Err(AccessError::Conflict);
    }
    let mut data: OperationData = serde_json::from_slice(&op.payload)?;
    if data.challenge_expires_at <= Utc::now() || data.login_consumed {
        return Err(AccessError::Rejected);
    }
    let OperationKind::Authorize { intent } = &data.kind else {
        return Err(AccessError::Rejected);
    };
    if intent != expected_intent {
        return Err(AccessError::Rejected);
    }
    let id = zann_crypto::account_access::decode(response.credential_id(), 1024)?;
    let key = AccountAccessRepo::credential_in(conn, &id)
        .await?
        .ok_or(AccessError::Rejected)?;
    if key.user_id != session.user_id {
        return Err(AccessError::Rejected);
    }
    let verified = relying_party(state)?.finish_assertion(
        response,
        data.assertion.take().ok_or(AccessError::Rejected)?,
        serde_json::from_slice(&key.credential)?,
        session.user_id,
        false,
    )?;
    AccountAccessRepo::update_credential_in(conn, &key, &serde_json::to_vec(&verified)?).await?;
    data.login_consumed = true;
    op.payload = serde_json::to_vec(&data)?;
    AccountAccessRepo::save_operation_in(conn, &op).await?;
    Ok(())
}

pub(super) async fn load_operation(
    state: &AppState,
    session: &Session,
    id: Uuid,
) -> Result<(AccessOperation, OperationData)> {
    let op = AccountAccessRepo::new(&state.db)
        .operation(id)
        .await?
        .ok_or(AccessError::Rejected)?;
    check_operation(&op, session)?;
    let data = serde_json::from_slice(&op.payload)?;
    Ok((op, data))
}
