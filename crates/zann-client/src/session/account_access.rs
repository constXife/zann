//! Discoverable login shares the journaled token-publication owner with passwords.
use super::*;
use crate::account_access::*;
use zann_core::api::account_access::*;

pub struct PasskeyVaultBootstrap {
    pub(crate) personal_vaults_enabled: bool,
    pub(crate) target: SessionTarget,
    pub(crate) server: VerifiedEndpointBinding,
    pub(crate) user_id: Uuid,
    pub(crate) credential_id: String,
    pub(crate) rp_id: String,
    pub(crate) key_access: AccountKeyAccess,
    pub(crate) prf: Option<PrfOutput>,
}
impl fmt::Debug for PasskeyVaultBootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasskeyVaultBootstrap([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeyVaultRequirement {
    Ready,
    EncryptionPassword,
    SharedCache,
    PrfUnavailable,
    GrantUnavailable(GrantIssue),
}
impl PasskeyVaultBootstrap {
    pub fn requirement(&self) -> PasskeyVaultRequirement {
        if !self.personal_vaults_enabled {
            return PasskeyVaultRequirement::SharedCache;
        }
        match &self.key_access {
            AccountKeyAccess::Ready { .. } if self.prf.is_some() => PasskeyVaultRequirement::Ready,
            AccountKeyAccess::Ready { .. } => PasskeyVaultRequirement::PrfUnavailable,
            AccountKeyAccess::AuthOnly { .. } => PasskeyVaultRequirement::EncryptionPassword,
            AccountKeyAccess::Unavailable { reason } => {
                PasskeyVaultRequirement::GrantUnavailable(*reason)
            }
        }
    }
}

pub struct PasskeyLoginOutcome {
    pub access: SessionAccess,
    pub vault: PasskeyVaultBootstrap,
}
impl AppSession {
    pub(crate) fn recovery_device(&self) -> Result<DeviceDescriptor, SessionError> {
        let client = self.inner.client.as_ref().ok_or_else(|| {
            SessionError::for_app(SessionOperationId::new(), SessionErrorKind::Configuration)
        })?;
        Ok(DeviceDescriptor {
            name: client.device_name.clone().ok_or_else(|| {
                SessionError::for_app(SessionOperationId::new(), SessionErrorKind::Configuration)
            })?,
            platform: client.device_platform.clone().ok_or_else(|| {
                SessionError::for_app(SessionOperationId::new(), SessionErrorKind::Configuration)
            })?,
            fingerprint: client.device_fingerprint.clone(),
            os: client.device_os.clone(),
            os_version: client.device_os_version.clone(),
            app_version: client.device_app_version.clone(),
        })
    }

    pub(crate) async fn passkey_login(
        &self,
        target: SessionTarget,
        provider: Arc<dyn AccountCeremonyProvider>,
        operation: SessionOperation,
    ) -> Result<PasskeyLoginOutcome, SessionError> {
        TokenManager {
            inner: self.inner.clone(),
        }
        .passkey_login(target, provider, &operation)
        .await
    }
}
impl TokenManager {
    async fn passkey_login(
        &self,
        target: SessionTarget,
        provider: Arc<dyn AccountCeremonyProvider>,
        operation: &SessionOperation,
    ) -> Result<PasskeyLoginOutcome, SessionError> {
        let failure = |kind| SessionError::new(operation, kind);
        if let Some(kind) = operation.pre_dispatch_error() {
            return Err(failure(kind));
        }
        let client = self
            .inner
            .client
            .clone()
            .ok_or_else(|| failure(SessionErrorKind::Configuration))?;
        let locks = acquire_session_locks(
            self.inner.repository.paths().root().to_path_buf(),
            operation,
        )
        .await?;
        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let (locks, recovered) = run_with_locks(locks, move || {
            repository.reconcile_auth_operation_with_operation_locks(store.as_ref())
        })
        .await
        .map_err(failure)?;
        let (recovered, _) =
            recovered.map_err(|e| failure(config_error_kind(&e, operation)).with_source(e))?;
        let cleanup_deferred = outcome_has_warnings(&recovered);
        let repository = self.inner.repository.clone();
        let selection = target.clone();
        let client_id = client.client_id.clone();
        let (locks, anchor) = run_with_locks(locks, move || {
            repository.resolve_login_anchor(
                &selection.connection_id,
                selection.profile_name,
                &client_id,
            )
        })
        .await
        .map_err(failure)?;
        let anchor =
            anchor.map_err(|e| failure(config_error_kind(&e, operation)).with_source(e))?;
        let (locks, port, verified) = self
            .verified_login_auth_port(locks, &anchor, operation)
            .await
            .map_err(|(_, e)| e)?;
        if !verified.supports_passkey {
            return Err(failure(SessionErrorKind::TransportRejected));
        }
        // Browser/provider waits never retain local config/credential leases.
        drop(locks);
        let config = port
            .passkey_configuration()
            .await
            .map_err(|e| SessionError::from_auth(operation, &e))?;
        if config.server_id != verified.server_id() {
            return Err(failure(SessionErrorKind::TrustInvalid));
        }
        let input = PasskeyLoginOptions {
            operation_id: Uuid::new_v4(),
            device: DeviceDescriptor {
                name: client
                    .device_name
                    .clone()
                    .ok_or_else(|| failure(SessionErrorKind::Configuration))?,
                platform: client
                    .device_platform
                    .clone()
                    .ok_or_else(|| failure(SessionErrorKind::Configuration))?,
                fingerprint: None,
                os: None,
                os_version: None,
                app_version: None,
            },
        };
        let options = port
            .passkey_options(&input)
            .await
            .map_err(|e| SessionError::from_auth(operation, &e))?;
        if options.operation_id != input.operation_id
            || options.phase != CeremonyPhase::Login
            || options.rp_id != config.rp_id
            || options.prf_input != config.prf_input
            || !options.credential_ids.is_empty()
        {
            return Err(failure(SessionErrorKind::Protocol));
        }
        let result = perform_account_ceremony(
            provider.as_ref(),
            (&verified.binding).into(),
            options,
            false,
            operation,
        )
        .await?;
        let CeremonyResponse::Assertion {
            credential_id,
            user_handle: Some(handle),
            ..
        } = &result.response
        else {
            return Err(failure(SessionErrorKind::Protocol));
        };
        let user_id = Uuid::from_slice(
            &zann_crypto::account_access::decode(handle, 16)
                .map_err(|e| failure(SessionErrorKind::Protocol).with_source(e))?,
        )
        .map_err(|e| failure(SessionErrorKind::Protocol).with_source(e))?;
        let credential_id = credential_id.clone();
        let locks = acquire_session_locks(
            self.inner.repository.paths().root().to_path_buf(),
            operation,
        )
        .await?;
        let (locks, port, verified) = self
            .verified_login_auth_port(locks, &anchor, operation)
            .await
            .map_err(|(_, e)| e)?;
        let storage_id = anchor.storage_id().map(str::to_owned);
        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let endpoint = verified.binding.clone();
        let id = operation.operation_id.to_string();
        let (locks, permit) = run_with_locks(locks, move || {
            repository.prepare_login_intent_with_operation_locks(
                &anchor,
                &endpoint,
                LoginPreflight::Passkey,
                &id,
                store.as_ref(),
            )
        })
        .await
        .map_err(failure)?;
        let permit =
            permit.map_err(|e| failure(config_error_kind(&e, operation)).with_source(e))?;
        let manager = self.clone();
        let operation = operation.detached_copy();
        tokio::spawn(async move {
            let response = match port
                .passkey_finish(&CeremonyFinish {
                    operation_id: input.operation_id,
                    response: result.response,
                })
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    return manager
                        .finish_failed_password_login(
                            locks,
                            None,
                            &port,
                            &operation,
                            error.kind.session_error_kind(),
                            error.status,
                            error.server_code,
                            cleanup_deferred,
                        )
                        .await
                        .map(|_| unreachable!())
                }
            };
            if response.user_id != user_id || response.credential_id != credential_id {
                let _access = Zeroizing::new(response.tokens.access_token);
                let refresh =
                    CredentialSecret::new(response.tokens.refresh_token).map_err(|e| {
                        SessionError::new(&operation, SessionErrorKind::Protocol).with_source(e)
                    })?;
                return manager
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::Protocol,
                        None,
                        None,
                        true,
                    )
                    .await
                    .map(|_| unreachable!());
            }
            let vault = PasskeyVaultBootstrap {
                personal_vaults_enabled: verified.personal_vaults_enabled,
                target: target.clone(),
                server: verified.binding.clone(),
                user_id,
                credential_id,
                rp_id: config.rp_id,
                key_access: response.key_access,
                prf: result.prf,
            };
            let access = manager
                .complete_interactive_login(
                    locks,
                    permit,
                    None,
                    target,
                    port,
                    verified,
                    storage_id,
                    operation,
                    cleanup_deferred,
                    AuthMethod::Passkey,
                    response.tokens,
                )
                .await?;
            if access.account_subject() != Some(user_id.to_string().as_str()) {
                return Err(SessionError::for_app(
                    access.operation_id(),
                    SessionErrorKind::Protocol,
                ));
            }
            Ok(PasskeyLoginOutcome { access, vault })
        })
        .await
        .map_err(|e| failure(SessionErrorKind::Internal).with_source(e))?
    }
}

/// Server identity already proven by the caller's verified endpoint or session.
#[derive(Clone, Copy)]
pub(crate) struct CeremonyServer<'a> {
    pub(crate) address: &'a str,
    pub(crate) fingerprint: &'a str,
    pub(crate) id: &'a str,
}
impl<'a> From<&'a VerifiedEndpointBinding> for CeremonyServer<'a> {
    fn from(binding: &'a VerifiedEndpointBinding) -> Self {
        Self {
            address: binding.address(),
            fingerprint: binding.server_fingerprint(),
            id: binding.server_id(),
        }
    }
}
/// The single account-ceremony runner: validates the prompt against the verified
/// server, then waits for the trusted provider under the operation's cancellation
/// and deadline. Provider failures are `TransportRejected`, prompt faults `Protocol`.
pub(crate) async fn perform_account_ceremony(
    provider: &dyn AccountCeremonyProvider,
    server: CeremonyServer<'_>,
    options: CeremonyOptions,
    require_prf: bool,
    operation: &SessionOperation,
) -> Result<AccountCeremonyResult, SessionError> {
    let prompt = AccountCeremonyPrompt {
        server_address: server.address.into(),
        server_fingerprint: server.fingerprint.into(),
        server_id: server.id.into(),
        options,
        require_prf,
    };
    validate_account_prompt(&prompt)
        .map_err(|e| SessionError::new(operation, SessionErrorKind::Protocol).with_source(e))?;
    tokio::select! {
        biased;
        () = operation.cancelled() => Err(SessionError::new(operation, SessionErrorKind::Cancelled)),
        () = tokio::time::sleep_until(tokio::time::Instant::from_std(operation.deadline())) => {
            Err(SessionError::new(operation, SessionErrorKind::DeadlineExceeded))
        }
        result = provider.perform(prompt) => result.map_err(|e| {
            SessionError::new(operation, SessionErrorKind::TransportRejected).with_source(e)
        }),
    }
}
