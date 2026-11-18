//! Native account-access orchestration. Shells receive no bearer, PRF or account key.
use super::*;
use crate::account_access::intents::{SecurityReply, SecurityRequest};
use crate::account_access::*;
use crate::session::{PasskeyLoginOutcome, PasskeyVaultBootstrap};

use zann_core::api::account_access::*;
use zann_crypto::account_access::{encode, AccountCustody, Authority};
mod enrollment;
mod management;
mod recovery_cleanup;
mod recovery_codes;
pub use recovery_codes::AccountRecoveryCode;
mod recovery;
mod recovery_enrollment;
pub use enrollment::PasskeyEnrollmentAuthorization;
pub use recovery::{AccountRecoveryHandle, AccountRecoveryPreparation};

/// Prepared encrypted keyring plus the lease held until local publication.
pub struct PasskeyAccountEnrollment {
    pub enrollment: AccountKeyEnrollment,
    pub keyring: unlock::DeviceUnlock,
}
impl AppClient {
    pub async fn passkey_login(
        &self,
        target: SessionTarget,
        provider: Arc<dyn AccountCeremonyProvider>,
        operation: SessionOperation,
    ) -> Result<PasskeyLoginOutcome, SessionError> {
        let outcome = self
            .session
            .passkey_login(target, provider, operation)
            .await?;
        let access = self.finish_account_authentication(outcome.access).await?;
        Ok(PasskeyLoginOutcome {
            access,
            vault: outcome.vault,
        })
    }
    /// Requires an independently unlocked DeviceUnlock root. Passkey never opens
    /// an existing multi-account root or changes the account's serialized origin.
    pub async fn prepare_passkey_account_key(
        &self,
        bootstrap: PasskeyVaultBootstrap,
        root: &SecretKey,
        keyring: &unlock::DeviceUnlock,
        operation: SessionOperation,
    ) -> Result<PasskeyAccountEnrollment, SessionError> {
        let operation_id = operation.operation_id();
        let failure = || SessionError::for_app(operation_id, SessionErrorKind::Protocol);
        let (storage, server, subject) = self
            .account_key_binding(&bootstrap.target)
            .map_err(|e| failure().with_source(e))?;
        let source = self
            .repository
            .snapshot()
            .map_err(|e| failure().with_source(e))?;
        let connection = source
            .config()
            .connections
            .get(bootstrap.target.connection_id())
            .ok_or_else(failure)?;
        if server != bootstrap.server.server_id()
            || subject != bootstrap.user_id.to_string()
            || connection.metadata().address != bootstrap.server.address()
            || connection.metadata().server_fingerprint.as_deref()
                != Some(bootstrap.server.server_fingerprint())
        {
            return Err(failure().with_source(AccountBootstrapCheck::AccountBinding));
        }
        let AccountKeyAccess::Ready { descriptor, grant } = bootstrap.key_access else {
            return Err(failure().with_source(AccountBootstrapCheck::GrantMode));
        };
        if descriptor.server_id != server
            || descriptor.user_id != bootstrap.user_id
            || grant.rp_id != bootstrap.rp_id
            || grant.credential_id != bootstrap.credential_id
        {
            return Err(failure().with_source(AccountBootstrapCheck::GrantBinding));
        }
        let prf = bootstrap.prf.ok_or_else(failure)?.into_account_prf();
        let key = Arc::new(
            grant
                .open(&descriptor, &prf)
                .map_err(|e| failure().with_source(e))?,
        );
        drop(prf);
        if self
            .verify_account_key(&bootstrap.target, &key, operation.detached_copy())
            .await
            .map_err(|e| failure().with_source(e))?
            != AccountKeyCheck::Matches
        {
            return Err(failure().with_source(AccountBootstrapCheck::VaultProof));
        }
        let identity = self
            .account_identity(&bootstrap.target)
            .map_err(|e| failure().with_source(e))?;
        let enrollment = self
            .prepare_account_key(
                &bootstrap.target,
                key.clone(),
                AccountKeyOrigin::AccountPassword,
                Some(&identity),
                operation,
            )
            .await
            .map_err(|e| failure().with_source(e))?;
        if enrollment.storage_id != storage
            || enrollment.server_id != server
            || enrollment.account_subject != subject
        {
            return Err(failure().with_source(AccountBootstrapCheck::PublicationBinding));
        }
        let mut candidate = keyring.clone();
        candidate
            .insert_account(
                root,
                storage,
                server,
                subject,
                &key,
                AccountKeyOrigin::AccountPassword,
            )
            .map_err(|e| failure().with_source(e))?;
        Ok(PasskeyAccountEnrollment {
            enrollment,
            keyring: candidate,
        })
    }
    pub async fn account_security(
        &self,
        target: &SessionTarget,
        operation: SessionOperation,
    ) -> Result<AccountSecurity, SessionError> {
        let access = self.session.access(target, operation).await?;
        let transport =
            AuthHttpTransport::new(access.endpoint()).map_err(|e| access_error(&access, e))?;
        transport
            .account_get("v1/users/me/security", access.bearer())
            .await
            .map_err(|e| access_error(&access, e))
    }
}
fn access_error(access: &SessionAccess, error: crate::remote::auth::AuthHttpError) -> SessionError {
    SessionError::from_http_for_app(access.operation_id(), &error).with_source(error)
}
struct AccountApi<'a> {
    client: &'a AppClient,
    target: &'a SessionTarget,
    operation: &'a SessionOperation,
    server: String,
    subject: String,
    storage: String,
}
impl<'a> AccountApi<'a> {
    fn new(
        client: &'a AppClient,
        target: &'a SessionTarget,
        operation: &'a SessionOperation,
    ) -> Result<Self, SessionError> {
        let (storage, server, subject) = client.account_key_binding(target).map_err(|e| {
            SessionError::for_app(operation.operation_id(), SessionErrorKind::Configuration)
                .with_source(e)
        })?;
        Ok(Self {
            client,
            target,
            operation,
            server,
            subject,
            storage,
        })
    }
    async fn access(&self) -> Result<SessionAccess, SessionError> {
        let access = self
            .client
            .session
            .access(self.target, self.operation.detached_copy())
            .await?;
        if access.account_subject() != Some(self.subject.as_str())
            || access.storage_id() != Some(self.storage.as_str())
            || self
                .client
                .account_key_binding(self.target)
                .map(|b| {
                    b != (
                        self.storage.clone(),
                        self.server.clone(),
                        self.subject.clone(),
                    )
                })
                .unwrap_or(true)
        {
            return Err(SessionError::for_app(
                self.operation.operation_id(),
                SessionErrorKind::Configuration,
            ));
        }
        Ok(access)
    }
    async fn post<T: SecurityRequest, R: SecurityReply>(
        &self,
        path: &str,
        input: &T,
    ) -> Result<R, SessionError> {
        let access = self.access().await?;
        let transport =
            AuthHttpTransport::new(access.endpoint()).map_err(|e| access_error(&access, e))?;
        let binding = self
            .client
            .recovery_endpoint(self.target, self.operation)
            .await?;
        let intent = self
            .client
            .repository
            .stage_account_request(binding, None, path, input.public_request())
            .map_err(|e| {
                SessionError::for_app(
                    self.operation.operation_id(),
                    SessionErrorKind::Configuration,
                )
                .with_source(e)
            })?;
        ensure_account_operation(self.operation)?;
        let result: R = transport
            .account_post(path, access.bearer(), input)
            .await
            .map_err(|e| {
                self.client
                    .account_request_error(intent.id, self.operation, e)
            })?;
        self.client
            .repository
            .finish_account_request(intent.id, result.public_receipt())
            .map_err(|e| {
                SessionError::for_app(
                    self.operation.operation_id(),
                    SessionErrorKind::Configuration,
                )
                .with_source(e)
            })?;
        Ok(result)
    }
    async fn ceremony(
        &self,
        provider: &dyn AccountCeremonyProvider,
        options: CeremonyOptions,
        require_prf: bool,
    ) -> Result<AccountCeremonyResult, SessionError> {
        let access = self.access().await?;
        let server = crate::session::CeremonyServer {
            address: access.endpoint(),
            fingerprint: access.server_fingerprint(),
            id: &self.server,
        };
        crate::session::perform_account_ceremony(
            provider,
            server,
            options,
            require_prf,
            self.operation,
        )
        .await
    }
    async fn custody(
        &self,
        key: &SecretKey,
        descriptor: &AccountDescriptor,
        revision: i64,
        purpose: MutationPurpose,
        digest: [u8; 32],
    ) -> Result<CustodyProof, SessionError> {
        let failure =
            || SessionError::for_app(self.operation.operation_id(), SessionErrorKind::Protocol);
        let context: MutationContext = self
            .post(
                "v1/users/me/security/custody/options",
                &MutationOptions {
                    expected_revision: revision,
                    purpose,
                    body_digest: encode(&digest),
                },
            )
            .await?;
        if context.server_id != self.server
            || context.user_id.to_string() != self.subject
            || context.authority != Authority::Session
            || context.security_revision != revision as u64
            || context.purpose != purpose
            || context.body_digest != encode(&digest)
        {
            return Err(failure());
        }
        let custody =
            AccountCustody::derive(key, &self.server, descriptor.user_id, descriptor.key_epoch)
                .map_err(|e| failure().with_source(e))?;
        Ok(CustodyProof {
            signature: custody
                .sign_mutation(descriptor, &context)
                .map_err(|e| failure().with_source(e))?,
            context,
        })
    }
}

fn ensure_account_operation(operation: &SessionOperation) -> Result<(), SessionError> {
    match operation.pre_dispatch_error() {
        Some(kind) => Err(SessionError::for_app(operation.operation_id(), kind)),
        None => Ok(()),
    }
}

#[derive(Debug, thiserror::Error)]
enum AccountBootstrapCheck {
    #[error("passkey bootstrap account/endpoint binding changed")]
    AccountBinding,
    #[error("passkey has no full vault grant")]
    GrantMode,
    #[error("passkey grant credential/RP binding differs")]
    GrantBinding,
    #[error("passkey grant key did not open the published personal vault")]
    VaultProof,
    #[error("account binding changed before local key publication")]
    PublicationBinding,
}

impl AppClient {
    // A definitive rejection closes only the public dispatch, never its secret
    // bundle. Network/5xx ambiguity remains pending for exact request replay.
    fn account_request_error(
        &self,
        id: Uuid,
        operation: &SessionOperation,
        error: crate::remote::auth::AuthHttpError,
    ) -> SessionError {
        let failure = SessionError::from_http_for_app(operation.operation_id(), &error);
        if let Some(status) = error
            .status()
            .filter(|s| (400..500).contains(s) && !matches!(s, 408 | 429))
        {
            if let Err(journal) = self.repository.finish_account_request(
                id,
                crate::account_access::intents::PublicReceipt::Rejected { status },
            ) {
                return failure.with_source(RejectedRequestJournalError {
                    http: error,
                    journal,
                });
            }
        }
        failure.with_source(error)
    }
}
#[derive(Debug, thiserror::Error)]
#[error("could not persist definitive security request rejection: {journal}")]
struct RejectedRequestJournalError {
    #[source]
    http: crate::remote::auth::AuthHttpError,
    journal: crate::config::ConfigError,
}
