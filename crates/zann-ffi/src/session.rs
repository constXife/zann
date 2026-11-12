//! Remote connection, login and logout projected over UniFFI.
//!
//! Every object here is an opaque handle around a `zann_client::app` value:
//! trust pinning, credential custody and session policy stay in that facade.
//! Calls block on this session's runtime, so shells make them off the UI
//! thread and cancel them through the operation they passed in.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::runtime::Runtime;
use zann_client::app::{
    AppClient, AuthMethod, ConnectionTrustChallenge, LocalLogoutStatus, LoginPassword,
    LogoutOutcome, PasswordLoginRequest, PasswordRegistrationRequest, PersonalVaultStatus,
    PrepareConnectionOutcome, PreparedConnection, RemoteLogoutStatus, SessionAccess,
    SessionCancellationHandle, SessionError, SessionErrorKind, SessionOperation,
};
use zann_client::oidc::{OidcBrowserError, OidcBrowserErrorKind, OidcBrowserLogin};

use crate::{CoreError, CoreResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum SessionErrorKindFfi {
    Cancelled,
    DeadlineExceeded,
    Busy,
    SessionNotFound,
    ReauthenticationRequired,
    MissingCredential,
    CredentialUnavailable,
    CredentialCancelled,
    CredentialUnsupported,
    TrustRequired,
    TrustMismatch,
    TrustInvalid,
    InsecureTransport,
    TransportUnavailable,
    TransportRejected,
    Protocol,
    SessionExpired,
    SessionLostRemoteUnknown,
    ConcurrentSessionChange,
    RecoveryRequired,
    Configuration,
    Internal,
}

impl From<SessionErrorKind> for SessionErrorKindFfi {
    fn from(kind: SessionErrorKind) -> Self {
        match kind {
            SessionErrorKind::Cancelled => Self::Cancelled,
            SessionErrorKind::DeadlineExceeded => Self::DeadlineExceeded,
            SessionErrorKind::Busy => Self::Busy,
            SessionErrorKind::SessionNotFound => Self::SessionNotFound,
            SessionErrorKind::ReauthenticationRequired => Self::ReauthenticationRequired,
            SessionErrorKind::MissingCredential => Self::MissingCredential,
            SessionErrorKind::CredentialUnavailable => Self::CredentialUnavailable,
            SessionErrorKind::CredentialCancelled => Self::CredentialCancelled,
            SessionErrorKind::CredentialUnsupported => Self::CredentialUnsupported,
            SessionErrorKind::TrustRequired => Self::TrustRequired,
            SessionErrorKind::TrustMismatch => Self::TrustMismatch,
            SessionErrorKind::TrustInvalid => Self::TrustInvalid,
            SessionErrorKind::InsecureTransport => Self::InsecureTransport,
            SessionErrorKind::TransportUnavailable => Self::TransportUnavailable,
            SessionErrorKind::TransportRejected => Self::TransportRejected,
            SessionErrorKind::Protocol => Self::Protocol,
            SessionErrorKind::SessionExpired => Self::SessionExpired,
            SessionErrorKind::SessionLostRemoteUnknown => Self::SessionLostRemoteUnknown,
            SessionErrorKind::ConcurrentSessionChange => Self::ConcurrentSessionChange,
            SessionErrorKind::RecoveryRequired => Self::RecoveryRequired,
            SessionErrorKind::Configuration => Self::Configuration,
            // `SessionErrorKind` is non-exhaustive; a new kind surfaces as
            // internal until it is projected here.
            _ => Self::Internal,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum OidcErrorKindFfi {
    Configuration,
    InvalidProvider,
    Transport,
    Protocol,
    Cancelled,
    DeadlineExceeded,
    AuthorizationRejected,
    Session,
}

impl From<OidcBrowserErrorKind> for OidcErrorKindFfi {
    fn from(kind: OidcBrowserErrorKind) -> Self {
        match kind {
            OidcBrowserErrorKind::Configuration => Self::Configuration,
            OidcBrowserErrorKind::InvalidProvider => Self::InvalidProvider,
            OidcBrowserErrorKind::Transport => Self::Transport,
            OidcBrowserErrorKind::Protocol => Self::Protocol,
            OidcBrowserErrorKind::Cancelled => Self::Cancelled,
            OidcBrowserErrorKind::DeadlineExceeded => Self::DeadlineExceeded,
            OidcBrowserErrorKind::AuthorizationRejected => Self::AuthorizationRejected,
            OidcBrowserErrorKind::Session => Self::Session,
        }
    }
}

impl From<SessionError> for CoreError {
    fn from(error: SessionError) -> Self {
        Self::Session {
            kind: error.kind().into(),
            message: error.to_string(),
        }
    }
}

/// Zann's answer to the provider token is a session failure like any other
/// login's, so it keeps its own kind instead of a generic OIDC one.
impl From<OidcBrowserError> for CoreError {
    fn from(error: OidcBrowserError) -> Self {
        match error.into_session_error() {
            Ok(session) => session.into(),
            Err(error) => Self::Oidc {
                kind: error.kind().into(),
                message: error.to_string(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum AuthMethodFfi {
    Password,
    Oidc,
    ServiceAccount,
}

impl From<AuthMethod> for AuthMethodFfi {
    fn from(method: AuthMethod) -> Self {
        match method {
            AuthMethod::Password => Self::Password,
            AuthMethod::Oidc => Self::Oidc,
            AuthMethod::ServiceAccount => Self::ServiceAccount,
        }
    }
}

/// Deadline and cancellation for exactly one session call. A shell cancels
/// it from any thread while the call blocks on another.
#[derive(uniffi::Object)]
pub struct SessionOperationFfi {
    operation: Mutex<Option<SessionOperation>>,
    cancellation: SessionCancellationHandle,
}

#[uniffi::export]
impl SessionOperationFfi {
    #[uniffi::constructor]
    pub fn new(timeout_ms: u64) -> CoreResult<Arc<Self>> {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(timeout_ms))
            .ok_or_else(|| CoreError::InvalidArgument("operation timeout".to_string()))?;
        let (operation, cancellation) = SessionOperation::new(deadline);
        Ok(Arc::new(Self {
            operation: Mutex::new(Some(operation)),
            cancellation,
        }))
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
}

impl SessionOperationFfi {
    fn take(&self) -> CoreResult<SessionOperation> {
        self.operation
            .lock()
            .expect("lock poisoned")
            .take()
            .ok_or_else(|| CoreError::InvalidArgument("operation was already used".to_string()))
    }
}

/// A verified and pinned server target, ready for login.
#[derive(uniffi::Object)]
pub struct PreparedConnectionFfi(PreparedConnection);

#[uniffi::export]
impl PreparedConnectionFfi {
    pub fn auth_methods(&self) -> Vec<AuthMethodFfi> {
        self.0
            .auth_methods()
            .iter()
            .map(|method| (*method).into())
            .collect()
    }

    pub fn registration_available(&self) -> bool {
        self.0.registration_available()
    }

    pub fn server_name(&self) -> Option<String> {
        self.0.server_name().map(str::to_string)
    }

    pub fn storage_id(&self) -> String {
        self.0.storage_id().to_string()
    }
}

/// A changed server fingerprint awaiting the user's explicit decision. It
/// can be trusted once; it is simply dropped when the user declines.
#[derive(uniffi::Object)]
pub struct ConnectionTrustChallengeFfi {
    old_fingerprint: String,
    new_fingerprint: String,
    challenge: Mutex<Option<ConnectionTrustChallenge>>,
}

#[uniffi::export]
impl ConnectionTrustChallengeFfi {
    pub fn old_fingerprint(&self) -> String {
        self.old_fingerprint.clone()
    }

    pub fn new_fingerprint(&self) -> String {
        self.new_fingerprint.clone()
    }
}

#[derive(uniffi::Enum)]
pub enum PrepareConnectionOutcomeFfi {
    Ready {
        connection: Arc<PreparedConnectionFfi>,
    },
    FingerprintChanged {
        challenge: Arc<ConnectionTrustChallengeFfi>,
    },
}

/// Opaque authorization capability; bearer material never leaves Rust.
#[derive(uniffi::Object)]
pub struct SessionAccessFfi(SessionAccess);

/// A prepared browser login. The shell opens `authorization_url` and then
/// calls `finish`, which commits the session through the client that began it.
#[derive(uniffi::Object)]
pub struct OidcLoginFfi {
    authorization_url: String,
    login: Mutex<Option<OidcBrowserLogin>>,
    bridge: Arc<Bridge>,
}

#[uniffi::export]
impl OidcLoginFfi {
    pub fn authorization_url(&self) -> String {
        self.authorization_url.clone()
    }

    /// Waits for the browser callback and commits the resulting session.
    pub fn finish(&self) -> CoreResult<Arc<SessionAccessFfi>> {
        let login = self
            .login
            .lock()
            .expect("lock poisoned")
            .take()
            .ok_or_else(|| CoreError::InvalidArgument("OIDC login was already used".to_string()))?;
        let access = self
            .bridge
            .runtime
            .block_on(login.finish(&self.bridge.client))?;
        Ok(Arc::new(SessionAccessFfi(access)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PersonalVaultStatusFfi {
    pub personal_vaults_present: bool,
    pub personal_key_envelopes_present: bool,
    pub personal_vault_id: Option<String>,
}

impl From<PersonalVaultStatus> for PersonalVaultStatusFfi {
    fn from(status: PersonalVaultStatus) -> Self {
        Self {
            personal_vaults_present: status.personal_vaults_present(),
            personal_key_envelopes_present: status.personal_key_envelopes_present(),
            personal_vault_id: status.personal_vault_id().map(|id| id.to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RemoteLogoutStatusFfi {
    Confirmed,
    NotAttempted,
    Unconfirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum LocalLogoutStatusFfi {
    Revoked,
    AlreadyAbsent,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct LogoutOutcomeFfi {
    pub remote: RemoteLogoutStatusFfi,
    pub local: LocalLogoutStatusFfi,
    pub cleanup_deferred: bool,
}

impl From<LogoutOutcome> for LogoutOutcomeFfi {
    fn from(outcome: LogoutOutcome) -> Self {
        Self {
            remote: match outcome.remote_status() {
                RemoteLogoutStatus::Confirmed => RemoteLogoutStatusFfi::Confirmed,
                RemoteLogoutStatus::NotAttempted => RemoteLogoutStatusFfi::NotAttempted,
                RemoteLogoutStatus::Unconfirmed => RemoteLogoutStatusFfi::Unconfirmed,
            },
            local: match outcome.local_status() {
                LocalLogoutStatus::Revoked => LocalLogoutStatusFfi::Revoked,
                LocalLogoutStatus::AlreadyAbsent => LocalLogoutStatusFfi::AlreadyAbsent,
            },
            cleanup_deferred: outcome.cleanup_deferred(),
        }
    }
}

struct Bridge {
    runtime: Runtime,
    client: AppClient,
}

/// Remote session surface of one local vault: connect, log in, log out.
#[derive(uniffi::Object)]
pub struct RemoteSession(Arc<Bridge>);

impl RemoteSession {
    pub(crate) fn new(client: AppClient) -> CoreResult<Self> {
        let runtime = Runtime::new().map_err(|error| CoreError::Service(error.to_string()))?;
        Ok(Self(Arc::new(Bridge { runtime, client })))
    }
}

#[uniffi::export]
impl RemoteSession {
    /// Verifies the server's signed identity and pins it. A fingerprint that
    /// differs from the pinned one is returned as a challenge, not trusted.
    pub fn prepare_connection(
        &self,
        endpoint: String,
        connection_name: String,
        profile_name: String,
    ) -> CoreResult<PrepareConnectionOutcomeFfi> {
        let outcome = self.0.runtime.block_on(self.0.client.prepare_connection(
            &endpoint,
            &connection_name,
            &profile_name,
        ))?;
        Ok(match outcome {
            PrepareConnectionOutcome::Ready(prepared) => PrepareConnectionOutcomeFfi::Ready {
                connection: Arc::new(PreparedConnectionFfi(prepared)),
            },
            PrepareConnectionOutcome::FingerprintChanged(challenge) => {
                PrepareConnectionOutcomeFfi::FingerprintChanged {
                    challenge: Arc::new(ConnectionTrustChallengeFfi {
                        old_fingerprint: challenge.old_fingerprint().to_string(),
                        new_fingerprint: challenge.new_fingerprint().to_string(),
                        challenge: Mutex::new(Some(*challenge)),
                    }),
                }
            }
        })
    }

    pub fn trust_connection(
        &self,
        challenge: Arc<ConnectionTrustChallengeFfi>,
    ) -> CoreResult<Arc<PreparedConnectionFfi>> {
        let challenge = challenge
            .challenge
            .lock()
            .expect("lock poisoned")
            .take()
            .ok_or_else(|| CoreError::InvalidArgument("challenge was already used".to_string()))?;
        let prepared = self.0.client.trust_connection(challenge)?;
        Ok(Arc::new(PreparedConnectionFfi(prepared)))
    }

    pub fn password_login(
        &self,
        connection: Arc<PreparedConnectionFfi>,
        email: String,
        password: String,
        operation: Arc<SessionOperationFfi>,
    ) -> CoreResult<Arc<SessionAccessFfi>> {
        let password = login_password(password)?;
        let request = PasswordLoginRequest::new(connection.0.target().clone(), email, password)
            .map_err(|error| CoreError::InvalidArgument(error.to_string()))?;
        let operation = operation.take()?;
        let access = self
            .0
            .runtime
            .block_on(self.0.client.password_login(request, operation))?;
        Ok(Arc::new(SessionAccessFfi(access)))
    }

    pub fn password_register(
        &self,
        connection: Arc<PreparedConnectionFfi>,
        email: String,
        password: String,
        full_name: Option<String>,
        operation: Arc<SessionOperationFfi>,
    ) -> CoreResult<Arc<SessionAccessFfi>> {
        let password = login_password(password)?;
        let request = PasswordRegistrationRequest::new(
            connection.0.target().clone(),
            email,
            password,
            full_name,
        )
        .map_err(|error| CoreError::InvalidArgument(error.to_string()))?;
        let operation = operation.take()?;
        let access = self
            .0
            .runtime
            .block_on(self.0.client.password_register(request, operation))?;
        Ok(Arc::new(SessionAccessFfi(access)))
    }

    /// Prepares a browser login. Its `operation` also bounds and cancels the
    /// wait in `OidcLoginFfi::finish`.
    pub fn begin_oidc_login(
        &self,
        connection: Arc<PreparedConnectionFfi>,
        operation: Arc<SessionOperationFfi>,
    ) -> CoreResult<Arc<OidcLoginFfi>> {
        let operation = operation.take()?;
        let login = self.0.runtime.block_on(
            self.0
                .client
                .begin_oidc_login(connection.0.target().clone(), operation),
        )?;
        Ok(Arc::new(OidcLoginFfi {
            authorization_url: login.authorization_url().to_string(),
            login: Mutex::new(Some(login)),
            bridge: Arc::clone(&self.0),
        }))
    }

    pub fn personal_vault_status(
        &self,
        access: Arc<SessionAccessFfi>,
    ) -> CoreResult<PersonalVaultStatusFfi> {
        let status = self
            .0
            .runtime
            .block_on(self.0.client.personal_vault_status(&access.0))?;
        Ok(status.into())
    }

    /// Logs out the profile of the configured target, chosen the same way
    /// `CoreFacade::remote_sync` chooses it.
    pub fn logout(
        &self,
        storage_id: Option<String>,
        operation: Arc<SessionOperationFfi>,
    ) -> CoreResult<LogoutOutcomeFfi> {
        let target = self.0.client.configured_target(storage_id.as_deref())?;
        let operation = operation.take()?;
        let outcome = self
            .0
            .runtime
            .block_on(self.0.client.logout(&target, operation))?;
        Ok(outcome.into())
    }
}

fn login_password(password: String) -> CoreResult<LoginPassword> {
    LoginPassword::new(password).map_err(|error| CoreError::InvalidArgument(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_error_kinds_project_one_to_one() {
        let kinds = [
            SessionErrorKind::Cancelled,
            SessionErrorKind::DeadlineExceeded,
            SessionErrorKind::Busy,
            SessionErrorKind::SessionNotFound,
            SessionErrorKind::ReauthenticationRequired,
            SessionErrorKind::MissingCredential,
            SessionErrorKind::CredentialUnavailable,
            SessionErrorKind::CredentialCancelled,
            SessionErrorKind::CredentialUnsupported,
            SessionErrorKind::TrustRequired,
            SessionErrorKind::TrustMismatch,
            SessionErrorKind::TrustInvalid,
            SessionErrorKind::InsecureTransport,
            SessionErrorKind::TransportUnavailable,
            SessionErrorKind::TransportRejected,
            SessionErrorKind::Protocol,
            SessionErrorKind::SessionExpired,
            SessionErrorKind::SessionLostRemoteUnknown,
            SessionErrorKind::ConcurrentSessionChange,
            SessionErrorKind::RecoveryRequired,
            SessionErrorKind::Configuration,
            SessionErrorKind::Internal,
        ];
        for kind in kinds {
            assert_eq!(
                format!("{:?}", SessionErrorKindFfi::from(kind)),
                format!("{kind:?}")
            );
        }
    }

    #[test]
    fn an_operation_is_consumed_by_one_call() {
        let operation = SessionOperationFfi::new(60_000).expect("operation");
        operation.take().expect("first use");
        assert!(matches!(
            operation.take(),
            Err(CoreError::InvalidArgument(_))
        ));
    }
}
