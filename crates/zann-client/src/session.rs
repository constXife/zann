//! DB-free application session orchestration.
//!
//! This module contains the sole crate-owned implementation of access-token
//! selection, refresh and logout policy. The public `app::AppClient` facade
//! delegates to it; raw bearer and refresh values never cross the crate
//! boundary.

use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use tokio::sync::Notify;
use uuid::Uuid;
use zann_core::api::auth::{
    LoginRequest, LoginResponse, LogoutRequest, OidcLoginRequest as OidcLoginWireRequest,
    PreloginResponse, RefreshRequest, RegisterRequest,
};
use zann_core::{AuthMethod, AuthSource, Identity};
use zeroize::{Zeroize, Zeroizing};

use crate::config::locking::{FileLockGuard, LockAttempt, LockKind};
use crate::config::{
    ActiveCredentialAfterRemoval, AuthOperationIntentPermit, AuthOperationKind,
    AuthOperationRecoveryDisposition, AuthenticatedConnectionTarget, AuthenticatedSessionCommit,
    AuthorizedTargetGeneration, ClientId, ClientPaths, ConfigError, ConfigIdentity,
    ConfigRepository, ConnectionId, CredentialBundle, CredentialKind, CredentialPortErrorKind,
    CredentialProfileAnchor, CredentialSecret, CredentialStore, CredentialTransactionOutcome,
    IdentityCommit, PasswordLoginAnchor, PasswordLoginIntentPermit, StoredConnectionBinding,
    VerifiedEndpointBinding,
};
use crate::remote::auth::{AuthHttpError, AuthHttpErrorKind, AuthHttpTransport};
use crate::remote::trust::verify_and_bind_system_info;

const PROFILE_NAME_MAX_BYTES: usize = 128;
const LOGIN_EMAIL_MAX_BYTES: usize = 320;
const LOGIN_PASSWORD_MAX_BYTES: usize = 4 * 1024;
const FULL_NAME_MAX_BYTES: usize = 200;
const OIDC_TOKEN_MAX_BYTES: usize = 64 * 1024;
const DEVICE_FIELD_MAX_BYTES: usize = 256;
const REFRESH_SKEW: ChronoDuration = ChronoDuration::seconds(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);

type AuthFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AuthFailure>> + Send + 'a>>;

/// Stable identifier carried through a session operation and its result.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionOperationId(Uuid);

impl SessionOperationId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for SessionOperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Explicit connection/profile selection for a session operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionTarget {
    connection_id: ConnectionId,
    profile_name: String,
}

impl SessionTarget {
    pub fn new(
        connection_id: ConnectionId,
        profile_name: impl Into<String>,
    ) -> Result<Self, SessionTargetError> {
        let profile_name = profile_name.into();
        if profile_name.is_empty() {
            return Err(SessionTargetError::EmptyProfile);
        }
        if profile_name.len() > PROFILE_NAME_MAX_BYTES {
            return Err(SessionTargetError::ProfileTooLong);
        }
        Ok(Self {
            connection_id,
            profile_name,
        })
    }

    #[must_use]
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    #[must_use]
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTargetError {
    EmptyProfile,
    ProfileTooLong,
}

impl fmt::Display for SessionTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyProfile => "session profile name is empty",
            Self::ProfileTooLong => "session profile name is too long",
        })
    }
}

impl std::error::Error for SessionTargetError {}

/// Bounded, zeroizing password input for one exactly-once login attempt.
///
/// It is intentionally neither `Clone` nor serializable. Debug output never
/// exposes its value.
pub struct LoginPassword(Zeroizing<String>);

impl LoginPassword {
    pub fn new(value: impl Into<String>) -> Result<Self, PasswordLoginInputError> {
        // Wrap before validation so rejected values are zeroized on every early return too.
        let value = Zeroizing::new(value.into());
        if value.is_empty() {
            return Err(PasswordLoginInputError::EmptyPassword);
        }
        if value.len() > LOGIN_PASSWORD_MAX_BYTES {
            return Err(PasswordLoginInputError::PasswordTooLong);
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for LoginPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoginPassword(<redacted>)")
    }
}

/// Stable local client identity and bounded device metadata consumed by the
/// crate-internal session owner exposed through `app::AppClient`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionClient {
    client_id: ClientId,
    device_name: Option<String>,
    device_platform: Option<String>,
    device_fingerprint: Option<String>,
    device_os: Option<String>,
    device_os_version: Option<String>,
    device_app_version: Option<String>,
}

impl SessionClient {
    #[must_use]
    pub fn new(client_id: ClientId) -> Self {
        Self {
            device_name: Some(client_id.as_str().to_string()),
            device_platform: Some("zann-client".to_string()),
            client_id,
            device_fingerprint: None,
            device_os: None,
            device_os_version: None,
            device_app_version: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_device_metadata(
        mut self,
        device_name: Option<String>,
        device_platform: Option<String>,
        device_fingerprint: Option<String>,
        device_os: Option<String>,
        device_os_version: Option<String>,
        device_app_version: Option<String>,
    ) -> Result<Self, PasswordLoginInputError> {
        for value in [
            device_name.as_deref(),
            device_platform.as_deref(),
            device_fingerprint.as_deref(),
            device_os.as_deref(),
            device_os_version.as_deref(),
            device_app_version.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.len() > DEVICE_FIELD_MAX_BYTES {
                return Err(PasswordLoginInputError::DeviceFieldTooLong);
            }
        }
        self.device_name = device_name;
        self.device_platform = device_platform;
        self.device_fingerprint = device_fingerprint;
        self.device_os = device_os;
        self.device_os_version = device_os_version;
        self.device_app_version = device_app_version;
        Ok(self)
    }

    #[must_use]
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }
}

/// Existing pinned connection/profile target and credentials for one
/// password-login operation.
pub struct PasswordLoginRequest {
    target: SessionTarget,
    email: String,
    password: LoginPassword,
}

pub struct PasswordRegistrationRequest {
    target: SessionTarget,
    email: String,
    password: LoginPassword,
    full_name: Option<String>,
}

/// A bounded, zeroizing token obtained from the configured OIDC provider.
///
/// The token is exchanged exactly once with the already verified Zann server;
/// it is never persisted by the client.
pub struct OidcToken(Zeroizing<String>);

impl OidcToken {
    pub fn new(value: impl Into<String>) -> Result<Self, OidcLoginInputError> {
        let value = Zeroizing::new(value.into());
        if value.is_empty() {
            return Err(OidcLoginInputError::EmptyToken);
        }
        if value.len() > OIDC_TOKEN_MAX_BYTES {
            return Err(OidcLoginInputError::TokenTooLong);
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for OidcToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OidcToken(<redacted>)")
    }
}

/// Existing pinned connection/profile target and one external OIDC token.
pub struct OidcLoginInput {
    target: SessionTarget,
    token: OidcToken,
}

impl OidcLoginInput {
    #[must_use]
    pub fn new(target: SessionTarget, token: OidcToken) -> Self {
        Self { target, token }
    }

    #[must_use]
    pub fn target(&self) -> &SessionTarget {
        &self.target
    }
}

impl fmt::Debug for OidcLoginInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcLoginInput")
            .field("target", &self.target)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcLoginInputError {
    EmptyToken,
    TokenTooLong,
}

impl fmt::Display for OidcLoginInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyToken => "OIDC token is empty",
            Self::TokenTooLong => "OIDC token is too long",
        })
    }
}

impl std::error::Error for OidcLoginInputError {}

impl PasswordRegistrationRequest {
    pub fn new(
        target: SessionTarget,
        email: impl Into<String>,
        password: LoginPassword,
        full_name: Option<String>,
    ) -> Result<Self, PasswordLoginInputError> {
        let email = email.into();
        if email.is_empty() || email.trim() != email {
            return Err(PasswordLoginInputError::EmptyEmail);
        }
        if email.len() > LOGIN_EMAIL_MAX_BYTES {
            return Err(PasswordLoginInputError::EmailTooLong);
        }
        let full_name = full_name
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if full_name
            .as_ref()
            .is_some_and(|value| value.len() > FULL_NAME_MAX_BYTES)
        {
            return Err(PasswordLoginInputError::FullNameTooLong);
        }
        Ok(Self {
            target,
            email,
            password,
            full_name,
        })
    }
}

impl fmt::Debug for PasswordRegistrationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordRegistrationRequest")
            .field("target", &self.target)
            .field("email", &"<redacted>")
            .field("password", &"<redacted>")
            .field("full_name_present", &self.full_name.is_some())
            .finish()
    }
}

impl PasswordLoginRequest {
    pub fn new(
        target: SessionTarget,
        email: impl Into<String>,
        password: LoginPassword,
    ) -> Result<Self, PasswordLoginInputError> {
        let email = email.into();
        if email.is_empty() || email.trim() != email {
            return Err(PasswordLoginInputError::EmptyEmail);
        }
        if email.len() > LOGIN_EMAIL_MAX_BYTES {
            return Err(PasswordLoginInputError::EmailTooLong);
        }
        Ok(Self {
            target,
            email,
            password,
        })
    }

    #[must_use]
    pub fn target(&self) -> &SessionTarget {
        &self.target
    }
}

impl fmt::Debug for PasswordLoginRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordLoginRequest")
            .field("target", &self.target)
            .field("email", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordLoginInputError {
    EmptyEmail,
    EmailTooLong,
    EmptyPassword,
    PasswordTooLong,
    DeviceFieldTooLong,
    FullNameTooLong,
}

impl fmt::Display for PasswordLoginInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyEmail => "password-login email is empty",
            Self::EmailTooLong => "password-login email is too long",
            Self::EmptyPassword => "password-login password is empty",
            Self::PasswordTooLong => "password-login password is too long",
            Self::DeviceFieldTooLong => "password-login device field is too long",
            Self::FullNameTooLong => "registration full name is too long",
        })
    }
}

impl std::error::Error for PasswordLoginInputError {}

struct CancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}

/// Clonable handle used by an adapter to cancel one session operation.
#[derive(Clone)]
pub struct SessionCancellationHandle {
    state: Arc<CancellationState>,
}

impl SessionCancellationHandle {
    pub fn cancel(&self) {
        if !self.state.cancelled.swap(true, Ordering::AcqRel) {
            self.state.notify.notify_waiters();
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }
}

impl fmt::Debug for SessionCancellationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCancellationHandle")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Deadline and cancellation context for one replaceable UI operation.
pub struct SessionOperation {
    operation_id: SessionOperationId,
    deadline: Instant,
    state: Arc<CancellationState>,
}

impl SessionOperation {
    #[must_use]
    pub fn new(deadline: Instant) -> (Self, SessionCancellationHandle) {
        Self::with_id(SessionOperationId::new(), deadline)
    }

    #[must_use]
    pub fn with_id(
        operation_id: SessionOperationId,
        deadline: Instant,
    ) -> (Self, SessionCancellationHandle) {
        let state = Arc::new(CancellationState {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        });
        (
            Self {
                operation_id,
                deadline,
                state: state.clone(),
            },
            SessionCancellationHandle { state },
        )
    }

    #[must_use]
    pub fn operation_id(&self) -> SessionOperationId {
        self.operation_id
    }

    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            let notified = self.state.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn pre_dispatch_error(&self) -> Option<SessionErrorKind> {
        if self.is_cancelled() {
            Some(SessionErrorKind::Cancelled)
        } else if Instant::now() >= self.deadline {
            Some(SessionErrorKind::DeadlineExceeded)
        } else {
            None
        }
    }

    pub(crate) fn completion(&self) -> OperationCompletion {
        if self.is_cancelled() {
            OperationCompletion::AfterCancellation
        } else if Instant::now() >= self.deadline {
            OperationCompletion::AfterDeadline
        } else {
            OperationCompletion::OnTime
        }
    }

    pub(crate) fn detached_copy(&self) -> Self {
        Self {
            operation_id: self.operation_id,
            deadline: self.deadline,
            state: self.state.clone(),
        }
    }
}

impl fmt::Debug for SessionOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionOperation")
            .field("operation_id", &self.operation_id)
            .field("deadline", &self.deadline)
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationCompletion {
    OnTime,
    AfterCancellation,
    AfterDeadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessSource {
    Stored,
    Refreshed,
    PasswordLogin,
    OidcLogin,
}

/// Opaque authorization capability consumed by crate-owned remote operations.
pub struct SessionAccess {
    operation_id: SessionOperationId,
    target: SessionTarget,
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    endpoint: String,
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    storage_id: Option<String>,
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    server_fingerprint: String,
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    account_subject: Option<String>,
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    auth_method: Option<AuthMethod>,
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    personal_vaults_enabled: bool,
    expires_at: DateTime<Utc>,
    source: AccessSource,
    completion: OperationCompletion,
    cleanup_deferred: bool,
    authorized_target_generation: Arc<AuthorizedTargetGeneration>,
    #[allow(dead_code)] // Consumed only by crate-owned authenticated transports.
    access_secret: CredentialSecret,
}

impl SessionAccess {
    #[must_use]
    pub fn operation_id(&self) -> SessionOperationId {
        self.operation_id
    }

    #[must_use]
    pub fn target(&self) -> &SessionTarget {
        &self.target
    }

    /// Verified canonical endpoint for crate-owned authenticated transports.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn storage_id(&self) -> Option<&str> {
        self.storage_id.as_deref()
    }

    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn server_fingerprint(&self) -> &str {
        &self.server_fingerprint
    }

    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn account_subject(&self) -> Option<&str> {
        self.account_subject.as_deref()
    }

    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn auth_method(&self) -> Option<AuthMethod> {
        self.auth_method
    }

    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn personal_vaults_enabled(&self) -> bool {
        self.personal_vaults_enabled
    }

    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    #[must_use]
    pub fn source(&self) -> AccessSource {
        self.source
    }

    #[must_use]
    pub fn completion(&self) -> OperationCompletion {
        self.completion
    }

    #[must_use]
    pub fn cleanup_deferred(&self) -> bool {
        self.cleanup_deferred
    }

    pub(crate) fn authorized_target_generation(&self) -> Arc<AuthorizedTargetGeneration> {
        Arc::clone(&self.authorized_target_generation)
    }

    #[allow(dead_code)] // Kept crate-private so adapters can never extract bearer material.
    pub(crate) fn bearer(&self) -> &str {
        self.access_secret.expose_secret()
    }

    #[cfg(all(test, feature = "sync"))]
    pub(crate) fn for_sync_test(
        operation_id: SessionOperationId,
        target: SessionTarget,
        endpoint: &str,
        storage_id: Option<String>,
        server_fingerprint: &str,
        account_binding: (Option<String>, Option<AuthMethod>),
        personal_vaults_enabled: bool,
    ) -> Self {
        let (account_subject, auth_method) = account_binding;
        let access_secret = match CredentialSecret::new("sync-test-access") {
            Ok(secret) => secret,
            Err(error) => panic!("static sync test credential must validate: {error}"),
        };
        let authorized_target_generation = AuthorizedTargetGeneration::for_sync_test(
            &target,
            "Remote test",
            endpoint,
            server_fingerprint,
            storage_id.clone(),
            account_subject.clone(),
            auth_method,
        );
        Self {
            operation_id,
            target,
            endpoint: endpoint.to_string(),
            storage_id,
            server_fingerprint: server_fingerprint.to_string(),
            account_subject,
            auth_method,
            personal_vaults_enabled,
            expires_at: Utc::now() + ChronoDuration::minutes(5),
            source: AccessSource::Stored,
            completion: OperationCompletion::OnTime,
            cleanup_deferred: false,
            authorized_target_generation,
            access_secret,
        }
    }
}

impl fmt::Debug for SessionAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionAccess")
            .field("operation_id", &self.operation_id)
            .field("target", &self.target)
            .field("expires_at", &self.expires_at)
            .field("source", &self.source)
            .field("completion", &self.completion)
            .field("cleanup_deferred", &self.cleanup_deferred)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SessionErrorKind {
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

impl fmt::Display for SessionErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Busy => "busy",
            Self::SessionNotFound => "session_not_found",
            Self::ReauthenticationRequired => "reauthentication_required",
            Self::MissingCredential => "missing_credential",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::CredentialCancelled => "credential_cancelled",
            Self::CredentialUnsupported => "credential_unsupported",
            Self::TrustRequired => "trust_required",
            Self::TrustMismatch => "trust_mismatch",
            Self::TrustInvalid => "trust_invalid",
            Self::InsecureTransport => "insecure_transport",
            Self::TransportUnavailable => "transport_unavailable",
            Self::TransportRejected => "transport_rejected",
            Self::Protocol => "protocol",
            Self::SessionExpired => "session_expired",
            Self::SessionLostRemoteUnknown => "session_lost_remote_unknown",
            Self::ConcurrentSessionChange => "concurrent_session_change",
            Self::RecoveryRequired => "recovery_required",
            Self::Configuration => "configuration",
            Self::Internal => "internal",
        })
    }
}

/// Redacted session failure. It contains no path, credential id or reflected body.
pub struct SessionError {
    operation_id: SessionOperationId,
    kind: SessionErrorKind,
    status: Option<u16>,
    server_code: Option<&'static str>,
    completion: OperationCompletion,
    cleanup_deferred: bool,
    local_revoke_confirmed: bool,
}

impl SessionError {
    fn new(operation: &SessionOperation, kind: SessionErrorKind) -> Self {
        Self {
            operation_id: operation.operation_id,
            kind,
            status: None,
            server_code: None,
            completion: operation.completion(),
            cleanup_deferred: false,
            local_revoke_confirmed: false,
        }
    }

    fn from_auth(operation: &SessionOperation, failure: &AuthFailure) -> Self {
        let mut error = Self::new(operation, failure.kind.session_error_kind());
        error.status = failure.status;
        error.server_code = failure.server_code;
        error
    }

    #[cfg(feature = "app")]
    pub(crate) fn for_app(operation_id: SessionOperationId, kind: SessionErrorKind) -> Self {
        Self {
            operation_id,
            kind,
            status: None,
            server_code: None,
            completion: OperationCompletion::OnTime,
            cleanup_deferred: false,
            local_revoke_confirmed: false,
        }
    }

    #[cfg(feature = "app")]
    pub(crate) fn from_http_for_app(
        operation_id: SessionOperationId,
        failure: &AuthHttpError,
    ) -> Self {
        let kind = match failure.kind() {
            AuthHttpErrorKind::InvalidEndpoint | AuthHttpErrorKind::Protocol => {
                SessionErrorKind::Protocol
            }
            AuthHttpErrorKind::InsecureTransport => SessionErrorKind::InsecureTransport,
            AuthHttpErrorKind::Timeout | AuthHttpErrorKind::Unavailable => {
                SessionErrorKind::TransportUnavailable
            }
            AuthHttpErrorKind::AmbiguousOutcome => SessionErrorKind::SessionLostRemoteUnknown,
            AuthHttpErrorKind::BodyTooLarge => SessionErrorKind::Protocol,
            AuthHttpErrorKind::SessionExpired => SessionErrorKind::SessionExpired,
            AuthHttpErrorKind::Rejected => SessionErrorKind::TransportRejected,
            AuthHttpErrorKind::Server => SessionErrorKind::TransportUnavailable,
        };
        let mut error = Self::for_app(operation_id, kind);
        error.status = failure.status();
        error.server_code = failure.server_code();
        error
    }

    fn terminal(
        operation: &SessionOperation,
        kind: SessionErrorKind,
        status: Option<u16>,
        server_code: Option<&'static str>,
        cleanup_deferred: bool,
        local_revoke_confirmed: bool,
    ) -> Self {
        Self {
            operation_id: operation.operation_id,
            kind,
            status,
            server_code,
            completion: operation.completion(),
            cleanup_deferred,
            local_revoke_confirmed,
        }
    }

    #[must_use]
    pub fn operation_id(&self) -> SessionOperationId {
        self.operation_id
    }

    #[must_use]
    pub fn kind(&self) -> SessionErrorKind {
        self.kind
    }

    #[must_use]
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    #[must_use]
    pub fn server_code(&self) -> Option<&'static str> {
        self.server_code
    }

    #[must_use]
    pub fn completion(&self) -> OperationCompletion {
        self.completion
    }

    #[must_use]
    pub fn cleanup_deferred(&self) -> bool {
        self.cleanup_deferred
    }

    #[must_use]
    pub fn local_revoke_confirmed(&self) -> bool {
        self.local_revoke_confirmed
    }
}

impl fmt::Debug for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionError")
            .field("operation_id", &self.operation_id)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("server_code", &self.server_code)
            .field("completion", &self.completion)
            .field("cleanup_deferred", &self.cleanup_deferred)
            .field("local_revoke_confirmed", &self.local_revoke_confirmed)
            .finish()
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "session:{}:{}", self.operation_id, self.kind)?;
        if let Some(status) = self.status {
            write!(formatter, ":status_{status}")?;
        }
        if let Some(code) = self.server_code {
            write!(formatter, ":{code}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SessionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteLogoutStatus {
    Confirmed,
    NotAttempted,
    Unconfirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalLogoutStatus {
    Revoked,
    AlreadyAbsent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogoutOutcome {
    operation_id: SessionOperationId,
    remote: RemoteLogoutStatus,
    local: LocalLogoutStatus,
    completion: OperationCompletion,
    cleanup_deferred: bool,
}

impl LogoutOutcome {
    #[must_use]
    pub fn operation_id(&self) -> SessionOperationId {
        self.operation_id
    }

    #[must_use]
    pub fn remote_status(&self) -> RemoteLogoutStatus {
        self.remote
    }

    #[must_use]
    pub fn local_status(&self) -> LocalLogoutStatus {
        self.local
    }

    #[must_use]
    pub fn completion(&self) -> OperationCompletion {
        self.completion
    }

    #[must_use]
    pub fn cleanup_deferred(&self) -> bool {
        self.cleanup_deferred
    }
}

/// Shared DB-free session owner.
#[derive(Clone)]
#[cfg_attr(not(feature = "app"), allow(dead_code))]
pub(crate) struct AppSession {
    inner: Arc<SessionInner>,
}

#[cfg_attr(not(feature = "app"), allow(dead_code))]
impl AppSession {
    #[must_use]
    #[cfg(test)]
    pub(crate) fn new(paths: ClientPaths, credential_store: Arc<dyn CredentialStore>) -> Self {
        Self::with_components(
            paths,
            credential_store,
            Arc::new(HttpAuthFactory),
            Arc::new(SystemClock),
        )
    }

    /// Creates the authenticated session owner used by the application facade.
    #[must_use]
    pub(crate) fn for_client(
        paths: ClientPaths,
        credential_store: Arc<dyn CredentialStore>,
        client: SessionClient,
    ) -> Self {
        Self::with_components_and_client(
            paths,
            credential_store,
            Arc::new(HttpAuthFactory),
            Arc::new(SystemClock),
            Some(client),
        )
    }

    #[cfg(test)]
    fn with_components(
        paths: ClientPaths,
        credential_store: Arc<dyn CredentialStore>,
        auth_factory: Arc<dyn AuthFactory>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::with_components_and_client(paths, credential_store, auth_factory, clock, None)
    }

    fn with_components_and_client(
        paths: ClientPaths,
        credential_store: Arc<dyn CredentialStore>,
        auth_factory: Arc<dyn AuthFactory>,
        clock: Arc<dyn Clock>,
        client: Option<SessionClient>,
    ) -> Self {
        Self {
            inner: Arc::new(SessionInner {
                repository: ConfigRepository::new(paths),
                credential_store,
                auth_factory,
                clock,
                client,
            }),
        }
    }

    /// Resolves a usable access credential, refreshing it exactly once when required.
    pub(crate) async fn access(
        &self,
        target: &SessionTarget,
        operation: SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        TokenManager {
            inner: self.inner.clone(),
        }
        .access(target, &operation)
        .await
    }

    /// Logs out the explicitly selected profile and always uses the journaled local revoke path.
    pub(crate) async fn logout(
        &self,
        target: &SessionTarget,
        operation: SessionOperation,
    ) -> Result<LogoutOutcome, SessionError> {
        TokenManager {
            inner: self.inner.clone(),
        }
        .logout(target, &operation)
        .await
    }

    /// Logs in to an already pinned connection with one exactly-once password
    /// POST and returns an opaque access capability.
    pub(crate) async fn password_login(
        &self,
        request: PasswordLoginRequest,
        operation: SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        TokenManager {
            inner: self.inner.clone(),
        }
        .password_login(request, &operation)
        .await
    }

    pub(crate) async fn password_register(
        &self,
        request: PasswordRegistrationRequest,
        operation: SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        TokenManager {
            inner: self.inner.clone(),
        }
        .password_register(request, &operation)
        .await
    }

    pub(crate) async fn oidc_login(
        &self,
        request: OidcLoginInput,
        operation: SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        TokenManager {
            inner: self.inner.clone(),
        }
        .oidc_login(request, &operation)
        .await
    }
}

impl fmt::Debug for AppSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("AppSession").finish_non_exhaustive()
    }
}

struct SessionInner {
    repository: ConfigRepository,
    credential_store: Arc<dyn CredentialStore>,
    auth_factory: Arc<dyn AuthFactory>,
    clock: Arc<dyn Clock>,
    client: Option<SessionClient>,
}

#[derive(Clone)]
struct TokenManager {
    inner: Arc<SessionInner>,
}

struct HeldSessionLocks {
    // Struct fields drop in declaration order: credential must be released before auth.
    _credential: FileLockGuard,
    _auth: FileLockGuard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccessDecision {
    Stored(DateTime<Utc>),
    Refresh,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReadCredentialError {
    MissingSlot,
    MissingPhysical,
    Port(CredentialPortErrorKind),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EndpointIdentity {
    binding: VerifiedEndpointBinding,
    personal_vaults_enabled: bool,
    supports_password: bool,
    supports_oidc: bool,
}

impl EndpointIdentity {
    fn address(&self) -> &str {
        self.binding.address()
    }

    fn server_id(&self) -> &str {
        self.binding.server_id()
    }

    fn server_fingerprint(&self) -> &str {
        self.binding.server_fingerprint()
    }

    #[cfg(test)]
    fn for_test(
        address: impl Into<String>,
        server_id: impl Into<String>,
        server_fingerprint: impl Into<String>,
        personal_vaults_enabled: bool,
        supports_password: bool,
    ) -> Self {
        Self {
            binding: crate::remote::trust::verified_endpoint_binding_for_test(
                address,
                server_id,
                server_fingerprint,
            ),
            personal_vaults_enabled,
            supports_password,
            supports_oidc: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthFailureKind {
    InvalidEndpoint,
    InsecureTransport,
    Timeout,
    Unavailable,
    AmbiguousOutcome,
    Protocol,
    BodyTooLarge,
    SessionExpired,
    Rejected,
    Server,
    TrustInvalid,
}

impl AuthFailureKind {
    fn session_error_kind(self) -> SessionErrorKind {
        match self {
            Self::InvalidEndpoint | Self::Protocol | Self::BodyTooLarge => {
                SessionErrorKind::Protocol
            }
            Self::InsecureTransport => SessionErrorKind::InsecureTransport,
            Self::Timeout | Self::Unavailable | Self::Server => {
                SessionErrorKind::TransportUnavailable
            }
            Self::AmbiguousOutcome => SessionErrorKind::SessionLostRemoteUnknown,
            Self::SessionExpired => SessionErrorKind::SessionExpired,
            Self::Rejected => SessionErrorKind::TransportRejected,
            Self::TrustInvalid => SessionErrorKind::TrustInvalid,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthFailure {
    kind: AuthFailureKind,
    status: Option<u16>,
    server_code: Option<&'static str>,
}

impl From<AuthHttpError> for AuthFailure {
    fn from(error: AuthHttpError) -> Self {
        let kind = match error.kind() {
            AuthHttpErrorKind::InvalidEndpoint => AuthFailureKind::InvalidEndpoint,
            AuthHttpErrorKind::InsecureTransport => AuthFailureKind::InsecureTransport,
            AuthHttpErrorKind::Timeout => AuthFailureKind::Timeout,
            AuthHttpErrorKind::Unavailable => AuthFailureKind::Unavailable,
            AuthHttpErrorKind::AmbiguousOutcome => AuthFailureKind::AmbiguousOutcome,
            AuthHttpErrorKind::Protocol => AuthFailureKind::Protocol,
            AuthHttpErrorKind::BodyTooLarge => AuthFailureKind::BodyTooLarge,
            AuthHttpErrorKind::SessionExpired => AuthFailureKind::SessionExpired,
            AuthHttpErrorKind::Rejected => AuthFailureKind::Rejected,
            AuthHttpErrorKind::Server => AuthFailureKind::Server,
        };
        Self {
            kind,
            status: error.status(),
            server_code: error.server_code(),
        }
    }
}

trait AuthFactory: Send + Sync {
    fn connect(&self, endpoint: &str, timeout: Duration) -> Result<Arc<dyn AuthPort>, AuthFailure>;
}

trait AuthPort: Send + Sync {
    fn verified_endpoint(&self) -> AuthFuture<'_, EndpointIdentity>;
    fn prelogin<'a>(&'a self, _email: &'a str) -> AuthFuture<'a, PreloginResponse> {
        Box::pin(async {
            Err(AuthFailure {
                kind: AuthFailureKind::Protocol,
                status: None,
                server_code: None,
            })
        })
    }
    fn password_login<'a>(
        &'a self,
        _email: &'a str,
        _password: &'a LoginPassword,
        _client: &'a SessionClient,
    ) -> AuthFuture<'a, LoginResponse> {
        Box::pin(async {
            Err(AuthFailure {
                kind: AuthFailureKind::Protocol,
                status: None,
                server_code: None,
            })
        })
    }
    fn register<'a>(
        &'a self,
        _request: &'a PasswordRegistrationRequest,
        _client: &'a SessionClient,
    ) -> AuthFuture<'a, LoginResponse> {
        Box::pin(async {
            Err(AuthFailure {
                kind: AuthFailureKind::Protocol,
                status: None,
                server_code: None,
            })
        })
    }
    fn oidc_login<'a>(&'a self, _token: &'a OidcToken) -> AuthFuture<'a, LoginResponse> {
        Box::pin(async {
            Err(AuthFailure {
                kind: AuthFailureKind::Protocol,
                status: None,
                server_code: None,
            })
        })
    }
    fn me<'a>(&'a self, _access_token: &'a str) -> AuthFuture<'a, Identity> {
        Box::pin(async {
            Err(AuthFailure {
                kind: AuthFailureKind::Protocol,
                status: None,
                server_code: None,
            })
        })
    }
    fn refresh<'a>(&'a self, refresh_token: &'a str) -> AuthFuture<'a, LoginResponse>;
    fn logout<'a>(&'a self, refresh_token: &'a str) -> AuthFuture<'a, ()>;
}

struct HttpAuthFactory;

impl AuthFactory for HttpAuthFactory {
    fn connect(&self, endpoint: &str, timeout: Duration) -> Result<Arc<dyn AuthPort>, AuthFailure> {
        let transport =
            AuthHttpTransport::with_timeout(endpoint, timeout).map_err(AuthFailure::from)?;
        transport
            .ensure_sensitive_endpoint()
            .map_err(AuthFailure::from)?;
        Ok(Arc::new(HttpAuthPort {
            endpoint: endpoint.to_string(),
            transport,
        }))
    }
}

struct HttpAuthPort {
    endpoint: String,
    transport: AuthHttpTransport,
}

struct ZeroizingRefreshRequest(RefreshRequest);

impl Drop for ZeroizingRefreshRequest {
    fn drop(&mut self) {
        self.0.refresh_token.zeroize();
    }
}

struct ZeroizingLogoutRequest(LogoutRequest);

impl Drop for ZeroizingLogoutRequest {
    fn drop(&mut self) {
        self.0.refresh_token.zeroize();
    }
}

struct ZeroizingLoginRequest(LoginRequest);

impl Drop for ZeroizingLoginRequest {
    fn drop(&mut self) {
        self.0.password.zeroize();
    }
}

struct ZeroizingRegisterRequest(RegisterRequest);

impl Drop for ZeroizingRegisterRequest {
    fn drop(&mut self) {
        self.0.password.zeroize();
        if let Some(invite) = self.0.invite_token.as_mut() {
            invite.zeroize();
        }
    }
}

struct ZeroizingOidcLoginRequest(OidcLoginWireRequest);

impl Drop for ZeroizingOidcLoginRequest {
    fn drop(&mut self) {
        self.0.token.zeroize();
    }
}

impl AuthPort for HttpAuthPort {
    fn verified_endpoint(&self) -> AuthFuture<'_, EndpointIdentity> {
        Box::pin(async move {
            let info = self
                .transport
                .system_info()
                .await
                .map_err(AuthFailure::from)?;
            let verified =
                verify_and_bind_system_info(&self.endpoint, info).map_err(|_| AuthFailure {
                    kind: AuthFailureKind::TrustInvalid,
                    status: None,
                    server_code: None,
                })?;
            let (info, binding) = verified.into_parts();
            Ok(EndpointIdentity {
                binding,
                personal_vaults_enabled: info.personal_vaults_enabled,
                supports_password: info.supports_auth_method(AuthMethod::Password),
                supports_oidc: info.supports_auth_method(AuthMethod::Oidc),
            })
        })
    }

    fn prelogin<'a>(&'a self, email: &'a str) -> AuthFuture<'a, PreloginResponse> {
        Box::pin(async move {
            self.transport
                .prelogin(email)
                .await
                .map_err(AuthFailure::from)
        })
    }

    fn password_login<'a>(
        &'a self,
        email: &'a str,
        password: &'a LoginPassword,
        client: &'a SessionClient,
    ) -> AuthFuture<'a, LoginResponse> {
        Box::pin(async move {
            let request = ZeroizingLoginRequest(LoginRequest {
                email: email.to_string(),
                password: password.expose().to_string(),
                device_name: client.device_name.clone(),
                device_platform: client.device_platform.clone(),
                device_fingerprint: client.device_fingerprint.clone(),
                device_os: client.device_os.clone(),
                device_os_version: client.device_os_version.clone(),
                device_app_version: client.device_app_version.clone(),
            });
            self.transport
                .password_login(&request.0)
                .await
                .map_err(AuthFailure::from)
        })
    }

    fn register<'a>(
        &'a self,
        request: &'a PasswordRegistrationRequest,
        client: &'a SessionClient,
    ) -> AuthFuture<'a, LoginResponse> {
        Box::pin(async move {
            let request = ZeroizingRegisterRequest(RegisterRequest {
                email: request.email.clone(),
                password: request.password.expose().to_string(),
                full_name: request.full_name.clone(),
                device_name: client.device_name.clone(),
                device_platform: client.device_platform.clone(),
                device_fingerprint: client.device_fingerprint.clone(),
                device_os: client.device_os.clone(),
                device_os_version: client.device_os_version.clone(),
                device_app_version: client.device_app_version.clone(),
                invite_token: None,
            });
            self.transport
                .register(&request.0)
                .await
                .map_err(AuthFailure::from)
        })
    }

    fn me<'a>(&'a self, access_token: &'a str) -> AuthFuture<'a, Identity> {
        Box::pin(async move {
            self.transport
                .me(access_token)
                .await
                .map_err(AuthFailure::from)
        })
    }

    fn oidc_login<'a>(&'a self, token: &'a OidcToken) -> AuthFuture<'a, LoginResponse> {
        Box::pin(async move {
            let request = ZeroizingOidcLoginRequest(OidcLoginWireRequest {
                token: token.expose().to_string(),
            });
            self.transport
                .oidc_login(&request.0)
                .await
                .map_err(AuthFailure::from)
        })
    }

    fn refresh<'a>(&'a self, refresh_token: &'a str) -> AuthFuture<'a, LoginResponse> {
        Box::pin(async move {
            let request = ZeroizingRefreshRequest(RefreshRequest {
                refresh_token: refresh_token.to_string(),
            });
            self.transport
                .refresh(&request.0)
                .await
                .map_err(AuthFailure::from)
        })
    }

    fn logout<'a>(&'a self, refresh_token: &'a str) -> AuthFuture<'a, ()> {
        Box::pin(async move {
            let request = ZeroizingLogoutRequest(LogoutRequest {
                refresh_token: refresh_token.to_string(),
            });
            self.transport
                .logout(&request.0)
                .await
                .map_err(AuthFailure::from)
        })
    }
}

trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

impl TokenManager {
    async fn oidc_login(
        &self,
        request: OidcLoginInput,
        operation: &SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        if let Some(kind) = operation.pre_dispatch_error() {
            return Err(SessionError::new(operation, kind));
        }
        let client = self
            .inner
            .client
            .clone()
            .ok_or_else(|| SessionError::new(operation, SessionErrorKind::Configuration))?;
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
        .map_err(|kind| SessionError::new(operation, kind))?;
        let (recovered, _) = recovered
            .map_err(|error| SessionError::new(operation, config_error_kind(&error, operation)))?;
        let cleanup_deferred = outcome_has_warnings(&recovered);

        let repository = self.inner.repository.clone();
        let connection_id = request.target.connection_id.clone();
        let profile_name = request.target.profile_name.clone();
        let client_id = client.client_id.clone();
        let (locks, anchor) = run_with_locks(locks, move || {
            repository.resolve_password_login_anchor(&connection_id, profile_name, &client_id)
        })
        .await
        .map_err(|kind| SessionError::new(operation, kind))?;
        let anchor = anchor
            .map_err(|error| SessionError::new(operation, config_error_kind(&error, operation)))?;
        let (locks, port, verified) = match self
            .verified_login_auth_port(locks, &anchor, operation)
            .await
        {
            Ok(value) => value,
            Err((locks, error)) => {
                drop(locks);
                return Err(error);
            }
        };
        if !verified.supports_oidc {
            drop(locks);
            return Err(SessionError::new(
                operation,
                SessionErrorKind::TransportRejected,
            ));
        }
        if let Some(kind) = operation.pre_dispatch_error() {
            drop(locks);
            return Err(SessionError::new(operation, kind));
        }

        let manager = self.clone();
        let detached = operation.detached_copy();
        tokio::spawn(async move {
            manager
                .oidc_login_dispatched(
                    locks,
                    port,
                    verified,
                    anchor,
                    request,
                    detached,
                    cleanup_deferred,
                )
                .await
        })
        .await
        .map_err(|_| SessionError::new(operation, SessionErrorKind::Internal))?
    }

    #[allow(clippy::too_many_arguments)]
    async fn oidc_login_dispatched(
        &self,
        locks: HeldSessionLocks,
        port: Arc<dyn AuthPort>,
        verified: EndpointIdentity,
        anchor: PasswordLoginAnchor,
        request: OidcLoginInput,
        operation: SessionOperation,
        mut cleanup_deferred: bool,
    ) -> Result<SessionAccess, SessionError> {
        let response = match port.oidc_login(&request.token).await {
            Ok(response) => response,
            Err(failure) => {
                drop(locks);
                return Err(SessionError::from_auth(&operation, &failure));
            }
        };
        drop(request.token);
        let expires_at = match checked_expiry(self.inner.clock.now(), response.expires_in) {
            Some(expires_at) => expires_at,
            None => {
                let _ = port.logout(&response.refresh_token).await;
                drop(locks);
                return Err(SessionError::new(&operation, SessionErrorKind::Protocol));
            }
        };
        let access = match CredentialSecret::new(response.access_token) {
            Ok(access) => access,
            Err(_) => {
                let _ = port.logout(&response.refresh_token).await;
                drop(locks);
                return Err(SessionError::new(&operation, SessionErrorKind::Protocol));
            }
        };
        let refresh = match CredentialSecret::new(response.refresh_token) {
            Ok(refresh) => refresh,
            Err(_) => {
                drop(locks);
                return Err(SessionError::new(&operation, SessionErrorKind::Protocol));
            }
        };

        let identity = match port.me(access.expose_secret()).await {
            Ok(identity) => identity,
            Err(failure) => {
                let _ = port.logout(refresh.expose_secret()).await;
                drop(locks);
                return Err(SessionError::from_auth(&operation, &failure));
            }
        };
        if !matches!(&identity.source, AuthSource::Oidc { .. })
            || identity.email.is_empty()
            || identity.email.trim() != identity.email
            || identity.email.len() > LOGIN_EMAIL_MAX_BYTES
        {
            let _ = port.logout(refresh.expose_secret()).await;
            drop(locks);
            return Err(SessionError::new(&operation, SessionErrorKind::Protocol));
        }
        let prelogin = match port.prelogin(&identity.email).await {
            Ok(prelogin) => prelogin,
            Err(failure) => {
                let _ = port.logout(refresh.expose_secret()).await;
                drop(locks);
                return Err(SessionError::from_auth(&operation, &failure));
            }
        };
        let authenticated_identity =
            match password_login_identity_from_prelogin(prelogin, Some(identity.email.clone())) {
                Ok(identity) => identity,
                Err(kind) => {
                    let _ = port.logout(refresh.expose_secret()).await;
                    drop(locks);
                    return Err(SessionError::new(&operation, kind));
                }
            };
        let account_subject = identity.user_id.to_string();
        let access_copy = match copy_secret(&access) {
            Ok(access) => access,
            Err(_) => {
                let _ = port.logout(refresh.expose_secret()).await;
                drop(locks);
                return Err(SessionError::new(&operation, SessionErrorKind::Internal));
            }
        };
        let refresh_copy = match copy_secret(&refresh) {
            Ok(refresh) => refresh,
            Err(_) => {
                let _ = port.logout(refresh.expose_secret()).await;
                drop(locks);
                return Err(SessionError::new(&operation, SessionErrorKind::Internal));
            }
        };
        let storage_id = anchor.storage_id().map(str::to_string);
        let commit = AuthenticatedSessionCommit::new(
            verified.binding.clone(),
            storage_id.clone(),
            AuthenticatedConnectionTarget::UseExisting {
                connection_id: anchor.connection_id().clone(),
                expected: StoredConnectionBinding::new(
                    anchor.address(),
                    Some(anchor.server_id().to_string()),
                    Some(anchor.server_fingerprint().to_string()),
                    storage_id.clone(),
                ),
            },
            IdentityCommit::InitializeOrMatch(authenticated_identity),
            anchor.client_id().clone(),
            anchor.profile_name(),
            CredentialBundle::new(Some(access_copy), Some(refresh_copy), None)
                .with_access_expires_at(Some(
                    expires_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                )),
        )
        .with_account_binding(account_subject.clone(), AuthMethod::Oidc);
        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let expected_revision = anchor.source_revision();
        let (locks, committed) = match run_with_locks(locks, move || {
            repository.commit_authenticated_session(expected_revision, commit, store.as_ref())
        })
        .await
        {
            Ok(result) => result,
            Err(_) => {
                let _ = port.logout(refresh.expose_secret()).await;
                return Err(SessionError::new(
                    &operation,
                    SessionErrorKind::RecoveryRequired,
                ));
            }
        };
        let committed = match committed {
            Ok(outcome) => outcome,
            Err(error) => {
                let _ = port.logout(refresh.expose_secret()).await;
                drop(locks);
                return Err(SessionError::new(
                    &operation,
                    config_error_kind(&error, &operation),
                ));
            }
        };
        cleanup_deferred |= outcome_has_warnings(committed.transaction());
        let (locks, authorized_target_generation) = self
            .generation_from_snapshot(
                locks,
                committed.snapshot().clone(),
                &request.target,
                &operation,
            )
            .await?;
        drop(locks);
        Ok(SessionAccess {
            operation_id: operation.operation_id,
            target: request.target,
            endpoint: verified.address().to_string(),
            storage_id,
            server_fingerprint: verified.server_fingerprint().to_string(),
            account_subject: Some(account_subject),
            auth_method: Some(AuthMethod::Oidc),
            personal_vaults_enabled: verified.personal_vaults_enabled,
            expires_at,
            source: AccessSource::OidcLogin,
            completion: operation.completion(),
            cleanup_deferred,
            authorized_target_generation,
            access_secret: access,
        })
    }

    async fn password_register(
        &self,
        request: PasswordRegistrationRequest,
        operation: &SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        if let Some(kind) = operation.pre_dispatch_error() {
            return Err(SessionError::new(operation, kind));
        }
        let client = self
            .inner
            .client
            .clone()
            .ok_or_else(|| SessionError::new(operation, SessionErrorKind::Configuration))?;
        let retry_password = LoginPassword::new(request.password.expose().to_string())
            .map_err(|_| SessionError::new(operation, SessionErrorKind::Internal))?;
        let retry_request = PasswordLoginRequest::new(
            request.target.clone(),
            request.email.clone(),
            retry_password,
        )
        .map_err(|_| SessionError::new(operation, SessionErrorKind::Internal))?;

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
        .map_err(|kind| SessionError::new(operation, kind))?;
        recovered
            .map_err(|error| SessionError::new(operation, config_error_kind(&error, operation)))?;
        let repository = self.inner.repository.clone();
        let connection_id = request.target.connection_id.clone();
        let profile_name = request.target.profile_name.clone();
        let client_id = client.client_id.clone();
        let (locks, anchor) = run_with_locks(locks, move || {
            repository.resolve_password_login_anchor(&connection_id, profile_name, &client_id)
        })
        .await
        .map_err(|kind| SessionError::new(operation, kind))?;
        let anchor = anchor
            .map_err(|error| SessionError::new(operation, config_error_kind(&error, operation)))?;
        let (locks, port, verified) = match self
            .verified_login_auth_port(locks, &anchor, operation)
            .await
        {
            Ok(value) => value,
            Err((locks, error)) => {
                drop(locks);
                return Err(error);
            }
        };
        if !verified.supports_password {
            drop(locks);
            return Err(SessionError::new(
                operation,
                SessionErrorKind::TransportRejected,
            ));
        }
        if let Some(kind) = operation.pre_dispatch_error() {
            drop(locks);
            return Err(SessionError::new(operation, kind));
        }
        let manager = self.clone();
        let detached = operation.detached_copy();
        let task = tokio::spawn(async move {
            manager
                .password_register_dispatched(locks, port, request, retry_request, client, detached)
                .await
        });
        task.await
            .map_err(|_| SessionError::new(operation, SessionErrorKind::Internal))?
    }

    async fn password_register_dispatched(
        &self,
        locks: HeldSessionLocks,
        port: Arc<dyn AuthPort>,
        request: PasswordRegistrationRequest,
        retry_request: PasswordLoginRequest,
        client: SessionClient,
        operation: SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        let response = port.register(&request, &client).await;
        drop(request);
        let response = match response {
            Ok(response) => response,
            Err(failure) => {
                drop(locks);
                return Err(SessionError::from_auth(&operation, &failure));
            }
        };
        let access = CredentialSecret::new(response.access_token);
        let refresh = CredentialSecret::new(response.refresh_token);
        let (access, refresh) = match (access, refresh) {
            (Ok(access), Ok(refresh)) => (access, refresh),
            _ => {
                drop(locks);
                return Err(SessionError::new(
                    &operation,
                    SessionErrorKind::SessionLostRemoteUnknown,
                ));
            }
        };
        // Registration creates a session before returning. Revoke that
        // bootstrap session, then enter the journaled password-login path so
        // only the canonical persisted session remains active.
        let _ = port.logout(refresh.expose_secret()).await;
        drop(refresh);
        drop(access);
        drop(port);
        drop(locks);
        self.password_login(retry_request, &operation).await
    }

    async fn generation_from_anchor(
        &self,
        locks: HeldSessionLocks,
        anchor: CredentialProfileAnchor,
        operation: &SessionOperation,
    ) -> Result<(HeldSessionLocks, Arc<AuthorizedTargetGeneration>), SessionError> {
        let repository = self.inner.repository.clone();
        let (locks, generation) = run_with_locks(locks, move || {
            repository.authorized_target_generation_from_anchor(&anchor)
        })
        .await
        .map_err(|_| SessionError::new(operation, SessionErrorKind::RecoveryRequired))?;
        match generation {
            Ok(generation) => Ok((locks, generation)),
            Err(_) => {
                drop(locks);
                Err(SessionError::new(
                    operation,
                    SessionErrorKind::RecoveryRequired,
                ))
            }
        }
    }

    async fn generation_from_snapshot(
        &self,
        locks: HeldSessionLocks,
        snapshot: crate::config::ConfigSnapshot,
        target: &SessionTarget,
        operation: &SessionOperation,
    ) -> Result<(HeldSessionLocks, Arc<AuthorizedTargetGeneration>), SessionError> {
        let repository = self.inner.repository.clone();
        let connection_id = target.connection_id.clone();
        let profile_name = target.profile_name.clone();
        let (locks, generation) = run_with_locks(locks, move || {
            repository.authorized_target_generation_from_snapshot(
                &snapshot,
                &connection_id,
                &profile_name,
            )
        })
        .await
        .map_err(|_| SessionError::new(operation, SessionErrorKind::RecoveryRequired))?;
        match generation {
            Ok(generation) => Ok((locks, generation)),
            Err(_) => {
                drop(locks);
                Err(SessionError::new(
                    operation,
                    SessionErrorKind::RecoveryRequired,
                ))
            }
        }
    }

    async fn password_login(
        &self,
        request: PasswordLoginRequest,
        operation: &SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        if let Some(kind) = operation.pre_dispatch_error() {
            return Err(SessionError::new(operation, kind));
        }
        let client = self
            .inner
            .client
            .clone()
            .ok_or_else(|| SessionError::new(operation, SessionErrorKind::Configuration))?;
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
        .map_err(|kind| SessionError::new(operation, kind))?;
        let (recovered, _) = recovered
            .map_err(|error| SessionError::new(operation, config_error_kind(&error, operation)))?;
        let cleanup_deferred = outcome_has_warnings(&recovered);

        let repository = self.inner.repository.clone();
        let connection_id = request.target.connection_id.clone();
        let profile_name = request.target.profile_name.clone();
        let client_id = client.client_id.clone();
        let (locks, anchor) = run_with_locks(locks, move || {
            repository.resolve_password_login_anchor(&connection_id, profile_name, &client_id)
        })
        .await
        .map_err(|kind| SessionError::new(operation, kind))?;
        let anchor = anchor
            .map_err(|error| SessionError::new(operation, config_error_kind(&error, operation)))?;
        let (locks, port, verified) = match self
            .verified_login_auth_port(locks, &anchor, operation)
            .await
        {
            Ok(value) => value,
            Err((locks, error)) => {
                drop(locks);
                return Err(error);
            }
        };
        if !verified.supports_password {
            drop(locks);
            return Err(SessionError::new(
                operation,
                SessionErrorKind::TransportRejected,
            ));
        }

        enum PreloginResult {
            Completed(Result<PreloginResponse, AuthFailure>),
            Cancelled,
            Deadline,
        }
        let deadline = tokio::time::Instant::from_std(operation.deadline);
        let prelogin = tokio::select! {
            biased;
            _ = operation.cancelled() => PreloginResult::Cancelled,
            _ = tokio::time::sleep_until(deadline) => PreloginResult::Deadline,
            result = port.prelogin(&request.email) => PreloginResult::Completed(result),
        };
        let prelogin = match prelogin {
            PreloginResult::Completed(Ok(prelogin)) => prelogin,
            PreloginResult::Completed(Err(failure)) => {
                drop(locks);
                return Err(SessionError::from_auth(operation, &failure));
            }
            PreloginResult::Cancelled => {
                drop(locks);
                return Err(SessionError::new(operation, SessionErrorKind::Cancelled));
            }
            PreloginResult::Deadline => {
                drop(locks);
                return Err(SessionError::new(
                    operation,
                    SessionErrorKind::DeadlineExceeded,
                ));
            }
        };
        let identity = match password_login_identity_from_prelogin(prelogin, None) {
            Ok(identity) => identity,
            Err(kind) => {
                drop(locks);
                return Err(SessionError::new(operation, kind));
            }
        };
        if let Some(kind) = operation.pre_dispatch_error() {
            drop(locks);
            return Err(SessionError::new(operation, kind));
        }
        let storage_id = anchor.storage_id().map(str::to_string);
        let prelogin_identity = identity.clone();
        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let operation_id = operation.operation_id.to_string();
        let endpoint_binding = verified.binding.clone();
        let (locks, permit) = run_with_locks(locks, move || {
            repository.prepare_password_login_intent_with_operation_locks(
                &anchor,
                &endpoint_binding,
                identity,
                &operation_id,
                store.as_ref(),
            )
        })
        .await
        .map_err(|kind| SessionError::new(operation, kind))?;
        let permit = match permit {
            Ok(permit) => permit,
            Err(error) => {
                drop(locks);
                return Err(SessionError::new(
                    operation,
                    config_error_kind(&error, operation),
                ));
            }
        };
        if let Some(kind) = operation.pre_dispatch_error() {
            return self
                .finish_failed_password_login(
                    locks,
                    None,
                    &port,
                    operation,
                    kind,
                    None,
                    None,
                    cleanup_deferred,
                )
                .await;
        }

        let manager = self.clone();
        let detached_operation = operation.detached_copy();
        let task = tokio::spawn(async move {
            manager
                .password_login_dispatched(
                    locks,
                    permit,
                    prelogin_identity,
                    request,
                    client,
                    port,
                    verified,
                    storage_id,
                    detached_operation,
                    cleanup_deferred,
                )
                .await
        });
        task.await
            .map_err(|_| SessionError::new(operation, SessionErrorKind::Internal))?
    }

    #[allow(clippy::too_many_arguments)]
    async fn password_login_dispatched(
        &self,
        locks: HeldSessionLocks,
        permit: PasswordLoginIntentPermit,
        prelogin_identity: ConfigIdentity,
        request: PasswordLoginRequest,
        client: SessionClient,
        port: Arc<dyn AuthPort>,
        verified: EndpointIdentity,
        storage_id: Option<String>,
        operation: SessionOperation,
        cleanup_deferred: bool,
    ) -> Result<SessionAccess, SessionError> {
        // Once armed, this detached task owns terminalization. There is no
        // cancellation branch around the exactly-once POST.
        let dispatched = port
            .password_login(&request.email, &request.password, &client)
            .await;
        let response = match dispatched {
            Ok(response) => response,
            Err(failure) => {
                return self
                    .finish_failed_password_login(
                        locks,
                        None,
                        &port,
                        &operation,
                        failure.kind.session_error_kind(),
                        failure.status,
                        failure.server_code,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        let LoginResponse {
            access_token,
            refresh_token,
            expires_in,
        } = response;
        let access = CredentialSecret::new(access_token);
        let refresh = CredentialSecret::new(refresh_token);
        let expires_at = checked_expiry(self.inner.clock.now(), expires_in);
        let (access, refresh, expires_at) = match (access, refresh, expires_at) {
            (Ok(access), Ok(refresh), Some(expires_at)) => (access, refresh, expires_at),
            (_, refresh, _) => {
                let refresh = refresh.ok();
                let remote_outcome_unknown = refresh.is_none();
                return self
                    .finish_failed_password_login(
                        locks,
                        refresh.as_ref(),
                        &port,
                        &operation,
                        if remote_outcome_unknown {
                            SessionErrorKind::SessionLostRemoteUnknown
                        } else {
                            SessionErrorKind::Protocol
                        },
                        None,
                        None,
                        cleanup_deferred || remote_outcome_unknown,
                    )
                    .await;
            }
        };
        if let Some(kind) = operation.pre_dispatch_error() {
            return self
                .finish_failed_password_login(
                    locks,
                    Some(&refresh),
                    &port,
                    &operation,
                    kind,
                    None,
                    None,
                    cleanup_deferred,
                )
                .await;
        }
        enum MeResult {
            Completed(Box<Result<Identity, AuthFailure>>),
            Cancelled,
            Deadline,
        }
        let deadline = tokio::time::Instant::from_std(operation.deadline);
        let me = tokio::select! {
            biased;
            _ = operation.cancelled() => MeResult::Cancelled,
            _ = tokio::time::sleep_until(deadline) => MeResult::Deadline,
            result = port.me(access.expose_secret()) => MeResult::Completed(Box::new(result)),
        };
        let identity = match me {
            MeResult::Completed(result) => match *result {
                Ok(identity) => identity,
                Err(failure) => {
                    return self
                        .finish_failed_password_login(
                            locks,
                            Some(&refresh),
                            &port,
                            &operation,
                            failure.kind.session_error_kind(),
                            failure.status,
                            failure.server_code,
                            cleanup_deferred,
                        )
                        .await;
                }
            },
            MeResult::Cancelled => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::Cancelled,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
            MeResult::Deadline => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::DeadlineExceeded,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        if !matches!(identity.source, AuthSource::Internal) {
            return self
                .finish_failed_password_login(
                    locks,
                    Some(&refresh),
                    &port,
                    &operation,
                    SessionErrorKind::TransportRejected,
                    None,
                    None,
                    cleanup_deferred,
                )
                .await;
        }
        let canonical_email = identity.email.clone();
        if canonical_email.is_empty()
            || canonical_email.trim() != canonical_email
            || canonical_email.len() > LOGIN_EMAIL_MAX_BYTES
        {
            return self
                .finish_failed_password_login(
                    locks,
                    Some(&refresh),
                    &port,
                    &operation,
                    SessionErrorKind::Protocol,
                    None,
                    None,
                    cleanup_deferred,
                )
                .await;
        }
        enum ConfirmedPreloginResult {
            Completed(Result<PreloginResponse, AuthFailure>),
            Cancelled,
            Deadline,
        }
        let deadline = tokio::time::Instant::from_std(operation.deadline);
        let confirmed_prelogin = tokio::select! {
            biased;
            _ = operation.cancelled() => ConfirmedPreloginResult::Cancelled,
            _ = tokio::time::sleep_until(deadline) => ConfirmedPreloginResult::Deadline,
            result = port.prelogin(&canonical_email) => ConfirmedPreloginResult::Completed(result),
        };
        let confirmed_prelogin = match confirmed_prelogin {
            ConfirmedPreloginResult::Completed(Ok(prelogin)) => prelogin,
            ConfirmedPreloginResult::Completed(Err(failure)) => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        failure.kind.session_error_kind(),
                        failure.status,
                        failure.server_code,
                        cleanup_deferred,
                    )
                    .await;
            }
            ConfirmedPreloginResult::Cancelled => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::Cancelled,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
            ConfirmedPreloginResult::Deadline => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::DeadlineExceeded,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        let authenticated_identity = match password_login_identity_from_prelogin(
            confirmed_prelogin,
            Some(canonical_email),
        ) {
            Ok(identity) => identity,
            Err(kind) => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        kind,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        if !password_login_kdf_is_coherent(&prelogin_identity, &authenticated_identity) {
            return self
                .finish_failed_password_login(
                    locks,
                    Some(&refresh),
                    &port,
                    &operation,
                    SessionErrorKind::Protocol,
                    None,
                    None,
                    cleanup_deferred,
                )
                .await;
        }
        if let Some(kind) = operation.pre_dispatch_error() {
            return self
                .finish_failed_password_login(
                    locks,
                    Some(&refresh),
                    &port,
                    &operation,
                    kind,
                    None,
                    None,
                    cleanup_deferred,
                )
                .await;
        }
        let account_subject = identity.user_id.to_string();
        let access_copy = match copy_secret(&access) {
            Ok(secret) => secret,
            Err(_) => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::Internal,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        let refresh_copy = match copy_secret(&refresh) {
            Ok(secret) => secret,
            Err(_) => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::Internal,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        let expires_at_wire = expires_at.to_rfc3339_opts(SecondsFormat::Secs, true);
        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let subject_for_commit = account_subject.clone();
        let operation_for_commit = operation.detached_copy();
        let (locks, (committed, permit)) = run_with_locks(locks, move || {
            let mut permit = permit;
            let committed = repository
                .commit_password_login_after_auth_intent_with_operation_locks(
                    &mut permit,
                    &subject_for_commit,
                    authenticated_identity,
                    access_copy,
                    refresh_copy,
                    expires_at_wire,
                    store.as_ref(),
                    || operation_for_commit.pre_dispatch_error().is_some(),
                );
            (committed, permit)
        })
        .await
        .map_err(|_| SessionError::new(&operation, SessionErrorKind::RecoveryRequired))?;
        match committed {
            Ok(outcome) => {
                let cleanup_deferred = cleanup_deferred || outcome_has_warnings(&outcome);
                let (locks, authorized_target_generation) = self
                    .generation_from_snapshot(
                        locks,
                        outcome.snapshot().clone(),
                        &request.target,
                        &operation,
                    )
                    .await?;
                drop(locks);
                Ok(password_login_access(
                    &request.target,
                    &verified,
                    &operation,
                    PasswordLoginAccess {
                        storage_id: storage_id.clone(),
                        account_subject,
                        expires_at,
                        access_secret: access,
                        cleanup_deferred,
                        authorized_target_generation,
                    },
                ))
            }
            Err(commit_error) => {
                self.finish_password_login_commit_failure(
                    locks,
                    permit,
                    &request.target,
                    &verified,
                    storage_id,
                    account_subject,
                    expires_at,
                    access,
                    refresh,
                    port,
                    &operation,
                    cleanup_deferred,
                    commit_error,
                )
                .await
            }
        }
    }

    async fn access(
        &self,
        target: &SessionTarget,
        operation: &SessionOperation,
    ) -> Result<SessionAccess, SessionError> {
        let (locks, anchor, cleanup_deferred) = self.begin_operation(target, operation).await?;
        let decision = access_decision(&anchor, self.inner.clock.now());

        match decision {
            AccessDecision::Stored(expires_at) => {
                let endpoint = anchor.address().to_string();
                let storage_id = anchor.storage_id().map(str::to_string);
                let server_fingerprint =
                    anchor.server_fingerprint().unwrap_or_default().to_string();
                let account_subject = anchor.account_subject().map(str::to_string);
                let auth_method = anchor.auth_method();
                let (locks, _port, verified_identity) =
                    match self.verified_auth_port(locks, &anchor, operation).await {
                        Ok(value) => value,
                        Err((locks, error)) => {
                            drop(locks);
                            return Err(error);
                        }
                    };
                let (locks, access_secret) = self
                    .read_required_credential(locks, &anchor, CredentialKind::Access, operation)
                    .await?;
                if let Some(kind) = operation.pre_dispatch_error() {
                    drop(locks);
                    return Err(SessionError::new(operation, kind));
                }
                let (locks, authorized_target_generation) = self
                    .generation_from_anchor(locks, anchor, operation)
                    .await?;
                drop(locks);
                Ok(SessionAccess {
                    operation_id: operation.operation_id,
                    target: target.clone(),
                    endpoint,
                    storage_id,
                    server_fingerprint,
                    account_subject,
                    auth_method,
                    personal_vaults_enabled: verified_identity.personal_vaults_enabled,
                    expires_at,
                    source: AccessSource::Stored,
                    completion: operation.completion(),
                    cleanup_deferred,
                    authorized_target_generation,
                    access_secret,
                })
            }
            AccessDecision::Refresh => {
                if !anchor.credentials().contains_key(&CredentialKind::Refresh) {
                    drop(locks);
                    return Err(SessionError::new(
                        operation,
                        SessionErrorKind::ReauthenticationRequired,
                    ));
                }
                let (locks, port, verified_identity) =
                    match self.verified_auth_port(locks, &anchor, operation).await {
                        Ok(value) => value,
                        Err((locks, error)) => {
                            drop(locks);
                            return Err(error);
                        }
                    };
                let (locks, refresh_secret) = self
                    .read_required_credential(locks, &anchor, CredentialKind::Refresh, operation)
                    .await?;
                if let Some(kind) = operation.pre_dispatch_error() {
                    drop(locks);
                    return Err(SessionError::new(operation, kind));
                }
                let manager = self.clone();
                let target = target.clone();
                let detached_operation = operation.detached_copy();
                let task = tokio::spawn(async move {
                    manager
                        .refresh_dispatched(
                            locks,
                            anchor,
                            target,
                            port,
                            verified_identity.personal_vaults_enabled,
                            refresh_secret,
                            detached_operation,
                            cleanup_deferred,
                        )
                        .await
                });
                task.await
                    .map_err(|_| SessionError::new(operation, SessionErrorKind::Internal))?
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn refresh_dispatched(
        &self,
        locks: HeldSessionLocks,
        anchor: CredentialProfileAnchor,
        target: SessionTarget,
        port: Arc<dyn AuthPort>,
        personal_vaults_enabled: bool,
        refresh_secret: CredentialSecret,
        operation: SessionOperation,
        mut cleanup_deferred: bool,
    ) -> Result<SessionAccess, SessionError> {
        // This task owns the locks and terminal state. Dropping the caller's future only detaches
        // the JoinHandle; it cannot strand an already-dispatched rotating refresh credential.
        if let Some(kind) = operation.pre_dispatch_error() {
            drop(refresh_secret);
            drop(locks);
            return Err(SessionError::new(&operation, kind));
        }
        let repository = self.inner.repository.clone();
        let endpoint = anchor.address().to_string();
        let storage_id = anchor.storage_id().map(str::to_string);
        let server_fingerprint = anchor.server_fingerprint().unwrap_or_default().to_string();
        let account_subject = anchor.account_subject().map(str::to_string);
        let auth_method = anchor.auth_method();
        let operation_id = operation.operation_id.to_string();
        let (locks, permit) = run_with_locks(locks, move || {
            repository.prepare_auth_operation_intent_with_operation_locks(
                &anchor,
                AuthOperationKind::Refresh,
                &operation_id,
            )
        })
        .await
        .map_err(|kind| SessionError::new(&operation, kind))?;
        let permit = match permit {
            Ok(permit) => permit,
            Err(error) => {
                drop(refresh_secret);
                drop(locks);
                return Err(SessionError::new(
                    &operation,
                    config_error_kind(&error, &operation),
                ));
            }
        };
        let dispatched = port.refresh(refresh_secret.expose_secret()).await;
        drop(refresh_secret);

        match dispatched {
            Ok(response) => {
                self.commit_refresh(
                    locks,
                    permit,
                    &target,
                    &endpoint,
                    storage_id.as_deref(),
                    &server_fingerprint,
                    account_subject.as_deref(),
                    auth_method,
                    personal_vaults_enabled,
                    port,
                    response,
                    &operation,
                    cleanup_deferred,
                )
                .await
            }
            Err(failure) if failure.kind == AuthFailureKind::SessionExpired => {
                let revoked = self.terminal_revoke(locks, permit, &operation).await?;
                cleanup_deferred |= revoked;
                Err(SessionError::terminal(
                    &operation,
                    SessionErrorKind::SessionExpired,
                    failure.status,
                    failure.server_code,
                    cleanup_deferred,
                    true,
                ))
            }
            Err(failure)
                if matches!(
                    failure.kind,
                    AuthFailureKind::AmbiguousOutcome
                        | AuthFailureKind::Timeout
                        | AuthFailureKind::Unavailable
                        | AuthFailureKind::Server
                ) =>
            {
                let revoked = self.terminal_revoke(locks, permit, &operation).await?;
                cleanup_deferred |= revoked;
                Err(SessionError::terminal(
                    &operation,
                    SessionErrorKind::SessionLostRemoteUnknown,
                    failure.status,
                    failure.server_code,
                    cleanup_deferred,
                    true,
                ))
            }
            Err(failure) => {
                let revoked = self.terminal_revoke(locks, permit, &operation).await?;
                cleanup_deferred |= revoked;
                Err(SessionError::terminal(
                    &operation,
                    failure.kind.session_error_kind(),
                    failure.status,
                    failure.server_code,
                    cleanup_deferred,
                    true,
                ))
            }
        }
    }

    async fn logout(
        &self,
        target: &SessionTarget,
        operation: &SessionOperation,
    ) -> Result<LogoutOutcome, SessionError> {
        let (locks, anchor, cleanup_deferred) = match self.begin_operation(target, operation).await
        {
            Ok(value) => value,
            Err(error) if error.kind == SessionErrorKind::SessionNotFound => {
                return Ok(LogoutOutcome {
                    operation_id: operation.operation_id,
                    remote: RemoteLogoutStatus::NotAttempted,
                    local: LocalLogoutStatus::AlreadyAbsent,
                    completion: operation.completion(),
                    cleanup_deferred: false,
                });
            }
            Err(error) => return Err(error),
        };

        let mut locks = locks;
        let mut remote_attempt = None;

        if anchor.credentials().contains_key(&CredentialKind::Refresh) {
            match self.verified_auth_port(locks, &anchor, operation).await {
                Ok((next_locks, port, _verified_identity)) => {
                    locks = next_locks;
                    let (next_locks, read) = self
                        .read_optional_credential(locks, &anchor, CredentialKind::Refresh)
                        .await
                        .map_err(|kind| SessionError::new(operation, kind))?;
                    locks = next_locks;
                    if let Ok(secret) = read {
                        remote_attempt = Some((port, secret));
                    }
                }
                Err((next_locks, error)) => {
                    if matches!(
                        error.kind,
                        SessionErrorKind::Cancelled | SessionErrorKind::DeadlineExceeded
                    ) {
                        drop(next_locks);
                        return Err(error);
                    }
                    // Logout is fail-closed locally without reading a secret when trust fails.
                    locks = next_locks;
                }
            }
        }
        if let Some(kind) = operation.pre_dispatch_error() {
            drop(locks);
            return Err(SessionError::new(operation, kind));
        }

        let manager = self.clone();
        let detached_operation = operation.detached_copy();
        let task = tokio::spawn(async move {
            manager
                .logout_terminal(
                    locks,
                    anchor,
                    remote_attempt,
                    detached_operation,
                    cleanup_deferred,
                )
                .await
        });
        task.await
            .map_err(|_| SessionError::new(operation, SessionErrorKind::Internal))?
    }

    async fn logout_terminal(
        &self,
        locks: HeldSessionLocks,
        anchor: CredentialProfileAnchor,
        remote_attempt: Option<(Arc<dyn AuthPort>, CredentialSecret)>,
        operation: SessionOperation,
        mut cleanup_deferred: bool,
    ) -> Result<LogoutOutcome, SessionError> {
        if let Some(kind) = operation.pre_dispatch_error() {
            drop(remote_attempt);
            drop(locks);
            return Err(SessionError::new(&operation, kind));
        }
        let repository = self.inner.repository.clone();
        let operation_id = operation.operation_id.to_string();
        let (locks, permit) = run_with_locks(locks, move || {
            repository.prepare_auth_operation_intent_with_operation_locks(
                &anchor,
                AuthOperationKind::Logout,
                &operation_id,
            )
        })
        .await
        .map_err(|kind| SessionError::new(&operation, kind))?;
        let permit = match permit {
            Ok(permit) => permit,
            Err(error) => {
                drop(remote_attempt);
                drop(locks);
                return Err(SessionError::new(
                    &operation,
                    config_error_kind(&error, &operation),
                ));
            }
        };
        let remote = if let Some((port, secret)) = remote_attempt {
            let result = port.logout(secret.expose_secret()).await;
            drop(secret);
            if result.is_ok() {
                RemoteLogoutStatus::Confirmed
            } else {
                RemoteLogoutStatus::Unconfirmed
            }
        } else {
            RemoteLogoutStatus::NotAttempted
        };
        let revoked = self.terminal_revoke(locks, permit, &operation).await?;
        cleanup_deferred |= revoked;
        Ok(LogoutOutcome {
            operation_id: operation.operation_id,
            remote,
            local: LocalLogoutStatus::Revoked,
            completion: operation.completion(),
            cleanup_deferred,
        })
    }

    async fn begin_operation(
        &self,
        target: &SessionTarget,
        operation: &SessionOperation,
    ) -> Result<(HeldSessionLocks, CredentialProfileAnchor, bool), SessionError> {
        if let Some(kind) = operation.pre_dispatch_error() {
            return Err(SessionError::new(operation, kind));
        }
        let locks = acquire_session_locks(
            self.inner.repository.paths().root().to_path_buf(),
            operation,
        )
        .await?;

        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let (locks, reconciled) = run_with_locks(locks, move || {
            repository.reconcile_auth_operation_with_operation_locks(store.as_ref())
        })
        .await
        .map_err(|kind| SessionError::new(operation, kind))?;
        let (reconciled, _disposition) = reconciled
            .map_err(|error| SessionError::new(operation, config_error_kind(&error, operation)))?;
        let cleanup_deferred = outcome_has_warnings(&reconciled);

        if let Some(kind) = operation.pre_dispatch_error() {
            drop(locks);
            return Err(SessionError::new(operation, kind));
        }
        let repository = self.inner.repository.clone();
        let connection_id = target.connection_id.clone();
        let profile_name = target.profile_name.clone();
        let (locks, anchor) = run_with_locks(locks, move || {
            repository.resolve_credential_profile_anchor(&connection_id, profile_name)
        })
        .await
        .map_err(|kind| SessionError::new(operation, kind))?;
        let anchor = anchor
            .map_err(|error| SessionError::new(operation, config_error_kind(&error, operation)))?;
        Ok((locks, anchor, cleanup_deferred))
    }

    async fn read_required_credential(
        &self,
        locks: HeldSessionLocks,
        anchor: &CredentialProfileAnchor,
        kind: CredentialKind,
        operation: &SessionOperation,
    ) -> Result<(HeldSessionLocks, CredentialSecret), SessionError> {
        let (locks, result) = self
            .read_optional_credential(locks, anchor, kind)
            .await
            .map_err(|kind| SessionError::new(operation, kind))?;
        match result {
            Ok(secret) => Ok((locks, secret)),
            Err(error) => {
                drop(locks);
                Err(SessionError::new(
                    operation,
                    credential_read_error_kind(error),
                ))
            }
        }
    }

    async fn read_optional_credential(
        &self,
        locks: HeldSessionLocks,
        anchor: &CredentialProfileAnchor,
        kind: CredentialKind,
    ) -> Result<
        (
            HeldSessionLocks,
            Result<CredentialSecret, ReadCredentialError>,
        ),
        SessionErrorKind,
    > {
        let Some(credential_id) = anchor.credentials().get(&kind).cloned() else {
            return Ok((locks, Err(ReadCredentialError::MissingSlot)));
        };
        let store = self.inner.credential_store.clone();
        run_with_locks(locks, move || match store.get(&credential_id) {
            Ok(Some(secret)) => Ok(secret),
            Ok(None) => Err(ReadCredentialError::MissingPhysical),
            Err(error) => Err(ReadCredentialError::Port(error.kind().clone())),
        })
        .await
    }

    async fn verified_auth_port(
        &self,
        locks: HeldSessionLocks,
        anchor: &CredentialProfileAnchor,
        operation: &SessionOperation,
    ) -> Result<
        (HeldSessionLocks, Arc<dyn AuthPort>, EndpointIdentity),
        (HeldSessionLocks, SessionError),
    > {
        let (Some(expected_server_id), Some(expected_fingerprint)) =
            (anchor.server_id(), anchor.server_fingerprint())
        else {
            return Err((
                locks,
                SessionError::new(operation, SessionErrorKind::TrustRequired),
            ));
        };
        let endpoint = anchor.address().to_string();
        let Some(timeout) = request_timeout(operation) else {
            return Err((
                locks,
                SessionError::new(operation, SessionErrorKind::DeadlineExceeded),
            ));
        };
        let port = match self.inner.auth_factory.connect(&endpoint, timeout) {
            Ok(port) => port,
            Err(failure) => {
                return Err((locks, SessionError::from_auth(operation, &failure)));
            }
        };

        enum ProbeResult {
            Completed(Result<EndpointIdentity, AuthFailure>),
            Cancelled,
            Deadline,
        }
        let deadline = tokio::time::Instant::from_std(operation.deadline);
        let probe = tokio::select! {
            biased;
            _ = operation.cancelled() => ProbeResult::Cancelled,
            _ = tokio::time::sleep_until(deadline) => ProbeResult::Deadline,
            result = port.verified_endpoint() => ProbeResult::Completed(result),
        };
        let observed = match probe {
            ProbeResult::Completed(Ok(observed)) => observed,
            ProbeResult::Completed(Err(failure)) => {
                return Err((locks, SessionError::from_auth(operation, &failure)));
            }
            ProbeResult::Cancelled => {
                return Err((
                    locks,
                    SessionError::new(operation, SessionErrorKind::Cancelled),
                ));
            }
            ProbeResult::Deadline => {
                return Err((
                    locks,
                    SessionError::new(operation, SessionErrorKind::DeadlineExceeded),
                ));
            }
        };
        if observed.address() != endpoint
            || observed.server_id() != expected_server_id
            || observed.server_fingerprint() != expected_fingerprint
        {
            return Err((
                locks,
                SessionError::new(operation, SessionErrorKind::TrustMismatch),
            ));
        }
        Ok((locks, port, observed))
    }

    async fn verified_login_auth_port(
        &self,
        locks: HeldSessionLocks,
        anchor: &PasswordLoginAnchor,
        operation: &SessionOperation,
    ) -> Result<
        (HeldSessionLocks, Arc<dyn AuthPort>, EndpointIdentity),
        (HeldSessionLocks, SessionError),
    > {
        let endpoint = anchor.address().to_string();
        let Some(timeout) = request_timeout(operation) else {
            return Err((
                locks,
                SessionError::new(operation, SessionErrorKind::DeadlineExceeded),
            ));
        };
        let port = match self.inner.auth_factory.connect(&endpoint, timeout) {
            Ok(port) => port,
            Err(failure) => {
                return Err((locks, SessionError::from_auth(operation, &failure)));
            }
        };
        enum ProbeResult {
            Completed(Result<EndpointIdentity, AuthFailure>),
            Cancelled,
            Deadline,
        }
        let deadline = tokio::time::Instant::from_std(operation.deadline);
        let probe = tokio::select! {
            biased;
            _ = operation.cancelled() => ProbeResult::Cancelled,
            _ = tokio::time::sleep_until(deadline) => ProbeResult::Deadline,
            result = port.verified_endpoint() => ProbeResult::Completed(result),
        };
        let observed = match probe {
            ProbeResult::Completed(Ok(observed)) => observed,
            ProbeResult::Completed(Err(failure)) => {
                return Err((locks, SessionError::from_auth(operation, &failure)));
            }
            ProbeResult::Cancelled => {
                return Err((
                    locks,
                    SessionError::new(operation, SessionErrorKind::Cancelled),
                ));
            }
            ProbeResult::Deadline => {
                return Err((
                    locks,
                    SessionError::new(operation, SessionErrorKind::DeadlineExceeded),
                ));
            }
        };
        if observed.address() != endpoint
            || observed.server_id() != anchor.server_id()
            || observed.server_fingerprint() != anchor.server_fingerprint()
        {
            return Err((
                locks,
                SessionError::new(operation, SessionErrorKind::TrustMismatch),
            ));
        }
        Ok((locks, port, observed))
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_failed_password_login(
        &self,
        locks: HeldSessionLocks,
        new_refresh: Option<&CredentialSecret>,
        port: &Arc<dyn AuthPort>,
        operation: &SessionOperation,
        kind: SessionErrorKind,
        status: Option<u16>,
        server_code: Option<&'static str>,
        mut cleanup_deferred: bool,
    ) -> Result<SessionAccess, SessionError> {
        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let (locks, recovered) = run_with_locks(locks, move || {
            repository.reconcile_auth_operation_with_operation_locks(store.as_ref())
        })
        .await
        .map_err(|_| {
            SessionError::terminal(
                operation,
                SessionErrorKind::RecoveryRequired,
                status,
                server_code,
                cleanup_deferred,
                false,
            )
        })?;
        match recovered {
            Ok((
                outcome,
                AuthOperationRecoveryDisposition::LoginAbandoned
                | AuthOperationRecoveryDisposition::TargetRemoved,
            )) => {
                cleanup_deferred |= outcome_has_warnings(&outcome);
                if let Some(refresh) = new_refresh {
                    if let Err(failure) = port.logout(refresh.expose_secret()).await {
                        drop(locks);
                        return Err(SessionError::terminal(
                            operation,
                            SessionErrorKind::SessionLostRemoteUnknown,
                            failure.status,
                            failure.server_code,
                            true,
                            false,
                        ));
                    }
                }
                drop(locks);
                Err(SessionError::terminal(
                    operation,
                    kind,
                    status,
                    server_code,
                    cleanup_deferred,
                    false,
                ))
            }
            Ok(_) | Err(_) => {
                drop(locks);
                Err(SessionError::terminal(
                    operation,
                    SessionErrorKind::RecoveryRequired,
                    status,
                    server_code,
                    cleanup_deferred,
                    false,
                ))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_password_login_commit_failure(
        &self,
        locks: HeldSessionLocks,
        permit: PasswordLoginIntentPermit,
        target: &SessionTarget,
        verified: &EndpointIdentity,
        storage_id: Option<String>,
        account_subject: String,
        expires_at: DateTime<Utc>,
        access: CredentialSecret,
        refresh: CredentialSecret,
        port: Arc<dyn AuthPort>,
        operation: &SessionOperation,
        mut cleanup_deferred: bool,
        commit_error: ConfigError,
    ) -> Result<SessionAccess, SessionError> {
        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let (mut locks, recovered) = run_with_locks(locks, move || {
            repository.reconcile_auth_operation_with_operation_locks(store.as_ref())
        })
        .await
        .map_err(|_| {
            SessionError::terminal(
                operation,
                SessionErrorKind::RecoveryRequired,
                None,
                None,
                cleanup_deferred,
                false,
            )
        })?;
        match recovered {
            Ok((outcome, AuthOperationRecoveryDisposition::CandidatePreserved)) => {
                cleanup_deferred |= outcome_has_warnings(&outcome);
                let (next_locks, authorized_target_generation) = self
                    .generation_from_snapshot(locks, outcome.snapshot().clone(), target, operation)
                    .await?;
                locks = next_locks;
                drop(locks);
                Ok(password_login_access(
                    target,
                    verified,
                    operation,
                    PasswordLoginAccess {
                        storage_id,
                        account_subject,
                        expires_at,
                        access_secret: access,
                        cleanup_deferred,
                        authorized_target_generation,
                    },
                ))
            }
            Ok((outcome, AuthOperationRecoveryDisposition::NoIntent)) => {
                cleanup_deferred |= outcome_has_warnings(&outcome);
                let repository = self.inner.repository.clone();
                let (next_locks, published) = run_with_locks(locks, move || {
                    repository.password_login_candidate_is_published_with_operation_locks(&permit)
                })
                .await
                .map_err(|_| {
                    SessionError::terminal(
                        operation,
                        SessionErrorKind::RecoveryRequired,
                        None,
                        None,
                        cleanup_deferred,
                        false,
                    )
                })?;
                locks = next_locks;
                if let Ok(Some(snapshot)) = published {
                    let (next_locks, authorized_target_generation) = self
                        .generation_from_snapshot(locks, snapshot, target, operation)
                        .await?;
                    locks = next_locks;
                    drop(locks);
                    return Ok(password_login_access(
                        target,
                        verified,
                        operation,
                        PasswordLoginAccess {
                            storage_id,
                            account_subject,
                            expires_at,
                            access_secret: access,
                            cleanup_deferred,
                            authorized_target_generation,
                        },
                    ));
                }
                drop(locks);
                Err(SessionError::terminal(
                    operation,
                    SessionErrorKind::RecoveryRequired,
                    None,
                    None,
                    cleanup_deferred,
                    false,
                ))
            }
            Ok((
                outcome,
                AuthOperationRecoveryDisposition::LoginAbandoned
                | AuthOperationRecoveryDisposition::TargetRemoved,
            )) => {
                cleanup_deferred |= outcome_has_warnings(&outcome);
                if let Err(failure) = port.logout(refresh.expose_secret()).await {
                    drop(locks);
                    return Err(SessionError::terminal(
                        operation,
                        SessionErrorKind::SessionLostRemoteUnknown,
                        failure.status,
                        failure.server_code,
                        true,
                        false,
                    ));
                }
                drop(locks);
                Err(SessionError::terminal(
                    operation,
                    operation
                        .pre_dispatch_error()
                        .unwrap_or_else(|| config_error_kind(&commit_error, operation)),
                    None,
                    None,
                    cleanup_deferred,
                    false,
                ))
            }
            Ok((_, AuthOperationRecoveryDisposition::SourceRevoked)) | Err(_) => {
                drop(locks);
                Err(SessionError::terminal(
                    operation,
                    SessionErrorKind::RecoveryRequired,
                    None,
                    None,
                    cleanup_deferred,
                    false,
                ))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_refresh(
        &self,
        locks: HeldSessionLocks,
        permit: AuthOperationIntentPermit,
        target: &SessionTarget,
        endpoint: &str,
        storage_id: Option<&str>,
        server_fingerprint: &str,
        account_subject: Option<&str>,
        auth_method: Option<AuthMethod>,
        personal_vaults_enabled: bool,
        port: Arc<dyn AuthPort>,
        response: LoginResponse,
        operation: &SessionOperation,
        mut cleanup_deferred: bool,
    ) -> Result<SessionAccess, SessionError> {
        let LoginResponse {
            access_token,
            refresh_token,
            expires_in,
        } = response;
        let access = CredentialSecret::new(access_token);
        let refresh = CredentialSecret::new(refresh_token);
        let expires_at = checked_expiry(self.inner.clock.now(), expires_in);
        let (access, refresh, expires_at) = match (access, refresh, expires_at) {
            (Ok(access), Ok(refresh), Some(expires_at)) => (access, refresh, expires_at),
            (_, refresh, _) => {
                let refresh = refresh.ok();
                return self
                    .lose_successful_refresh(
                        locks,
                        permit,
                        port,
                        refresh.as_ref(),
                        operation,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        let expires_at_wire = expires_at.to_rfc3339_opts(SecondsFormat::Secs, true);
        let access_copy = match copy_secret(&access) {
            Ok(secret) => secret,
            Err(_) => {
                return self
                    .lose_successful_refresh(
                        locks,
                        permit,
                        port,
                        Some(&refresh),
                        operation,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        let refresh_copy = match copy_secret(&refresh) {
            Ok(secret) => secret,
            Err(_) => {
                return self
                    .lose_successful_refresh(
                        locks,
                        permit,
                        port,
                        Some(&refresh),
                        operation,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let (mut locks, (committed, _permit)) = run_with_locks(locks, move || {
            let mut permit = permit;
            let committed = repository
                .rotate_session_credentials_after_auth_intent_with_operation_locks(
                    &mut permit,
                    access_copy,
                    refresh_copy,
                    expires_at_wire,
                    store.as_ref(),
                );
            (committed, permit)
        })
        .await
        .map_err(|_| SessionError::new(operation, SessionErrorKind::RecoveryRequired))?;
        if let Ok(outcome) = committed {
            cleanup_deferred |= outcome_has_warnings(&outcome);
            let (next_locks, authorized_target_generation) = self
                .generation_from_snapshot(locks, outcome.snapshot().clone(), target, operation)
                .await?;
            locks = next_locks;
            drop(locks);
            return Ok(SessionAccess {
                operation_id: operation.operation_id,
                target: target.clone(),
                endpoint: endpoint.to_string(),
                storage_id: storage_id.map(str::to_string),
                server_fingerprint: server_fingerprint.to_string(),
                account_subject: account_subject.map(str::to_string),
                auth_method,
                personal_vaults_enabled,
                expires_at,
                source: AccessSource::Refreshed,
                completion: operation.completion(),
                cleanup_deferred,
                authorized_target_generation,
                access_secret: access,
            });
        }

        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let (next_locks, reconciled) = run_with_locks(locks, move || {
            repository.reconcile_auth_operation_with_operation_locks(store.as_ref())
        })
        .await
        .map_err(|kind| SessionError::new(operation, kind))?;
        locks = next_locks;
        match reconciled {
            Ok((outcome, AuthOperationRecoveryDisposition::CandidatePreserved)) => {
                cleanup_deferred |= outcome_has_warnings(&outcome);
                let (next_locks, authorized_target_generation) = self
                    .generation_from_snapshot(locks, outcome.snapshot().clone(), target, operation)
                    .await?;
                locks = next_locks;
                drop(locks);
                return Ok(SessionAccess {
                    operation_id: operation.operation_id,
                    target: target.clone(),
                    endpoint: endpoint.to_string(),
                    storage_id: storage_id.map(str::to_string),
                    server_fingerprint: server_fingerprint.to_string(),
                    account_subject: account_subject.map(str::to_string),
                    auth_method,
                    personal_vaults_enabled,
                    expires_at,
                    source: AccessSource::Refreshed,
                    completion: operation.completion(),
                    cleanup_deferred,
                    authorized_target_generation,
                    access_secret: access,
                });
            }
            Ok((
                outcome,
                AuthOperationRecoveryDisposition::SourceRevoked
                | AuthOperationRecoveryDisposition::TargetRemoved,
            )) => {
                cleanup_deferred |= outcome_has_warnings(&outcome);
            }
            Ok((outcome, AuthOperationRecoveryDisposition::NoIntent)) => {
                cleanup_deferred |= outcome_has_warnings(&outcome);
                let (next_locks, revoked) = self
                    .revoke_current_target_without_auth_intent(locks, target, operation)
                    .await?;
                locks = next_locks;
                cleanup_deferred |= revoked;
            }
            Ok((_, AuthOperationRecoveryDisposition::LoginAbandoned)) => {
                drop(locks);
                return Err(SessionError::terminal(
                    operation,
                    SessionErrorKind::RecoveryRequired,
                    None,
                    None,
                    cleanup_deferred,
                    false,
                ));
            }
            Err(error) => {
                drop(locks);
                return Err(SessionError::terminal(
                    operation,
                    config_error_kind(&error, operation),
                    None,
                    None,
                    cleanup_deferred,
                    false,
                ));
            }
        }

        let _ = port.logout(refresh.expose_secret()).await;
        drop(locks);
        Err(SessionError::terminal(
            operation,
            SessionErrorKind::SessionLostRemoteUnknown,
            None,
            None,
            cleanup_deferred,
            true,
        ))
    }

    async fn revoke_current_target_without_auth_intent(
        &self,
        locks: HeldSessionLocks,
        target: &SessionTarget,
        operation: &SessionOperation,
    ) -> Result<(HeldSessionLocks, bool), SessionError> {
        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let connection_id = target.connection_id.clone();
        let profile_name = target.profile_name.clone();
        let (locks, result) = run_with_locks(locks, move || {
            let anchor =
                match repository.resolve_credential_profile_anchor(&connection_id, profile_name) {
                    Ok(anchor) => anchor,
                    Err(
                        ConfigError::MissingConnection { .. }
                        | ConfigError::MissingCredentialProfile { .. },
                    ) => return Ok(None),
                    Err(error) => return Err(error),
                };
            repository
                .remove_credential_profile_if_matches_with_operation_lock(
                    &anchor,
                    ActiveCredentialAfterRemoval::Clear,
                    store.as_ref(),
                )
                .map(Some)
        })
        .await
        .map_err(|_| SessionError::new(operation, SessionErrorKind::RecoveryRequired))?;
        match result {
            Ok(Some(outcome)) => Ok((locks, outcome_has_warnings(&outcome))),
            Ok(None) => Ok((locks, false)),
            Err(error) => {
                drop(locks);
                Err(SessionError::terminal(
                    operation,
                    config_error_kind(&error, operation),
                    None,
                    None,
                    false,
                    false,
                ))
            }
        }
    }

    async fn lose_successful_refresh(
        &self,
        locks: HeldSessionLocks,
        permit: AuthOperationIntentPermit,
        port: Arc<dyn AuthPort>,
        new_refresh: Option<&CredentialSecret>,
        operation: &SessionOperation,
        mut cleanup_deferred: bool,
    ) -> Result<SessionAccess, SessionError> {
        if let Some(refresh) = new_refresh {
            let _ = port.logout(refresh.expose_secret()).await;
        }
        match self.terminal_revoke(locks, permit, operation).await {
            Ok(warnings) => {
                cleanup_deferred |= warnings;
                Err(SessionError::terminal(
                    operation,
                    SessionErrorKind::SessionLostRemoteUnknown,
                    None,
                    None,
                    cleanup_deferred,
                    true,
                ))
            }
            Err(error) => Err(error),
        }
    }

    async fn terminal_revoke(
        &self,
        locks: HeldSessionLocks,
        permit: AuthOperationIntentPermit,
        operation: &SessionOperation,
    ) -> Result<bool, SessionError> {
        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let (mut locks, result) = run_with_locks(locks, move || {
            repository.remove_credential_profile_after_auth_intent_with_operation_locks(
                &permit,
                ActiveCredentialAfterRemoval::Clear,
                store.as_ref(),
            )
        })
        .await
        .map_err(|_| SessionError::new(operation, SessionErrorKind::RecoveryRequired))?;
        match result {
            Ok(outcome) => {
                let warnings = outcome_has_warnings(&outcome);
                drop(locks);
                Ok(warnings)
            }
            Err(
                ConfigError::MissingConnection { .. }
                | ConfigError::MissingCredentialProfile { .. },
            ) => {
                let repository = self.inner.repository.clone();
                let store = self.inner.credential_store.clone();
                let (next_locks, recovered) = run_with_locks(locks, move || {
                    repository.reconcile_auth_operation_with_operation_locks(store.as_ref())
                })
                .await
                .map_err(|_| SessionError::new(operation, SessionErrorKind::RecoveryRequired))?;
                locks = next_locks;
                match recovered {
                    Ok((outcome, AuthOperationRecoveryDisposition::TargetRemoved)) => {
                        let warnings = outcome_has_warnings(&outcome);
                        drop(locks);
                        Ok(warnings)
                    }
                    Ok(_) | Err(_) => {
                        drop(locks);
                        Err(SessionError::terminal(
                            operation,
                            SessionErrorKind::RecoveryRequired,
                            None,
                            None,
                            false,
                            false,
                        ))
                    }
                }
            }
            Err(error) => {
                drop(locks);
                Err(SessionError::terminal(
                    operation,
                    if matches!(&error, ConfigError::Busy { .. }) {
                        SessionErrorKind::RecoveryRequired
                    } else {
                        config_error_kind(&error, operation)
                    },
                    None,
                    None,
                    false,
                    false,
                ))
            }
        }
    }
}

struct PasswordLoginAccess {
    storage_id: Option<String>,
    account_subject: String,
    expires_at: DateTime<Utc>,
    access_secret: CredentialSecret,
    cleanup_deferred: bool,
    authorized_target_generation: Arc<AuthorizedTargetGeneration>,
}

fn password_login_identity_from_prelogin(
    prelogin: PreloginResponse,
    email: Option<String>,
) -> Result<ConfigIdentity, SessionErrorKind> {
    prelogin
        .kdf_params
        .validate_policy()
        .map_err(|_| SessionErrorKind::Protocol)?;
    let decoded_salt = base64::engine::general_purpose::STANDARD
        .decode(&prelogin.kdf_salt)
        .map_err(|_| SessionErrorKind::Protocol)?;
    if decoded_salt.is_empty() {
        return Err(SessionErrorKind::Protocol);
    }
    let expected_fingerprint = zann_core::passwords::kdf_fingerprint(
        &prelogin.kdf_salt,
        &prelogin.kdf_params.to_crypto_params(),
    )
    .map_err(|_| SessionErrorKind::Protocol)?;
    if expected_fingerprint != prelogin.salt_fingerprint {
        return Err(SessionErrorKind::Protocol);
    }
    Ok(ConfigIdentity {
        kdf_salt: prelogin.kdf_salt,
        kdf_params: prelogin.kdf_params.into(),
        salt_fingerprint: Some(prelogin.salt_fingerprint),
        first_seen_at: None,
        email,
    })
}

fn password_login_kdf_is_coherent(
    pre_dispatch: &ConfigIdentity,
    authenticated: &ConfigIdentity,
) -> bool {
    pre_dispatch.kdf_salt == authenticated.kdf_salt
        && pre_dispatch.kdf_params == authenticated.kdf_params
        && pre_dispatch.salt_fingerprint == authenticated.salt_fingerprint
}

fn password_login_access(
    target: &SessionTarget,
    verified: &EndpointIdentity,
    operation: &SessionOperation,
    result: PasswordLoginAccess,
) -> SessionAccess {
    SessionAccess {
        operation_id: operation.operation_id,
        target: target.clone(),
        endpoint: verified.address().to_string(),
        storage_id: result.storage_id,
        server_fingerprint: verified.server_fingerprint().to_string(),
        account_subject: Some(result.account_subject),
        auth_method: Some(AuthMethod::Password),
        personal_vaults_enabled: verified.personal_vaults_enabled,
        expires_at: result.expires_at,
        source: AccessSource::PasswordLogin,
        completion: operation.completion(),
        cleanup_deferred: result.cleanup_deferred,
        authorized_target_generation: result.authorized_target_generation,
        access_secret: result.access_secret,
    }
}

fn access_decision(anchor: &CredentialProfileAnchor, now: DateTime<Utc>) -> AccessDecision {
    let has_access = anchor.credentials().contains_key(&CredentialKind::Access);
    let expires_at = anchor.access_expires_at().and_then(parse_rfc3339);
    if let Some(expires_at) = expires_at.filter(|expires_at| {
        has_access
            && now
                .checked_add_signed(REFRESH_SKEW)
                .is_some_and(|threshold| threshold < *expires_at)
    }) {
        return AccessDecision::Stored(expires_at);
    }
    AccessDecision::Refresh
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn checked_expiry(now: DateTime<Utc>, expires_in: u64) -> Option<DateTime<Utc>> {
    let seconds = i64::try_from(expires_in).ok()?;
    if seconds <= 0 {
        return None;
    }
    now.checked_add_signed(ChronoDuration::seconds(seconds))
}

fn copy_secret(secret: &CredentialSecret) -> Result<CredentialSecret, SessionErrorKind> {
    CredentialSecret::new(secret.expose_secret().to_string())
        .map_err(|_| SessionErrorKind::Internal)
}

fn credential_read_error_kind(error: ReadCredentialError) -> SessionErrorKind {
    match error {
        ReadCredentialError::MissingSlot | ReadCredentialError::MissingPhysical => {
            SessionErrorKind::MissingCredential
        }
        ReadCredentialError::Port(CredentialPortErrorKind::Cancelled) => {
            SessionErrorKind::CredentialCancelled
        }
        ReadCredentialError::Port(CredentialPortErrorKind::Unsupported) => {
            SessionErrorKind::CredentialUnsupported
        }
        ReadCredentialError::Port(_) => SessionErrorKind::CredentialUnavailable,
    }
}

fn outcome_has_warnings(outcome: &CredentialTransactionOutcome) -> bool {
    !outcome.warnings().is_empty()
}

fn request_timeout(operation: &SessionOperation) -> Option<Duration> {
    let remaining = operation.deadline.checked_duration_since(Instant::now())?;
    let timeout = remaining.min(REQUEST_TIMEOUT);
    (!timeout.is_zero()).then_some(timeout)
}

fn config_error_kind(error: &ConfigError, operation: &SessionOperation) -> SessionErrorKind {
    match error {
        ConfigError::Busy { .. } if Instant::now() >= operation.deadline => {
            SessionErrorKind::DeadlineExceeded
        }
        ConfigError::Busy { .. } => SessionErrorKind::Busy,
        ConfigError::MissingConnection { .. } | ConfigError::MissingCredentialProfile { .. } => {
            SessionErrorKind::SessionNotFound
        }
        ConfigError::CredentialProfileAnchorConflict { .. }
        | ConfigError::CredentialProfileAnchorRepositoryMismatch => {
            SessionErrorKind::ConcurrentSessionChange
        }
        ConfigError::ConfigTooLarge { path, .. }
            if path.file_name().and_then(|name| name.to_str())
                == Some(crate::config::v2::AUTH_OPERATION_INTENT_FILENAME) =>
        {
            SessionErrorKind::RecoveryRequired
        }
        ConfigError::CredentialRecoveryRequired { .. }
        | ConfigError::CredentialTransactionJournalConflict { .. }
        | ConfigError::RecoveryRequired { .. }
        | ConfigError::RestoreJournalConflict { .. }
        | ConfigError::MissingAuthOperationIntentVersion { .. }
        | ConfigError::FutureAuthOperationIntent { .. }
        | ConfigError::UnsupportedAuthOperationIntent { .. }
        | ConfigError::MalformedAuthOperationIntent { .. }
        | ConfigError::AuthOperationRecoveryRequired { .. }
        | ConfigError::AuthOperationIntentConflict { .. }
        | ConfigError::AuthOperationIntentRepositoryMismatch => SessionErrorKind::RecoveryRequired,
        ConfigError::CredentialStore { source, .. }
        | ConfigError::CredentialValidation { source, .. } => match source.kind() {
            CredentialPortErrorKind::Cancelled => SessionErrorKind::CredentialCancelled,
            CredentialPortErrorKind::Unsupported => SessionErrorKind::CredentialUnsupported,
            _ => SessionErrorKind::CredentialUnavailable,
        },
        _ => SessionErrorKind::Configuration,
    }
}

async fn acquire_session_locks(
    root: PathBuf,
    operation: &SessionOperation,
) -> Result<HeldSessionLocks, SessionError> {
    let auth = acquire_lock(root.clone(), LockKind::AuthOperation, operation).await?;
    let credential = match acquire_lock(root, LockKind::CredentialOperation, operation).await {
        Ok(guard) => guard,
        Err(error) => {
            drop(auth);
            return Err(error);
        }
    };
    Ok(HeldSessionLocks {
        _credential: credential,
        _auth: auth,
    })
}

async fn acquire_lock(
    root: PathBuf,
    kind: LockKind,
    operation: &SessionOperation,
) -> Result<FileLockGuard, SessionError> {
    if let Some(kind) = operation.pre_dispatch_error() {
        return Err(SessionError::new(operation, kind));
    }
    let pending = run_blocking(move || kind.pending_at(&root))
        .await
        .map_err(|kind| SessionError::new(operation, kind))?
        .map_err(|error| SessionError::new(operation, config_error_kind(&error, operation)))?;
    let mut pending = pending;
    loop {
        if let Some(kind) = operation.pre_dispatch_error() {
            return Err(SessionError::new(operation, kind));
        }
        let attempt = run_blocking(move || pending.try_acquire())
            .await
            .map_err(|kind| SessionError::new(operation, kind))?
            .map_err(|error| SessionError::new(operation, config_error_kind(&error, operation)))?;
        match attempt {
            LockAttempt::Acquired(guard) => return Ok(guard),
            LockAttempt::WouldBlock(next) => pending = next,
        }
        let Some(remaining) = operation.deadline.checked_duration_since(Instant::now()) else {
            return Err(SessionError::new(
                operation,
                SessionErrorKind::DeadlineExceeded,
            ));
        };
        let wait = remaining.min(LOCK_RETRY_DELAY);
        tokio::select! {
            biased;
            _ = operation.cancelled() => {
                return Err(SessionError::new(operation, SessionErrorKind::Cancelled));
            }
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

async fn run_blocking<T, F>(function: F) -> Result<T, SessionErrorKind>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(function)
        .await
        .map_err(|_| SessionErrorKind::Internal)
}

async fn run_with_locks<T, F>(
    locks: HeldSessionLocks,
    function: F,
) -> Result<(HeldSessionLocks, T), SessionErrorKind>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    run_blocking(move || {
        let result = function();
        (locks, result)
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::{Condvar, Mutex};

    use tempfile::TempDir;
    use tokio::sync::{Barrier, Notify};

    use super::*;
    use crate::config::{
        ClientId, ConnectionMetadata, CredentialActivation, CredentialBundle, CredentialId,
        CredentialPortError, LegacyCredentialLocator, LegacyCredentialSource,
    };

    const ADDRESS: &str = "https://session.test";
    const SERVER_ID: &str = "server-a";
    const FINGERPRINT: &str = "pin-a";
    const PROFILE: &str = "default";

    #[derive(Default)]
    struct MemoryStore {
        values: Mutex<BTreeMap<String, String>>,
        gets: AtomicUsize,
        puts: AtomicUsize,
        deletes: AtomicUsize,
        fail_put: AtomicBool,
        probe_repository: Mutex<Option<ConfigRepository>>,
        probe_succeeded: AtomicBool,
        block_next_get: Mutex<Option<GetBlock>>,
    }

    type GetBlock = (Arc<Notify>, Arc<(Mutex<bool>, Condvar)>);

    impl MemoryStore {
        fn calls(&self) -> (usize, usize, usize) {
            (
                self.gets.load(Ordering::SeqCst),
                self.puts.load(Ordering::SeqCst),
                self.deletes.load(Ordering::SeqCst),
            )
        }

        fn get_count(&self) -> usize {
            self.gets.load(Ordering::SeqCst)
        }

        fn value(&self, id: &CredentialId) -> Option<String> {
            self.values
                .lock()
                .expect("credential values lock")
                .get(&id.to_string())
                .cloned()
        }

        fn remove_physical(&self, id: &CredentialId) {
            self.values
                .lock()
                .expect("credential values lock")
                .remove(&id.to_string());
        }

        fn fail_future_puts(&self) {
            self.fail_put.store(true, Ordering::SeqCst);
        }

        fn probe_config_lock_on_get(&self, repository: ConfigRepository) {
            *self.probe_repository.lock().expect("probe repository lock") = Some(repository);
        }

        fn block_next_get(&self) -> GetBlock {
            let block = (
                Arc::new(Notify::new()),
                Arc::new((Mutex::new(false), Condvar::new())),
            );
            *self.block_next_get.lock().expect("get block lock") = Some(block.clone());
            block
        }
    }

    impl CredentialStore for MemoryStore {
        fn put(
            &self,
            credential_id: &CredentialId,
            secret: &CredentialSecret,
        ) -> Result<(), CredentialPortError> {
            self.puts.fetch_add(1, Ordering::SeqCst);
            if self.fail_put.load(Ordering::SeqCst) {
                return Err(CredentialPortError::new("injected credential put failure"));
            }
            self.values.lock().expect("credential values lock").insert(
                credential_id.to_string(),
                secret.expose_secret().to_string(),
            );
            Ok(())
        }

        fn get(
            &self,
            credential_id: &CredentialId,
        ) -> Result<Option<CredentialSecret>, CredentialPortError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            let block = self.block_next_get.lock().expect("get block lock").take();
            if let Some((started, release)) = block {
                started.notify_waiters();
                let (released, condition) = &*release;
                let mut released = released.lock().expect("get release lock");
                while !*released {
                    released = condition.wait(released).expect("get release wait");
                }
            }
            let probe = self
                .probe_repository
                .lock()
                .expect("probe repository lock")
                .clone();
            if let Some(repository) = probe {
                let acquired = LockKind::Config
                    .pending_at(repository.paths().root())
                    .and_then(|pending| pending.acquire_blocking(Duration::from_millis(100)))
                    .is_ok();
                self.probe_succeeded.store(acquired, Ordering::SeqCst);
            }
            self.value(credential_id)
                .map(CredentialSecret::new)
                .transpose()
                .map_err(|error| CredentialPortError::new(error.to_string()))
        }

        fn delete(&self, credential_id: &CredentialId) -> Result<(), CredentialPortError> {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            self.values
                .lock()
                .expect("credential values lock")
                .remove(&credential_id.to_string());
            Ok(())
        }
    }

    struct EmptyLegacyCredentials;

    impl LegacyCredentialSource for EmptyLegacyCredentials {
        fn get(
            &self,
            _locator: &LegacyCredentialLocator,
        ) -> Result<Option<CredentialSecret>, CredentialPortError> {
            Ok(None)
        }
    }

    struct FixedClock(DateTime<Utc>);

    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    #[derive(Clone)]
    enum RefreshBehavior {
        Success {
            access: String,
            refresh: String,
            expires_in: u64,
        },
        Failure(AuthFailure),
        BlockedSuccess {
            started: Arc<Barrier>,
            release: Arc<Notify>,
            access: String,
            refresh: String,
            expires_in: u64,
        },
    }

    #[derive(Clone)]
    enum MeBehavior {
        Success(Identity),
        Failure(AuthFailure),
        BlockedSuccess {
            started: Arc<Barrier>,
            release: Arc<Notify>,
            identity: Identity,
        },
    }

    struct FakeAuthPort {
        identity: Mutex<Result<EndpointIdentity, AuthFailure>>,
        refresh_behavior: Mutex<RefreshBehavior>,
        prelogin: Mutex<VecDeque<Result<PreloginResponse, AuthFailure>>>,
        login_behavior: Mutex<RefreshBehavior>,
        me_behavior: Mutex<MeBehavior>,
        probe_calls: AtomicUsize,
        prelogin_calls: AtomicUsize,
        login_calls: AtomicUsize,
        me_calls: AtomicUsize,
        refresh_calls: AtomicUsize,
        logout_calls: AtomicUsize,
        logout_fails: AtomicBool,
    }

    impl FakeAuthPort {
        fn new(identity: EndpointIdentity, refresh_behavior: RefreshBehavior) -> Arc<Self> {
            let me_identity = Identity {
                user_id: Uuid::parse_str("018f4f08-7f1d-7d57-bd43-bb4b7c520001")
                    .expect("test user id"),
                email: "person@example.test".to_string(),
                display_name: "Person".to_string(),
                avatar_url: None,
                avatar_initials: "P".to_string(),
                groups: Vec::new(),
                source: AuthSource::Internal,
                device_id: None,
                service_account_id: None,
            };
            Arc::new(Self {
                identity: Mutex::new(Ok(identity)),
                refresh_behavior: Mutex::new(refresh_behavior),
                prelogin: Mutex::new(VecDeque::from([Ok(valid_prelogin_response())])),
                login_behavior: Mutex::new(success_behavior()),
                me_behavior: Mutex::new(MeBehavior::Success(me_identity)),
                probe_calls: AtomicUsize::new(0),
                prelogin_calls: AtomicUsize::new(0),
                login_calls: AtomicUsize::new(0),
                me_calls: AtomicUsize::new(0),
                refresh_calls: AtomicUsize::new(0),
                logout_calls: AtomicUsize::new(0),
                logout_fails: AtomicBool::new(false),
            })
        }

        fn refresh_calls(&self) -> usize {
            self.refresh_calls.load(Ordering::SeqCst)
        }

        fn logout_calls(&self) -> usize {
            self.logout_calls.load(Ordering::SeqCst)
        }

        fn login_calls(&self) -> usize {
            self.login_calls.load(Ordering::SeqCst)
        }

        fn me_calls(&self) -> usize {
            self.me_calls.load(Ordering::SeqCst)
        }

        fn set_login_behavior(&self, behavior: RefreshBehavior) {
            *self.login_behavior.lock().expect("login behavior lock") = behavior;
        }

        fn set_me_behavior(&self, behavior: MeBehavior) {
            *self.me_behavior.lock().expect("me behavior lock") = behavior;
        }

        fn set_prelogin_results(&self, results: Vec<Result<PreloginResponse, AuthFailure>>) {
            *self.prelogin.lock().expect("prelogin lock") = results.into();
        }
    }

    impl AuthPort for FakeAuthPort {
        fn verified_endpoint(&self) -> AuthFuture<'_, EndpointIdentity> {
            self.probe_calls.fetch_add(1, Ordering::SeqCst);
            let result = self.identity.lock().expect("identity lock").clone();
            Box::pin(async move { result })
        }

        fn prelogin<'a>(&'a self, _email: &'a str) -> AuthFuture<'a, PreloginResponse> {
            self.prelogin_calls.fetch_add(1, Ordering::SeqCst);
            let mut results = self.prelogin.lock().expect("prelogin lock");
            let result = if results.len() > 1 {
                results.pop_front().expect("nonempty prelogin results")
            } else {
                results.front().expect("prelogin result configured").clone()
            };
            Box::pin(async move { result })
        }

        fn password_login<'a>(
            &'a self,
            _email: &'a str,
            _password: &'a LoginPassword,
            _client: &'a SessionClient,
        ) -> AuthFuture<'a, LoginResponse> {
            self.login_calls.fetch_add(1, Ordering::SeqCst);
            let behavior = self
                .login_behavior
                .lock()
                .expect("login behavior lock")
                .clone();
            Box::pin(async move {
                match behavior {
                    RefreshBehavior::Success {
                        access,
                        refresh,
                        expires_in,
                    } => Ok(LoginResponse {
                        access_token: access,
                        refresh_token: refresh,
                        expires_in,
                    }),
                    RefreshBehavior::Failure(failure) => Err(failure),
                    RefreshBehavior::BlockedSuccess {
                        started,
                        release,
                        access,
                        refresh,
                        expires_in,
                    } => {
                        started.wait().await;
                        release.notified().await;
                        Ok(LoginResponse {
                            access_token: access,
                            refresh_token: refresh,
                            expires_in,
                        })
                    }
                }
            })
        }

        fn me<'a>(&'a self, _access_token: &'a str) -> AuthFuture<'a, Identity> {
            self.me_calls.fetch_add(1, Ordering::SeqCst);
            let behavior = self.me_behavior.lock().expect("me behavior lock").clone();
            Box::pin(async move {
                match behavior {
                    MeBehavior::Success(identity) => Ok(identity),
                    MeBehavior::Failure(failure) => Err(failure),
                    MeBehavior::BlockedSuccess {
                        started,
                        release,
                        identity,
                    } => {
                        started.wait().await;
                        release.notified().await;
                        Ok(identity)
                    }
                }
            })
        }

        fn refresh<'a>(&'a self, _refresh_token: &'a str) -> AuthFuture<'a, LoginResponse> {
            self.refresh_calls.fetch_add(1, Ordering::SeqCst);
            let behavior = self
                .refresh_behavior
                .lock()
                .expect("refresh behavior lock")
                .clone();
            Box::pin(async move {
                match behavior {
                    RefreshBehavior::Success {
                        access,
                        refresh,
                        expires_in,
                    } => Ok(LoginResponse {
                        access_token: access,
                        refresh_token: refresh,
                        expires_in,
                    }),
                    RefreshBehavior::Failure(failure) => Err(failure),
                    RefreshBehavior::BlockedSuccess {
                        started,
                        release,
                        access,
                        refresh,
                        expires_in,
                    } => {
                        started.wait().await;
                        release.notified().await;
                        Ok(LoginResponse {
                            access_token: access,
                            refresh_token: refresh,
                            expires_in,
                        })
                    }
                }
            })
        }

        fn logout<'a>(&'a self, _refresh_token: &'a str) -> AuthFuture<'a, ()> {
            self.logout_calls.fetch_add(1, Ordering::SeqCst);
            let fails = self.logout_fails.load(Ordering::SeqCst);
            Box::pin(async move {
                if fails {
                    Err(AuthFailure {
                        kind: AuthFailureKind::Unavailable,
                        status: None,
                        server_code: None,
                    })
                } else {
                    Ok(())
                }
            })
        }
    }

    struct FakeAuthFactory {
        port: Arc<FakeAuthPort>,
        connects: AtomicUsize,
    }

    impl FakeAuthFactory {
        fn new(port: Arc<FakeAuthPort>) -> Arc<Self> {
            Arc::new(Self {
                port,
                connects: AtomicUsize::new(0),
            })
        }
    }

    impl AuthFactory for FakeAuthFactory {
        fn connect(
            &self,
            _endpoint: &str,
            _timeout: Duration,
        ) -> Result<Arc<dyn AuthPort>, AuthFailure> {
            self.connects.fetch_add(1, Ordering::SeqCst);
            Ok(self.port.clone())
        }
    }

    struct Harness {
        _temp: TempDir,
        paths: ClientPaths,
        repository: ConfigRepository,
        store: Arc<MemoryStore>,
        target: SessionTarget,
        now: DateTime<Utc>,
    }

    impl Harness {
        fn new(
            address: &str,
            expires_at: DateTime<Utc>,
            refresh: Option<&str>,
            service: Option<&str>,
        ) -> Self {
            Self::new_with_binding(address, expires_at, refresh, service, true)
        }

        fn new_with_binding(
            address: &str,
            expires_at: DateTime<Utc>,
            refresh: Option<&str>,
            service: Option<&str>,
            pinned: bool,
        ) -> Self {
            let temp = TempDir::new().expect("session tempdir");
            let paths = ClientPaths::new(temp.path());
            let repository = ConfigRepository::new(paths.clone());
            let store = Arc::new(MemoryStore::default());
            repository
                .initialize(
                    &ClientId::new("test").expect("client id"),
                    store.as_ref(),
                    &EmptyLegacyCredentials,
                )
                .expect("initialize config");
            let connection_id = ConnectionId::deterministic("session", address);
            let mut metadata = ConnectionMetadata::new("session", address);
            if pinned {
                metadata.server_id = Some(SERVER_ID.to_string());
                metadata.server_fingerprint = Some(FINGERPRINT.to_string());
            }
            let snapshot = repository
                .upsert_connection(connection_id.clone(), metadata)
                .expect("insert connection");
            let bundle = CredentialBundle::new(
                Some(secret("old-access")),
                refresh.map(secret),
                service.map(secret),
            )
            .with_access_expires_at(Some(expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)));
            repository
                .replace_credential_bundle(
                    snapshot.revision(),
                    &connection_id,
                    PROFILE,
                    bundle,
                    CredentialActivation::MakeActive,
                    store.as_ref(),
                )
                .expect("store credentials");
            let target = SessionTarget::new(connection_id, PROFILE).expect("session target");
            let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
                .expect("fixed time")
                .with_timezone(&Utc);
            Self {
                _temp: temp,
                paths,
                repository,
                store,
                target,
                now,
            }
        }

        fn identity(&self) -> EndpointIdentity {
            let anchor = self
                .repository
                .resolve_credential_profile_anchor(
                    self.target.connection_id(),
                    self.target.profile_name(),
                )
                .expect("profile anchor");
            EndpointIdentity::for_test(
                anchor.address(),
                anchor.server_id().expect("server id"),
                anchor.server_fingerprint().expect("server fingerprint"),
                true,
                true,
            )
        }

        fn app(&self, port: Arc<FakeAuthPort>) -> AppSession {
            AppSession::with_components(
                self.paths.clone(),
                self.store.clone(),
                FakeAuthFactory::new(port),
                Arc::new(FixedClock(self.now)),
            )
        }

        fn login_app(&self, port: Arc<FakeAuthPort>) -> AppSession {
            AppSession::with_components_and_client(
                self.paths.clone(),
                self.store.clone(),
                FakeAuthFactory::new(port),
                Arc::new(FixedClock(self.now)),
                Some(SessionClient::new(
                    ClientId::new("test").expect("client id"),
                )),
            )
        }

        fn operation(&self) -> SessionOperation {
            SessionOperation::new(Instant::now() + Duration::from_secs(3)).0
        }
    }

    fn secret(value: &str) -> CredentialSecret {
        CredentialSecret::new(value).expect("credential secret")
    }

    fn success_behavior() -> RefreshBehavior {
        RefreshBehavior::Success {
            access: "new-access".to_string(),
            refresh: "new-refresh".to_string(),
            expires_in: 3_600,
        }
    }

    fn valid_prelogin_response() -> PreloginResponse {
        let kdf_salt = base64::engine::general_purpose::STANDARD.encode([7_u8; 32]);
        let kdf_params = zann_core::api::auth::KdfParams {
            algorithm: "argon2id".to_string(),
            iterations: 3,
            memory_kb: 64 * 1024,
            parallelism: 1,
        };
        let salt_fingerprint =
            zann_core::passwords::kdf_fingerprint(&kdf_salt, &kdf_params.to_crypto_params())
                .expect("valid test KDF fingerprint");
        PreloginResponse {
            kdf_salt,
            kdf_params,
            salt_fingerprint,
        }
    }

    fn failure(kind: AuthFailureKind) -> AuthFailure {
        AuthFailure {
            kind,
            status: None,
            server_code: None,
        }
    }

    #[tokio::test]
    async fn stored_access_verifies_trust_before_reading_secret() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        harness
            .store
            .probe_config_lock_on_get(harness.repository.clone());
        let source_anchor = harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .expect("stored source anchor");
        let reads = harness.store.get_count();
        let access = harness
            .app(port.clone())
            .access(&harness.target, harness.operation())
            .await
            .expect("stored access");

        assert_eq!(access.source(), AccessSource::Stored);
        assert_eq!(access.bearer(), "old-access");
        assert!(access.personal_vaults_enabled());
        assert!(!format!("{access:?}").contains("old-access"));
        let generation = access.authorized_target_generation();
        assert_eq!(generation.revision(), source_anchor.source_revision());
        assert_eq!(generation.connection_id(), harness.target.connection_id());
        assert_eq!(generation.profile_name(), harness.target.profile_name());
        let rendered = format!("{generation:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(ADDRESS));
        drop(
            harness
                .repository
                .acquire_sync_commit_lease(&generation)
                .await
                .expect("stored generation remains exact"),
        );
        assert_eq!(harness.store.get_count(), reads + 1);
        assert_eq!(port.probe_calls.load(Ordering::SeqCst), 1);
        assert_eq!(port.refresh_calls(), 0);
        assert!(harness.store.probe_succeeded.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn trust_mismatch_reads_no_secret_and_sends_no_sensitive_request() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let mismatched = EndpointIdentity::for_test(ADDRESS, SERVER_ID, "pin-b", true, true);
        let port = FakeAuthPort::new(mismatched, success_behavior());
        let reads = harness.store.get_count();
        let error = harness
            .app(port.clone())
            .access(&harness.target, harness.operation())
            .await
            .expect_err("mismatched trust");

        assert_eq!(error.kind(), SessionErrorKind::TrustMismatch);
        assert_eq!(harness.store.get_count(), reads);
        assert_eq!(port.refresh_calls(), 0);
        assert_eq!(port.logout_calls(), 0);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("old-access"));
        assert!(!rendered.contains(ADDRESS));
        assert!(!rendered.contains(PROFILE));
    }

    #[tokio::test]
    async fn unpinned_endpoint_reads_no_secret_and_sends_no_request() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new_with_binding(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
            false,
        );
        let port = FakeAuthPort::new(
            EndpointIdentity::for_test(ADDRESS, SERVER_ID, FINGERPRINT, true, true),
            success_behavior(),
        );
        let factory = FakeAuthFactory::new(port.clone());
        let reads = harness.store.get_count();
        let app = AppSession::with_components(
            harness.paths.clone(),
            harness.store.clone(),
            factory.clone(),
            Arc::new(FixedClock(harness.now)),
        );
        let error = app
            .access(&harness.target, harness.operation())
            .await
            .expect_err("unpinned endpoint");

        assert_eq!(error.kind(), SessionErrorKind::TrustRequired);
        assert_eq!(harness.store.get_count(), reads);
        assert_eq!(factory.connects.load(Ordering::SeqCst), 0);
        assert_eq!(port.probe_calls.load(Ordering::SeqCst), 0);
        assert_eq!(port.refresh_calls(), 0);
    }

    #[tokio::test]
    async fn insecure_endpoint_reads_no_secret() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            "http://session.test",
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let reads = harness.store.get_count();
        let error = AppSession::new(harness.paths.clone(), harness.store.clone())
            .access(&harness.target, harness.operation())
            .await
            .expect_err("non-loopback plaintext endpoint");

        assert_eq!(error.kind(), SessionErrorKind::InsecureTransport);
        assert_eq!(harness.store.get_count(), reads);
    }

    #[tokio::test]
    async fn missing_physical_refresh_never_sends_the_secret_request() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now - ChronoDuration::minutes(1),
            Some("old-refresh"),
            None,
        );
        let anchor = harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .expect("profile anchor");
        harness
            .store
            .remove_physical(&anchor.credentials()[&CredentialKind::Refresh]);
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        let error = harness
            .app(port.clone())
            .access(&harness.target, harness.operation())
            .await
            .expect_err("missing physical refresh");

        assert_eq!(error.kind(), SessionErrorKind::MissingCredential);
        assert_eq!(port.probe_calls.load(Ordering::SeqCst), 1);
        assert_eq!(port.refresh_calls(), 0);
    }

    #[tokio::test]
    async fn refreshes_once_and_preserves_service_slot() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now - ChronoDuration::minutes(1),
            Some("old-refresh"),
            Some("service-secret"),
        );
        let before = harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .expect("old anchor");
        let before_generation = harness
            .repository
            .authorized_target_generation_from_anchor(&before)
            .expect("old authorized generation");
        let service_id = before.credentials()[&CredentialKind::ServiceAccount].clone();
        let port = FakeAuthPort::new(harness.identity(), success_behavior());

        let access = harness
            .app(port.clone())
            .access(&harness.target, harness.operation())
            .await
            .expect("refreshed access");
        let after = harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .expect("new anchor");

        assert_eq!(access.source(), AccessSource::Refreshed);
        assert_eq!(access.bearer(), "new-access");
        let refreshed_generation = access.authorized_target_generation();
        assert_eq!(refreshed_generation.revision(), after.source_revision());
        assert_eq!(
            refreshed_generation.stable_target_fingerprint(),
            before_generation.stable_target_fingerprint()
        );
        assert_ne!(
            refreshed_generation.anchor_fingerprint(),
            before_generation.anchor_fingerprint()
        );
        drop(
            harness
                .repository
                .acquire_sync_commit_lease(&refreshed_generation)
                .await
                .expect("refresh candidate generation remains exact"),
        );
        assert_eq!(port.refresh_calls(), 1);
        assert_eq!(
            after.credentials()[&CredentialKind::ServiceAccount],
            service_id
        );
        assert_eq!(
            harness.store.value(&service_id).as_deref(),
            Some("service-secret")
        );
        assert_eq!(
            harness
                .store
                .value(&after.credentials()[&CredentialKind::Refresh])
                .as_deref(),
            Some("new-refresh")
        );
    }

    #[tokio::test]
    async fn local_rotation_failure_logs_out_new_refresh_and_revokes_old_profile() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now - ChronoDuration::minutes(1),
            Some("old-refresh"),
            None,
        );
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        harness.store.fail_future_puts();
        let error = harness
            .app(port.clone())
            .access(&harness.target, harness.operation())
            .await
            .expect_err("injected local rotation failure");

        assert_eq!(error.kind(), SessionErrorKind::SessionLostRemoteUnknown);
        assert!(error.local_revoke_confirmed());
        assert_eq!(port.refresh_calls(), 1);
        assert_eq!(port.logout_calls(), 1);
        assert!(harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .is_err());
    }

    #[tokio::test]
    async fn terminal_refresh_failures_revoke_without_retry() {
        for (failure_kind, expected_kind) in [
            (
                AuthFailureKind::SessionExpired,
                SessionErrorKind::SessionExpired,
            ),
            (
                AuthFailureKind::AmbiguousOutcome,
                SessionErrorKind::SessionLostRemoteUnknown,
            ),
        ] {
            let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
                .expect("fixed time")
                .with_timezone(&Utc);
            let harness = Harness::new(
                ADDRESS,
                now - ChronoDuration::minutes(1),
                Some("old-refresh"),
                None,
            );
            let port = FakeAuthPort::new(
                harness.identity(),
                RefreshBehavior::Failure(failure(failure_kind)),
            );
            let error = harness
                .app(port.clone())
                .access(&harness.target, harness.operation())
                .await
                .expect_err("terminal refresh failure");

            assert_eq!(error.kind(), expected_kind);
            assert!(error.local_revoke_confirmed());
            assert_eq!(port.refresh_calls(), 1);
            assert!(harness
                .repository
                .resolve_credential_profile_anchor(
                    harness.target.connection_id(),
                    harness.target.profile_name(),
                )
                .is_err());
        }
    }

    #[tokio::test]
    async fn terminal_revoke_preserves_a_newer_active_profile() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now - ChronoDuration::minutes(1),
            Some("old-refresh"),
            None,
        );
        let snapshot = harness.repository.snapshot().expect("snapshot");
        harness
            .repository
            .replace_credential_bundle(
                snapshot.revision(),
                harness.target.connection_id(),
                "other",
                CredentialBundle::new(Some(secret("other-access")), None, None)
                    .with_access_expires_at(Some(
                        (now + ChronoDuration::hours(1)).to_rfc3339_opts(SecondsFormat::Secs, true),
                    )),
                CredentialActivation::MakeActive,
                harness.store.as_ref(),
            )
            .expect("add newer active profile");
        let port = FakeAuthPort::new(
            harness.identity(),
            RefreshBehavior::Failure(failure(AuthFailureKind::SessionExpired)),
        );
        let error = harness
            .app(port)
            .access(&harness.target, harness.operation())
            .await
            .expect_err("expired target profile");

        assert_eq!(error.kind(), SessionErrorKind::SessionExpired);
        let snapshot = harness
            .repository
            .snapshot()
            .expect("snapshot after revoke");
        let connection = &snapshot.config().connections[harness.target.connection_id()];
        assert_eq!(connection.active_credential(), Some("other"));
        assert!(!connection.credential_profiles().contains_key(PROFILE));
        assert!(connection.credential_profiles().contains_key("other"));
    }

    #[tokio::test]
    async fn cancellation_before_dispatch_has_no_sensitive_effect() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now - ChronoDuration::minutes(1),
            Some("old-refresh"),
            None,
        );
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        let app = harness.app(port.clone());
        let (operation, cancellation) =
            SessionOperation::new(Instant::now() + Duration::from_secs(3));
        cancellation.cancel();
        let error = app
            .access(&harness.target, operation)
            .await
            .expect_err("pre-dispatch cancellation");

        assert_eq!(error.kind(), SessionErrorKind::Cancelled);
        assert_eq!(port.probe_calls.load(Ordering::SeqCst), 0);
        assert_eq!(port.refresh_calls(), 0);
        assert!(harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .is_ok());
    }

    #[tokio::test]
    async fn aborting_caller_after_dispatch_still_commits_rotation() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now - ChronoDuration::minutes(1),
            Some("old-refresh"),
            None,
        );
        let started = Arc::new(Barrier::new(2));
        let release = Arc::new(Notify::new());
        let port = FakeAuthPort::new(
            harness.identity(),
            RefreshBehavior::BlockedSuccess {
                started: started.clone(),
                release: release.clone(),
                access: "detached-access".to_string(),
                refresh: "detached-refresh".to_string(),
                expires_in: 3_600,
            },
        );
        let app = harness.app(port);
        let target = harness.target.clone();
        let caller = tokio::spawn(async move { app.access(&target, operation()).await });
        started.wait().await;
        caller.abort();
        release.notify_one();

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let anchor = harness
                .repository
                .resolve_credential_profile_anchor(
                    harness.target.connection_id(),
                    harness.target.profile_name(),
                )
                .expect("profile remains after successful detached refresh");
            let access_id = &anchor.credentials()[&CredentialKind::Access];
            if harness.store.value(access_id).as_deref() == Some("detached-access") {
                break;
            }
            assert!(Instant::now() < deadline, "detached refresh did not commit");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn cancellation_after_dispatch_completes_rotation_and_marks_outcome() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now - ChronoDuration::minutes(1),
            Some("old-refresh"),
            None,
        );
        let started = Arc::new(Barrier::new(2));
        let release = Arc::new(Notify::new());
        let port = FakeAuthPort::new(
            harness.identity(),
            RefreshBehavior::BlockedSuccess {
                started: started.clone(),
                release: release.clone(),
                access: "late-cancel-access".to_string(),
                refresh: "late-cancel-refresh".to_string(),
                expires_in: 3_600,
            },
        );
        let app = harness.app(port);
        let target = harness.target.clone();
        let (operation, cancellation) =
            SessionOperation::new(Instant::now() + Duration::from_secs(3));
        let caller = tokio::spawn(async move { app.access(&target, operation).await });
        started.wait().await;
        cancellation.cancel();
        release.notify_one();
        let access = caller
            .await
            .expect("caller task")
            .expect("terminal refresh succeeds");

        assert_eq!(access.bearer(), "late-cancel-access");
        assert_eq!(access.completion(), OperationCompletion::AfterCancellation);
    }

    #[tokio::test]
    async fn same_root_serializes_while_different_root_remains_independent() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let blocked = Harness::new(
            ADDRESS,
            now - ChronoDuration::minutes(1),
            Some("old-refresh"),
            None,
        );
        let started = Arc::new(Barrier::new(2));
        let release = Arc::new(Notify::new());
        let port = FakeAuthPort::new(
            blocked.identity(),
            RefreshBehavior::BlockedSuccess {
                started: started.clone(),
                release: release.clone(),
                access: "serialized-access".to_string(),
                refresh: "serialized-refresh".to_string(),
                expires_in: 3_600,
            },
        );
        let first_app = blocked.app(port.clone());
        let first_target = blocked.target.clone();
        let first = tokio::spawn(async move { first_app.access(&first_target, operation()).await });
        started.wait().await;

        let same_root = blocked.app(port);
        let short_operation = SessionOperation::new(Instant::now() + Duration::from_millis(80)).0;
        let same_error = same_root
            .access(&blocked.target, short_operation)
            .await
            .expect_err("same root must serialize");
        assert_eq!(same_error.kind(), SessionErrorKind::DeadlineExceeded);

        let independent = Harness::new(
            "https://independent.test",
            now + ChronoDuration::hours(1),
            Some("independent-refresh"),
            None,
        );
        let independent_port = FakeAuthPort::new(independent.identity(), success_behavior());
        independent
            .app(independent_port)
            .access(&independent.target, independent.operation())
            .await
            .expect("different root is independent");

        release.notify_one();
        first
            .await
            .expect("first task join")
            .expect("first refresh");
    }

    #[tokio::test]
    async fn logout_trust_failure_skips_secret_read_and_revokes_locally() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let mismatched = EndpointIdentity::for_test(ADDRESS, "server-b", FINGERPRINT, true, true);
        let port = FakeAuthPort::new(mismatched, success_behavior());
        let reads = harness.store.get_count();
        let outcome = harness
            .app(port.clone())
            .logout(&harness.target, harness.operation())
            .await
            .expect("local logout despite trust mismatch");

        assert_eq!(outcome.remote_status(), RemoteLogoutStatus::NotAttempted);
        assert_eq!(outcome.local_status(), LocalLogoutStatus::Revoked);
        assert_eq!(harness.store.get_count(), reads);
        assert_eq!(port.logout_calls(), 0);
        assert!(harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .is_err());
    }

    #[tokio::test]
    async fn logout_with_missing_physical_refresh_still_revokes_locally() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let anchor = harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .expect("profile anchor");
        harness
            .store
            .remove_physical(&anchor.credentials()[&CredentialKind::Refresh]);
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        let outcome = harness
            .app(port.clone())
            .logout(&harness.target, harness.operation())
            .await
            .expect("local logout with missing physical refresh");

        assert_eq!(outcome.remote_status(), RemoteLogoutStatus::NotAttempted);
        assert_eq!(outcome.local_status(), LocalLogoutStatus::Revoked);
        assert_eq!(port.logout_calls(), 0);
        assert!(harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .is_err());
    }

    #[tokio::test]
    async fn armed_intent_restart_revokes_without_replaying_refresh() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now - ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let anchor = harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .expect("source anchor");
        let permit = harness
            .repository
            .prepare_auth_operation_intent_with_operation_locks(
                &anchor,
                AuthOperationKind::Refresh,
                "crashed-refresh-operation",
            )
            .expect("durably arm refresh");
        drop(permit);
        let port = FakeAuthPort::new(harness.identity(), success_behavior());

        let error = harness
            .app(port.clone())
            .access(&harness.target, harness.operation())
            .await
            .expect_err("restart must revoke armed source");
        assert_eq!(error.kind(), SessionErrorKind::SessionNotFound);
        assert_eq!(port.probe_calls.load(Ordering::SeqCst), 0);
        assert_eq!(port.refresh_calls(), 0);
        assert_eq!(port.logout_calls(), 0);
        assert!(!harness.paths.auth_operation_intent().exists());
        assert!(harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .is_err());
    }

    #[test]
    fn runtime_drop_after_real_dispatch_recovers_without_second_refresh() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now - ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let started = Arc::new(Barrier::new(2));
        let release = Arc::new(Notify::new());
        let port = FakeAuthPort::new(
            harness.identity(),
            RefreshBehavior::BlockedSuccess {
                started: started.clone(),
                release,
                access: "new-access".to_string(),
                refresh: "new-refresh".to_string(),
                expires_in: 3_600,
            },
        );
        let first_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("first runtime");
        let first_app = harness.app(port.clone());
        let first_target = harness.target.clone();
        first_runtime.spawn(async move {
            let _ = first_app.access(&first_target, operation()).await;
        });
        first_runtime.block_on(started.wait());
        assert!(harness.paths.auth_operation_intent().exists());
        assert_eq!(port.refresh_calls(), 1);
        first_runtime.shutdown_background();

        let second_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("second runtime");
        let second_app = harness.app(port.clone());
        let error = second_runtime
            .block_on(second_app.access(&harness.target, harness.operation()))
            .expect_err("restart must revoke dispatched source without replay");
        assert_eq!(error.kind(), SessionErrorKind::SessionNotFound);
        assert_eq!(port.refresh_calls(), 1);
        assert!(!harness.paths.auth_operation_intent().exists());
    }

    #[tokio::test]
    async fn malformed_intent_is_redacted_recovery_required_before_ports() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now - ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        fs::write(harness.paths.auth_operation_intent(), b"{broken").expect("malformed intent");
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        let calls = harness.store.calls();

        let error = harness
            .app(port.clone())
            .access(&harness.target, harness.operation())
            .await
            .expect_err("malformed intent fails closed");
        assert_eq!(error.kind(), SessionErrorKind::RecoveryRequired);
        assert_eq!(harness.store.calls(), calls);
        assert_eq!(port.probe_calls.load(Ordering::SeqCst), 0);
        assert_eq!(port.refresh_calls(), 0);
        assert_eq!(port.logout_calls(), 0);
        assert!(harness.paths.auth_operation_intent().exists());
        assert!(harness.repository.snapshot().is_ok());
    }

    fn password_request(target: &SessionTarget, password: &str) -> PasswordLoginRequest {
        PasswordLoginRequest::new(
            target.clone(),
            "person@example.test",
            LoginPassword::new(password).expect("bounded password"),
        )
        .expect("bounded login request")
    }

    #[tokio::test]
    async fn password_login_commits_exact_account_and_auth_method_once() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            Some("service-secret"),
        );
        harness
            .store
            .probe_config_lock_on_get(harness.repository.clone());
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        let access = harness
            .login_app(port.clone())
            .password_login(
                password_request(&harness.target, "password-secret"),
                harness.operation(),
            )
            .await
            .expect("password login");

        assert_eq!(access.source(), AccessSource::PasswordLogin);
        assert_eq!(
            access.account_subject(),
            Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001")
        );
        assert_eq!(access.auth_method(), Some(AuthMethod::Password));
        assert_eq!(port.prelogin_calls.load(Ordering::SeqCst), 2);
        assert_eq!(port.login_calls(), 1);
        assert_eq!(port.me_calls(), 1);
        assert!(harness.store.probe_succeeded.load(Ordering::SeqCst));
        assert!(!harness.paths.auth_operation_intent().exists());
        let anchor = harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .expect("published login anchor");
        assert_eq!(
            anchor.account_subject(),
            Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001")
        );
        assert_eq!(anchor.auth_method(), Some(AuthMethod::Password));
        let generation = access.authorized_target_generation();
        assert_eq!(generation.revision(), anchor.source_revision());
        assert_eq!(
            generation.account_subject(),
            Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001")
        );
        assert_eq!(generation.auth_method(), Some(AuthMethod::Password));
        drop(
            harness
                .repository
                .acquire_sync_commit_lease(&generation)
                .await
                .expect("password candidate generation remains exact"),
        );
        assert!(anchor
            .credentials()
            .contains_key(&CredentialKind::ServiceAccount));
    }

    #[tokio::test]
    async fn password_login_me_failure_compensates_only_after_source_is_proven() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        port.set_me_behavior(MeBehavior::Failure(failure(AuthFailureKind::Unavailable)));
        let error = harness
            .login_app(port.clone())
            .password_login(
                password_request(&harness.target, "password-secret"),
                harness.operation(),
            )
            .await
            .expect_err("failed /me cannot publish login");

        assert_eq!(error.kind(), SessionErrorKind::TransportUnavailable);
        assert_eq!(port.login_calls(), 1);
        assert_eq!(port.me_calls(), 1);
        assert_eq!(port.logout_calls(), 1);
        assert!(!harness.paths.auth_operation_intent().exists());
        let source = harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .expect("source profile remains");
        assert_eq!(source.account_subject(), None);
        assert_eq!(source.auth_method(), None);
    }

    #[tokio::test]
    async fn password_login_kdf_change_after_me_compensates_without_candidate() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        let initial = valid_prelogin_response();
        let mut changed = valid_prelogin_response();
        changed.kdf_salt = base64::engine::general_purpose::STANDARD.encode([8_u8; 32]);
        changed.salt_fingerprint = zann_core::passwords::kdf_fingerprint(
            &changed.kdf_salt,
            &changed.kdf_params.to_crypto_params(),
        )
        .expect("changed fingerprint");
        port.set_prelogin_results(vec![Ok(initial), Ok(changed)]);

        let error = harness
            .login_app(port.clone())
            .password_login(
                password_request(&harness.target, "password-secret"),
                harness.operation(),
            )
            .await
            .expect_err("KDF race must not publish");

        assert_eq!(error.kind(), SessionErrorKind::Protocol);
        assert_eq!(port.prelogin_calls.load(Ordering::SeqCst), 2);
        assert_eq!(port.login_calls(), 1);
        assert_eq!(port.me_calls(), 1);
        assert_eq!(port.logout_calls(), 1);
        assert!(!harness.paths.auth_operation_intent().exists());
        let source = harness
            .repository
            .resolve_credential_profile_anchor(
                harness.target.connection_id(),
                harness.target.profile_name(),
            )
            .expect("source profile remains");
        assert_eq!(source.account_subject(), None);
        assert_eq!(source.auth_method(), None);
    }

    #[tokio::test]
    async fn password_login_uses_canonical_me_email_to_enrich_existing_identity() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        harness
            .repository
            .reconcile_credentials_with_operation_lock(harness.store.as_ref())
            .expect("settle seed credential journal");
        let prelogin = valid_prelogin_response();
        let mut config = harness
            .repository
            .snapshot()
            .expect("source config")
            .config()
            .clone();
        config.revision = config.revision.checked_add(1).expect("revision advance");
        config.identity = Some(
            password_login_identity_from_prelogin(prelogin.clone(), None)
                .expect("valid test identity"),
        );
        fs::write(
            harness.paths.config(),
            serde_json::to_vec(&config).expect("serialize config"),
        )
        .expect("publish existing identity");
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        port.set_prelogin_results(vec![Ok(prelogin.clone()), Ok(prelogin)]);
        let request = PasswordLoginRequest::new(
            harness.target.clone(),
            "Person@Example.Test",
            LoginPassword::new("password-secret").expect("password"),
        )
        .expect("login request");

        harness
            .login_app(port)
            .password_login(request, harness.operation())
            .await
            .expect("canonical email login");

        assert_eq!(
            harness
                .repository
                .snapshot()
                .expect("published config")
                .config()
                .identity
                .as_ref()
                .and_then(|identity| identity.email.as_deref()),
            Some("person@example.test")
        );
    }

    #[tokio::test]
    async fn failed_password_login_compensation_is_explicitly_remote_unknown() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        port.set_me_behavior(MeBehavior::Failure(failure(AuthFailureKind::Unavailable)));
        port.logout_fails.store(true, Ordering::SeqCst);

        let error = harness
            .login_app(port.clone())
            .password_login(
                password_request(&harness.target, "password-secret"),
                harness.operation(),
            )
            .await
            .expect_err("failed compensation is remote-unknown");

        assert_eq!(error.kind(), SessionErrorKind::SessionLostRemoteUnknown);
        assert!(error.cleanup_deferred());
        assert_eq!(port.logout_calls(), 1);
    }

    #[tokio::test]
    async fn successful_login_with_invalid_refresh_is_remote_unknown_without_logout() {
        for invalid_refresh in [String::new(), "x".repeat(64 * 1024 + 1)] {
            let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
                .expect("fixed time")
                .with_timezone(&Utc);
            let harness = Harness::new(
                ADDRESS,
                now + ChronoDuration::hours(1),
                Some("old-refresh"),
                None,
            );
            let port = FakeAuthPort::new(harness.identity(), success_behavior());
            port.set_login_behavior(RefreshBehavior::Success {
                access: "new-access".to_string(),
                refresh: invalid_refresh,
                expires_in: 3_600,
            });

            let error = harness
                .login_app(port.clone())
                .password_login(
                    password_request(&harness.target, "password-secret"),
                    harness.operation(),
                )
                .await
                .expect_err("invalid refresh cannot be compensated");

            assert_eq!(error.kind(), SessionErrorKind::SessionLostRemoteUnknown);
            assert!(error.cleanup_deferred());
            assert_eq!(port.login_calls(), 1);
            assert_eq!(port.logout_calls(), 0);
            assert!(!harness.paths.auth_operation_intent().exists());
            let source = harness
                .repository
                .resolve_credential_profile_anchor(
                    harness.target.connection_id(),
                    harness.target.profile_name(),
                )
                .expect("source remains");
            assert_eq!(source.account_subject(), None);
            assert_eq!(source.auth_method(), None);
        }
    }

    #[tokio::test]
    async fn cancellation_before_candidate_preserves_kind_only_when_compensation_succeeds() {
        for (logout_fails, expected_kind) in [
            (false, SessionErrorKind::Cancelled),
            (true, SessionErrorKind::SessionLostRemoteUnknown),
        ] {
            let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
                .expect("fixed time")
                .with_timezone(&Utc);
            let harness = Harness::new(
                ADDRESS,
                now + ChronoDuration::hours(1),
                Some("old-refresh"),
                None,
            );
            let port = FakeAuthPort::new(harness.identity(), success_behavior());
            port.logout_fails.store(logout_fails, Ordering::SeqCst);
            let me_started = Arc::new(Barrier::new(2));
            let me_release = Arc::new(Notify::new());
            let identity = match &*port.me_behavior.lock().expect("me behavior lock") {
                MeBehavior::Success(identity) => identity.clone(),
                _ => panic!("default me behavior"),
            };
            port.set_me_behavior(MeBehavior::BlockedSuccess {
                started: me_started.clone(),
                release: me_release.clone(),
                identity,
            });
            let (operation, cancellation) =
                SessionOperation::new(Instant::now() + Duration::from_secs(3));
            let app = harness.login_app(port.clone());
            let target = harness.target.clone();
            let task = tokio::spawn(async move {
                app.password_login(password_request(&target, "password-secret"), operation)
                    .await
            });
            me_started.wait().await;
            let (store_started, store_release) = harness.store.block_next_get();
            let store_wait = store_started.notified();
            tokio::pin!(store_wait);
            store_wait.as_mut().enable();
            me_release.notify_waiters();
            store_wait.await;
            cancellation.cancel();
            let (released, condition) = &*store_release;
            *released.lock().expect("store release lock") = true;
            condition.notify_all();

            let error = task
                .await
                .expect("login join")
                .expect_err("cancelled before candidate");
            assert_eq!(error.kind(), expected_kind);
            assert_eq!(error.cleanup_deferred(), logout_fails);
            assert_eq!(port.login_calls(), 1);
            assert_eq!(port.logout_calls(), 1);
            assert!(!harness.paths.auth_operation_intent().exists());
        }
    }

    #[tokio::test]
    async fn cancellation_during_reserved_id_preflight_abandons_without_login_post() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        let (started, release) = harness.store.block_next_get();
        let started_wait = started.notified();
        tokio::pin!(started_wait);
        started_wait.as_mut().enable();
        let (operation, cancellation) =
            SessionOperation::new(Instant::now() + Duration::from_secs(3));
        let app = harness.login_app(port.clone());
        let target = harness.target.clone();
        let task = tokio::spawn(async move {
            app.password_login(password_request(&target, "password-secret"), operation)
                .await
        });
        started_wait.await;
        cancellation.cancel();
        let (released, condition) = &*release;
        *released.lock().expect("release lock") = true;
        condition.notify_all();

        let error = task
            .await
            .expect("login join")
            .expect_err("cancelled preflight");
        assert_eq!(error.kind(), SessionErrorKind::Cancelled);
        assert_eq!(port.login_calls(), 0);
        assert_eq!(port.me_calls(), 0);
        assert_eq!(port.logout_calls(), 0);
        assert!(!harness.paths.auth_operation_intent().exists());
    }

    #[tokio::test]
    async fn cancelled_login_during_me_cannot_late_publish_over_next_login() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        let started = Arc::new(Barrier::new(2));
        let release = Arc::new(Notify::new());
        let winner_identity = match &*port.me_behavior.lock().expect("me behavior lock") {
            MeBehavior::Success(identity) => identity.clone(),
            _ => panic!("default me behavior"),
        };
        port.set_me_behavior(MeBehavior::BlockedSuccess {
            started: started.clone(),
            release: release.clone(),
            identity: winner_identity.clone(),
        });
        let (first_operation, cancellation) =
            SessionOperation::new(Instant::now() + Duration::from_secs(3));
        let first_app = harness.login_app(port.clone());
        let first_target = harness.target.clone();
        let first = tokio::spawn(async move {
            first_app
                .password_login(
                    password_request(&first_target, "first-password"),
                    first_operation,
                )
                .await
        });
        started.wait().await;
        port.set_me_behavior(MeBehavior::Success(winner_identity));
        cancellation.cancel();
        let second_app = harness.login_app(port.clone());
        let second_target = harness.target.clone();
        let second = tokio::spawn(async move {
            second_app
                .password_login(
                    password_request(&second_target, "second-password"),
                    operation(),
                )
                .await
        });
        release.notify_waiters();

        let first_error = first
            .await
            .expect("first join")
            .expect_err("first login cancelled");
        assert_eq!(first_error.kind(), SessionErrorKind::Cancelled);
        let second_access = second
            .await
            .expect("second join")
            .expect("second login wins");
        assert_eq!(second_access.source(), AccessSource::PasswordLogin);
        assert_eq!(port.login_calls(), 2);
        assert_eq!(port.logout_calls(), 1);
        assert!(!harness.paths.auth_operation_intent().exists());
    }

    #[test]
    fn runtime_drop_after_password_post_recovers_without_replaying_login() {
        let now = DateTime::parse_from_rfc3339("2026-08-16T12:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc);
        let harness = Harness::new(
            ADDRESS,
            now + ChronoDuration::hours(1),
            Some("old-refresh"),
            None,
        );
        let started = Arc::new(Barrier::new(2));
        let release = Arc::new(Notify::new());
        let port = FakeAuthPort::new(harness.identity(), success_behavior());
        port.set_login_behavior(RefreshBehavior::BlockedSuccess {
            started: started.clone(),
            release,
            access: "new-access".to_string(),
            refresh: "new-refresh".to_string(),
            expires_in: 3_600,
        });
        let first_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("first runtime");
        let first_app = harness.login_app(port.clone());
        let first_target = harness.target.clone();
        first_runtime.spawn(async move {
            let _ = first_app
                .password_login(
                    password_request(&first_target, "password-secret"),
                    operation(),
                )
                .await;
        });
        first_runtime.block_on(started.wait());
        assert!(harness.paths.auth_operation_intent().exists());
        let intent = fs::read_to_string(harness.paths.auth_operation_intent())
            .expect("read armed auth intent");
        for private in [
            "person@example.test",
            "password-secret",
            "new-access",
            "new-refresh",
        ] {
            assert!(!intent.contains(private));
        }
        assert_eq!(port.login_calls(), 1);
        first_runtime.shutdown_background();

        let second_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("second runtime");
        let access = second_runtime
            .block_on(
                harness
                    .app(port.clone())
                    .access(&harness.target, harness.operation()),
            )
            .expect("restart uses untouched source session");
        assert_eq!(access.source(), AccessSource::Stored);
        assert_eq!(port.login_calls(), 1);
        assert!(!harness.paths.auth_operation_intent().exists());
    }

    #[test]
    fn login_password_and_request_debug_are_redacted_and_bounded() {
        let secret = "password-secret-do-not-render";
        let password = LoginPassword::new(secret).expect("password");
        assert!(!format!("{password:?}").contains(secret));
        let request = PasswordLoginRequest::new(
            SessionTarget::new(ConnectionId::deterministic("login", ADDRESS), PROFILE)
                .expect("target"),
            "person@example.test",
            password,
        )
        .expect("request");
        assert!(!format!("{request:?}").contains(secret));
        assert!(PasswordLoginRequest::new(
            request.target().clone(),
            " person@example.test",
            LoginPassword::new("secret").expect("password"),
        )
        .is_err());
        assert!(LoginPassword::new("x".repeat(LOGIN_PASSWORD_MAX_BYTES + 1)).is_err());
    }

    fn operation() -> SessionOperation {
        SessionOperation::new(Instant::now() + Duration::from_secs(3)).0
    }
}
