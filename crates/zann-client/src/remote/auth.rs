use std::fmt;
use std::time::Duration;

use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::{RequestBuilder, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use zann_core::api::auth::{
    ApiErrorResponse, LoginRequest, LoginResponse, LogoutRequest, OidcConfigResponse,
    OidcLoginRequest, PreloginResponse, RefreshRequest, RegisterRequest,
    ServiceAccountLoginRequest, ServiceAccountLoginResponse,
};
use zann_core::api::system::SystemInfoResponse;
use zann_core::api::vaults::PersonalVaultStatusResponse;
use zann_core::Identity;
use zeroize::Zeroizing;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Auth responses are deliberately small. The 512 KiB ceiling leaves room for
/// a service-account response containing many vault keys while preventing an
/// untrusted endpoint from making the client buffer an unbounded body.
const MAX_RESPONSE_BODY_BYTES: usize = 512 * 1024;

const REGISTER_PATH: &str = "v1/auth/register";
const PRELOGIN_PATH: &str = "v1/auth/prelogin";
const PASSWORD_LOGIN_PATH: &str = "v1/auth/login";
const OIDC_LOGIN_PATH: &str = "v1/auth/login/oidc";
const SERVICE_ACCOUNT_LOGIN_PATH: &str = "v1/auth/service-account";
const REFRESH_PATH: &str = "v1/auth/refresh";
const LOGOUT_PATH: &str = "v1/auth/logout";
const OIDC_CONFIG_PATH: &str = "v1/auth/oidc/config";
const ME_PATH: &str = "v1/users/me";
const SYSTEM_INFO_PATH: &str = "v1/system/info";
const PERSONAL_VAULT_STATUS_PATH: &str = "v1/vaults/personal/status";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthOperation {
    Configure,
    Prelogin,
    OidcConfig,
    SystemInfo,
    PasswordLogin,
    Register,
    OidcLogin,
    Refresh,
    Logout,
    ServiceAccountLogin,
    Me,
    PersonalVaultStatus,
}

impl AuthOperation {
    const fn semantics(self) -> RequestSemantics {
        match self {
            Self::Prelogin
            | Self::OidcConfig
            | Self::SystemInfo
            | Self::Me
            | Self::PersonalVaultStatus => RequestSemantics::SafeRead,
            Self::Logout => RequestSemantics::IdempotentWrite,
            Self::PasswordLogin
            | Self::Register
            | Self::OidcLogin
            | Self::Refresh
            | Self::ServiceAccountLogin => RequestSemantics::ExactlyOnce,
            Self::Configure => RequestSemantics::Local,
        }
    }
}

impl fmt::Display for AuthOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configure => "configure",
            Self::Prelogin => "prelogin",
            Self::OidcConfig => "oidc_config",
            Self::SystemInfo => "system_info",
            Self::PasswordLogin => "password_login",
            Self::Register => "register",
            Self::OidcLogin => "oidc_login",
            Self::Refresh => "refresh",
            Self::Logout => "logout",
            Self::ServiceAccountLogin => "service_account_login",
            Self::Me => "me",
            Self::PersonalVaultStatus => "personal_vault_status",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestSemantics {
    Local,
    SafeRead,
    ExactlyOnce,
    IdempotentWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthHttpErrorKind {
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
}

impl fmt::Display for AuthHttpErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::InsecureTransport => "insecure_transport",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::AmbiguousOutcome => "ambiguous_outcome",
            Self::Protocol => "protocol",
            Self::BodyTooLarge => "body_too_large",
            Self::SessionExpired => "session_expired",
            Self::Rejected => "rejected",
            Self::Server => "server",
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct AuthHttpError {
    operation: AuthOperation,
    kind: AuthHttpErrorKind,
    status: Option<u16>,
    server_code: Option<&'static str>,
}

impl AuthHttpError {
    const fn new(operation: AuthOperation, kind: AuthHttpErrorKind) -> Self {
        Self {
            operation,
            kind,
            status: None,
            server_code: None,
        }
    }

    const fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status.as_u16());
        self
    }

    const fn with_server_code(mut self, server_code: Option<&'static str>) -> Self {
        self.server_code = server_code;
        self
    }

    pub(crate) const fn operation(&self) -> AuthOperation {
        self.operation
    }

    pub(crate) const fn kind(&self) -> AuthHttpErrorKind {
        self.kind
    }

    pub(crate) const fn status(&self) -> Option<u16> {
        self.status
    }

    pub(crate) const fn server_code(&self) -> Option<&'static str> {
        self.server_code
    }
}

impl fmt::Debug for AuthHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthHttpError")
            .field("operation", &self.operation)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("server_code", &self.server_code)
            .finish()
    }
}

impl fmt::Display for AuthHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "auth_http:{}:{}", self.operation, self.kind)?;
        if let Some(status) = self.status {
            write!(formatter, ":status_{status}")?;
        }
        if let Some(code) = self.server_code {
            write!(formatter, ":{code}")?;
        }
        Ok(())
    }
}

impl std::error::Error for AuthHttpError {}

/// A single-shot HTTP transport for authentication endpoints.
///
/// The owned client disables redirects and reqwest's protocol-level automatic
/// retries. Every method below constructs and sends exactly one HTTP request.
pub(crate) struct AuthHttpTransport {
    client: reqwest::Client,
    base_url: Url,
    request_timeout: Duration,
}

impl AuthHttpTransport {
    pub(crate) fn new(endpoint: &str) -> Result<Self, AuthHttpError> {
        Self::with_timeout(endpoint, DEFAULT_REQUEST_TIMEOUT)
    }

    pub(crate) fn with_timeout(
        endpoint: &str,
        request_timeout: Duration,
    ) -> Result<Self, AuthHttpError> {
        let base_url = canonical_base_url(endpoint)?;
        if request_timeout.is_zero() || request_timeout > MAX_REQUEST_TIMEOUT {
            return Err(AuthHttpError::new(
                AuthOperation::Configure,
                AuthHttpErrorKind::InvalidEndpoint,
            ));
        }

        let mut client_builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .connect_timeout(request_timeout);
        // Plain HTTP is accepted only for a loopback origin. It must never be
        // handed to an environment/system proxy, which would move bearer or
        // refresh material off-host without TLS. HTTPS endpoints retain the
        // platform proxy policy because the proxy only carries their TLS
        // tunnel under the configured trust store.
        if loopback_plaintext_requires_direct_transport(&base_url) {
            client_builder = client_builder.no_proxy();
        }
        let client = client_builder.build().map_err(|_| {
            AuthHttpError::new(AuthOperation::Configure, AuthHttpErrorKind::InvalidEndpoint)
        })?;

        Ok(Self {
            client,
            base_url,
            request_timeout,
        })
    }

    /// Validates that this endpoint may receive authentication secrets.
    ///
    /// Safe discovery reads deliberately support plain HTTP so callers can
    /// inspect an endpoint before trusting it. Session orchestration must call
    /// this preflight before reading a credential from its store; the request
    /// methods repeat the same check at dispatch as defence in depth.
    pub(crate) fn ensure_sensitive_endpoint(&self) -> Result<(), AuthHttpError> {
        self.ensure_sensitive_transport(AuthOperation::Configure)
    }

    pub(crate) async fn prelogin(&self, email: &str) -> Result<PreloginResponse, AuthHttpError> {
        self.ensure_sensitive_transport(AuthOperation::Prelogin)?;
        let mut url = self.url_for(AuthOperation::Prelogin, PRELOGIN_PATH)?;
        url.query_pairs_mut().append_pair("email", email);
        let request = self.client.get(url).timeout(self.request_timeout);
        self.execute_json(AuthOperation::Prelogin, request).await
    }

    pub(crate) async fn oidc_config(&self) -> Result<OidcConfigResponse, AuthHttpError> {
        let request = self
            .client
            .get(self.url_for(AuthOperation::OidcConfig, OIDC_CONFIG_PATH)?)
            .timeout(self.request_timeout);
        self.execute_json(AuthOperation::OidcConfig, request).await
    }

    pub(crate) async fn system_info(&self) -> Result<SystemInfoResponse, AuthHttpError> {
        let request = self
            .client
            .get(self.url_for(AuthOperation::SystemInfo, SYSTEM_INFO_PATH)?)
            .timeout(self.request_timeout);
        self.execute_json(AuthOperation::SystemInfo, request).await
    }

    pub(crate) async fn password_login(
        &self,
        payload: &LoginRequest,
    ) -> Result<LoginResponse, AuthHttpError> {
        self.post_json(AuthOperation::PasswordLogin, PASSWORD_LOGIN_PATH, payload)
            .await
    }

    pub(crate) async fn register(
        &self,
        payload: &RegisterRequest,
    ) -> Result<LoginResponse, AuthHttpError> {
        self.post_json(AuthOperation::Register, REGISTER_PATH, payload)
            .await
    }

    pub(crate) async fn oidc_login(
        &self,
        payload: &OidcLoginRequest,
    ) -> Result<LoginResponse, AuthHttpError> {
        self.post_json(AuthOperation::OidcLogin, OIDC_LOGIN_PATH, payload)
            .await
    }

    pub(crate) async fn refresh(
        &self,
        payload: &RefreshRequest,
    ) -> Result<LoginResponse, AuthHttpError> {
        self.post_json(AuthOperation::Refresh, REFRESH_PATH, payload)
            .await
    }

    pub(crate) async fn logout(&self, payload: &LogoutRequest) -> Result<(), AuthHttpError> {
        self.ensure_sensitive_transport(AuthOperation::Logout)?;
        let request = self
            .client
            .post(self.url_for(AuthOperation::Logout, LOGOUT_PATH)?)
            .timeout(self.request_timeout)
            .json(payload);
        self.execute_empty(AuthOperation::Logout, request).await
    }

    pub(crate) async fn service_account_login(
        &self,
        payload: &ServiceAccountLoginRequest,
    ) -> Result<ServiceAccountLoginResponse, AuthHttpError> {
        self.post_json(
            AuthOperation::ServiceAccountLogin,
            SERVICE_ACCOUNT_LOGIN_PATH,
            payload,
        )
        .await
    }

    pub(crate) async fn me(&self, access_token: &str) -> Result<Identity, AuthHttpError> {
        self.ensure_sensitive_transport(AuthOperation::Me)?;
        let authorization = bearer_authorization_header(access_token)?;
        let request = self
            .client
            .get(self.url_for(AuthOperation::Me, ME_PATH)?)
            .header(AUTHORIZATION, authorization)
            .timeout(self.request_timeout);
        self.execute_json(AuthOperation::Me, request).await
    }

    pub(crate) async fn personal_vault_status(
        &self,
        access_token: &str,
    ) -> Result<PersonalVaultStatusResponse, AuthHttpError> {
        self.ensure_sensitive_transport(AuthOperation::PersonalVaultStatus)?;
        let authorization = bearer_authorization_header(access_token)?;
        let request = self
            .client
            .get(self.url_for(
                AuthOperation::PersonalVaultStatus,
                PERSONAL_VAULT_STATUS_PATH,
            )?)
            .header(AUTHORIZATION, authorization)
            .timeout(self.request_timeout);
        self.execute_json(AuthOperation::PersonalVaultStatus, request)
            .await
    }

    async fn post_json<T, R>(
        &self,
        operation: AuthOperation,
        path: &str,
        payload: &T,
    ) -> Result<R, AuthHttpError>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        debug_assert_eq!(operation.semantics(), RequestSemantics::ExactlyOnce);
        self.ensure_sensitive_transport(operation)?;
        let request = self
            .client
            .post(self.url_for(operation, path)?)
            .timeout(self.request_timeout)
            .json(payload);
        self.execute_json(operation, request).await
    }

    async fn execute_json<T>(
        &self,
        operation: AuthOperation,
        request: RequestBuilder,
    ) -> Result<T, AuthHttpError>
    where
        T: DeserializeOwned,
    {
        let (status, body) = self.execute(operation, request).await?;
        if !status.is_success() {
            return Err(status_error(operation, status, &body));
        }
        serde_json::from_slice(&body)
            .map_err(|_| response_processing_error(operation, status, AuthHttpErrorKind::Protocol))
    }

    async fn execute_empty(
        &self,
        operation: AuthOperation,
        request: RequestBuilder,
    ) -> Result<(), AuthHttpError> {
        debug_assert_eq!(operation.semantics(), RequestSemantics::IdempotentWrite);
        let (status, body) = self.execute(operation, request).await?;
        if !status.is_success() {
            return Err(status_error(operation, status, &body));
        }
        if body.iter().any(|byte| !byte.is_ascii_whitespace()) {
            return Err(AuthHttpError::new(operation, AuthHttpErrorKind::Protocol));
        }
        Ok(())
    }

    async fn execute(
        &self,
        operation: AuthOperation,
        request: RequestBuilder,
    ) -> Result<(StatusCode, Zeroizing<Vec<u8>>), AuthHttpError> {
        let response = request
            .send()
            .await
            .map_err(|error| request_error(operation, &error))?;
        read_bounded_body(operation, response).await
    }

    fn url_for(&self, operation: AuthOperation, path: &str) -> Result<Url, AuthHttpError> {
        self.base_url
            .join(path)
            .map_err(|_| AuthHttpError::new(operation, AuthHttpErrorKind::InvalidEndpoint))
    }

    fn ensure_sensitive_transport(&self, operation: AuthOperation) -> Result<(), AuthHttpError> {
        if self.base_url.scheme() == "https" || endpoint_is_loopback(&self.base_url) {
            return Ok(());
        }
        Err(AuthHttpError::new(
            operation,
            AuthHttpErrorKind::InsecureTransport,
        ))
    }
}

fn bearer_authorization_header(access_token: &str) -> Result<HeaderValue, AuthHttpError> {
    let encoded = Zeroizing::new(format!("Bearer {access_token}"));
    let mut authorization = HeaderValue::from_str(encoded.as_str())
        .map_err(|_| AuthHttpError::new(AuthOperation::Me, AuthHttpErrorKind::Protocol))?;
    authorization.set_sensitive(true);
    Ok(authorization)
}

fn canonical_base_url(endpoint: &str) -> Result<Url, AuthHttpError> {
    let invalid =
        || AuthHttpError::new(AuthOperation::Configure, AuthHttpErrorKind::InvalidEndpoint);
    let mut url = Url::parse(endpoint).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || endpoint_authority(endpoint).is_some_and(|authority| authority.contains('@'))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(invalid());
    }
    url.set_path("/");
    Ok(url)
}

fn endpoint_authority(endpoint: &str) -> Option<&str> {
    endpoint
        .split_once("://")
        .map(|(_, remainder)| remainder.split(['/', '?', '#']).next().unwrap_or_default())
}

fn endpoint_is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    // `url::Url::host_str` retains brackets for IPv6 literals. Strip only
    // that syntactic pair before parsing the address; domains cannot contain
    // brackets in a valid URL authority.
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn loopback_plaintext_requires_direct_transport(url: &Url) -> bool {
    url.scheme() == "http" && endpoint_is_loopback(url)
}

async fn read_bounded_body(
    operation: AuthOperation,
    mut response: reqwest::Response,
) -> Result<(StatusCode, Zeroizing<Vec<u8>>), AuthHttpError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BODY_BYTES as u64)
    {
        return Err(response_processing_error(
            operation,
            status,
            AuthHttpErrorKind::BodyTooLarge,
        ));
    }

    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default()
        .min(MAX_RESPONSE_BODY_BYTES);
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| request_error(operation, &error))?
    {
        let Some(next_length) = body.len().checked_add(chunk.len()) else {
            return Err(response_processing_error(
                operation,
                status,
                AuthHttpErrorKind::BodyTooLarge,
            ));
        };
        if next_length > MAX_RESPONSE_BODY_BYTES {
            return Err(response_processing_error(
                operation,
                status,
                AuthHttpErrorKind::BodyTooLarge,
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

/// Once an exactly-once request has received a successful response, failures
/// while reading or decoding that response cannot prove that the server did
/// not commit the operation. In particular, refresh may already have
/// invalidated the old refresh token. Preserve that uncertainty explicitly so
/// callers never retry or revoke based on an ordinary protocol error.
fn response_processing_error(
    operation: AuthOperation,
    status: StatusCode,
    fallback: AuthHttpErrorKind,
) -> AuthHttpError {
    let kind = classified_status_kind(operation, status, None).unwrap_or(fallback);
    AuthHttpError::new(operation, kind).with_status(status)
}

fn request_error(operation: AuthOperation, error: &reqwest::Error) -> AuthHttpError {
    if error.is_builder() {
        return AuthHttpError::new(operation, AuthHttpErrorKind::Protocol);
    }
    if operation.semantics() == RequestSemantics::ExactlyOnce {
        return AuthHttpError::new(operation, AuthHttpErrorKind::AmbiguousOutcome);
    }
    let kind = if error.is_timeout() {
        AuthHttpErrorKind::Timeout
    } else {
        AuthHttpErrorKind::Unavailable
    };
    AuthHttpError::new(operation, kind)
}

fn status_error(operation: AuthOperation, status: StatusCode, body: &[u8]) -> AuthHttpError {
    let server_code = allowlisted_server_code(body);
    let kind = if let Some(kind) = classified_status_kind(operation, status, server_code) {
        kind
    } else if status.is_server_error() {
        AuthHttpErrorKind::Server
    } else {
        AuthHttpErrorKind::Rejected
    };
    AuthHttpError::new(operation, kind)
        .with_status(status)
        .with_server_code(server_code)
}

fn classified_status_kind(
    operation: AuthOperation,
    status: StatusCode,
    server_code: Option<&'static str>,
) -> Option<AuthHttpErrorKind> {
    if operation == AuthOperation::Refresh {
        if status == StatusCode::UNAUTHORIZED {
            // A refresh 401 is terminal even when an intermediary strips or
            // truncates the canonical error body. Keeping the old credential
            // would turn an unclassified rejection into an automatic replay.
            return Some(AuthHttpErrorKind::SessionExpired);
        }
        if status.is_client_error() && is_definitive_pre_dispatch_rejection(status) {
            return None;
        }
        // Refresh rotates a credential. Every response not proven to be a
        // pre-handler rejection is ambiguous, including 1xx, 3xx, 5xx and
        // future/non-standard status classes.
        return Some(AuthHttpErrorKind::AmbiguousOutcome);
    }
    if operation == AuthOperation::PasswordLogin {
        let documented_rejection = matches!(
            (status, server_code),
            (StatusCode::UNAUTHORIZED, Some("invalid_credentials"))
                | (
                    StatusCode::FORBIDDEN,
                    Some("internal_disabled" | "user_disabled")
                )
        );
        if documented_rejection || is_definitive_pre_dispatch_rejection(status) {
            return None;
        }
        // A proxy-generated/unknown 4xx cannot prove the login handler did
        // not create a session. Treat it exactly like every non-4xx outcome.
        return Some(AuthHttpErrorKind::AmbiguousOutcome);
    }
    if operation.semantics() == RequestSemantics::ExactlyOnce && !status.is_client_error() {
        return Some(AuthHttpErrorKind::AmbiguousOutcome);
    }
    None
}

fn is_definitive_pre_dispatch_rejection(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
            | StatusCode::UNPROCESSABLE_ENTITY
    )
}

/// Only static, documented error codes may cross the redaction boundary. An
/// arbitrary or reflected server string is discarded rather than copied into
/// a diagnostic value.
fn allowlisted_server_code(body: &[u8]) -> Option<&'static str> {
    let response = serde_json::from_slice::<ApiErrorResponse>(body).ok()?;
    match response.error.as_str() {
        "db_error" => Some("db_error"),
        "device_required" => Some("device_required"),
        "email_taken" => Some("email_taken"),
        "internal_disabled" => Some("internal_disabled"),
        "invalid_credentials" => Some("invalid_credentials"),
        "invalid_password" => Some("invalid_password"),
        "invalid_token" => Some("invalid_token"),
        "ip_not_allowed" => Some("ip_not_allowed"),
        "kdf_error" => Some("kdf_error"),
        "kdf_failed" => Some("kdf_failed"),
        "no_changes" => Some("no_changes"),
        "oidc_disabled" => Some("oidc_disabled"),
        "personal_vault_create_failed" => Some("personal_vault_create_failed"),
        "policy_mismatch" => Some("policy_mismatch"),
        "registration_disabled" => Some("registration_disabled"),
        "token_expired" => Some("token_expired"),
        "token_revoked" => Some("token_revoked"),
        "user_disabled" => Some("user_disabled"),
        "vault_keys_failed" => Some("vault_keys_failed"),
        _ => None,
    }
}

#[cfg(test)]
fn expect_auth_error<T>(result: Result<T, AuthHttpError>, message: &str) -> AuthHttpError {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_requires_an_unambiguous_http_origin() {
        for invalid in [
            "file:///tmp/zann",
            "https://user@example.test",
            "https://@example.test",
            "https://example.test/base",
            "https://example.test?tenant=one",
            "https://example.test/#fragment",
        ] {
            let error =
                expect_auth_error(AuthHttpTransport::new(invalid), "endpoint must be rejected");
            assert_eq!(error.operation(), AuthOperation::Configure);
            assert_eq!(error.kind(), AuthHttpErrorKind::InvalidEndpoint);
        }

        assert!(AuthHttpTransport::new("https://example.test").is_ok());
        assert!(AuthHttpTransport::new("http://127.0.0.1:8080/").is_ok());
    }

    #[test]
    fn sensitive_endpoint_preflight_uses_the_dispatch_transport_policy() {
        let remote_http = AuthHttpTransport::new("http://example.test")
            .expect("safe discovery may inspect remote HTTP");
        let error = remote_http
            .ensure_sensitive_endpoint()
            .expect_err("remote HTTP must not receive credentials");
        assert_eq!(error.operation(), AuthOperation::Configure);
        assert_eq!(error.kind(), AuthHttpErrorKind::InsecureTransport);

        AuthHttpTransport::new("https://example.test")
            .expect("HTTPS endpoint")
            .ensure_sensitive_endpoint()
            .expect("HTTPS may receive credentials");
        AuthHttpTransport::new("http://127.0.0.1:8080")
            .expect("loopback endpoint")
            .ensure_sensitive_endpoint()
            .expect("loopback HTTP may receive credentials");
    }

    #[test]
    fn only_loopback_plaintext_forces_direct_proxy_bypass() {
        for endpoint in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            let url = canonical_base_url(endpoint).expect("loopback endpoint");
            assert!(loopback_plaintext_requires_direct_transport(&url));
        }

        for endpoint in [
            "https://localhost",
            "https://example.test",
            "http://example.test",
        ] {
            let url = canonical_base_url(endpoint).expect("valid endpoint");
            assert!(!loopback_plaintext_requires_direct_transport(&url));
        }
    }

    #[test]
    fn operation_semantics_make_replay_policy_explicit() {
        assert_eq!(
            AuthOperation::PasswordLogin.semantics(),
            RequestSemantics::ExactlyOnce
        );
        assert_eq!(
            AuthOperation::Refresh.semantics(),
            RequestSemantics::ExactlyOnce
        );
        assert_eq!(
            AuthOperation::Prelogin.semantics(),
            RequestSemantics::SafeRead
        );
        assert_eq!(
            AuthOperation::Logout.semantics(),
            RequestSemantics::IdempotentWrite
        );
    }

    #[test]
    fn non_loopback_plain_http_rejects_sensitive_operations() {
        let transport = AuthHttpTransport::new("http://example.test").expect("build transport");
        let error = expect_auth_error(
            transport.ensure_sensitive_transport(AuthOperation::PasswordLogin),
            "plain HTTP must reject a password operation before dispatch",
        );
        assert_eq!(error.operation(), AuthOperation::PasswordLogin);
        assert_eq!(error.kind(), AuthHttpErrorKind::InsecureTransport);
    }

    #[test]
    fn arbitrary_server_error_text_does_not_cross_redaction_boundary() {
        let secret = "seeded-password-DO-NOT-LEAK";
        let body = serde_json::to_vec(&ApiErrorResponse::new(secret)).expect("encode response");
        let error = status_error(
            AuthOperation::PasswordLogin,
            StatusCode::UNAUTHORIZED,
            &body,
        );
        assert_eq!(error.server_code(), None);
        assert!(!format!("{error}").contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    #[test]
    fn password_login_only_accepts_proven_pre_session_rejections() {
        for (status, body) in [
            (StatusCode::REQUEST_TIMEOUT, Vec::new()),
            (StatusCode::UNAUTHORIZED, Vec::new()),
            (
                StatusCode::UNAUTHORIZED,
                serde_json::to_vec(&ApiErrorResponse::new("unknown_proxy_error"))
                    .expect("encode unknown error"),
            ),
            (StatusCode::TOO_MANY_REQUESTS, Vec::new()),
        ] {
            let error = status_error(AuthOperation::PasswordLogin, status, &body);
            assert_eq!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
        }

        for (status, code) in [
            (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            (StatusCode::FORBIDDEN, "internal_disabled"),
            (StatusCode::FORBIDDEN, "user_disabled"),
        ] {
            let body = serde_json::to_vec(&ApiErrorResponse::new(code)).expect("encode error");
            let error = status_error(AuthOperation::PasswordLogin, status, &body);
            assert_eq!(error.kind(), AuthHttpErrorKind::Rejected);
            assert_eq!(error.server_code(), Some(code));
        }

        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::METHOD_NOT_ALLOWED,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            let error = status_error(AuthOperation::PasswordLogin, status, &[]);
            assert_eq!(error.kind(), AuthHttpErrorKind::Rejected);
        }
    }

    #[test]
    fn unclassifiable_refresh_statuses_are_ambiguous() {
        for status in [
            StatusCode::SWITCHING_PROTOCOLS,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::from_u16(600).expect("non-standard status"),
        ] {
            let error = status_error(AuthOperation::Refresh, status, &[]);
            assert_eq!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
            assert_eq!(error.status(), Some(status.as_u16()));
        }

        let rejected = status_error(AuthOperation::Refresh, StatusCode::PAYLOAD_TOO_LARGE, &[]);
        assert_eq!(rejected.kind(), AuthHttpErrorKind::Rejected);
    }
}

#[cfg(all(test, feature = "session"))]
mod network_tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use zann_core::api::auth::{LoginRequest, RefreshRequest};

    use super::*;

    const PROXY_CHILD_MODE_ENV: &str = "ZANN_AUTH_PROXY_CHILD_MODE";
    const PROXY_CHILD_ORIGIN_ENV: &str = "ZANN_AUTH_PROXY_CHILD_ORIGIN";

    struct TestServer {
        endpoint: String,
        requests: Arc<AtomicUsize>,
        thread: thread::JoinHandle<()>,
    }

    struct ProbeServer {
        endpoint: String,
        requests: Arc<AtomicUsize>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        thread: thread::JoinHandle<()>,
    }

    impl ProbeServer {
        fn join(self) -> usize {
            self.stop.store(true, Ordering::SeqCst);
            self.thread.join().expect("join proxy probe");
            self.requests.load(Ordering::SeqCst)
        }
    }

    impl TestServer {
        fn join(self) -> usize {
            self.thread.join().expect("join test server");
            self.requests.load(Ordering::SeqCst)
        }
    }

    fn spawn_server(
        response: Vec<u8>,
        response_delay: Duration,
        watch_for_redirect: bool,
    ) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::clone(&requests);
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            read_http_request(&mut stream);
            request_count.fetch_add(1, Ordering::SeqCst);
            if !response_delay.is_zero() {
                thread::sleep(response_delay);
            }
            let _ = stream.write_all(&response);
            let _ = stream.flush();

            if watch_for_redirect {
                listener
                    .set_nonblocking(true)
                    .expect("make listener nonblocking");
                let deadline = Instant::now() + Duration::from_millis(250);
                while Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut redirected, _)) => {
                            read_http_request(&mut redirected);
                            request_count.fetch_add(1, Ordering::SeqCst);
                            break;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept redirected request: {error}"),
                    }
                }
            }
        });
        TestServer {
            endpoint: format!("http://{address}"),
            requests,
            thread,
        }
    }

    fn spawn_proxy_probe() -> ProbeServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy probe");
        listener
            .set_nonblocking(true)
            .expect("make proxy probe nonblocking");
        let address = listener.local_addr().expect("proxy probe address");
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::clone(&requests);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_signal = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stop_signal.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        read_http_request(&mut stream);
                        request_count.fetch_add(1, Ordering::SeqCst);
                        let response = response(
                            "502 Bad Gateway",
                            r#"{"error":"proxy_must_not_receive_loopback_auth"}"#,
                            "Content-Type: application/json\r\n",
                        );
                        let _ = stream.write_all(&response);
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept proxy probe request: {error}"),
                }
            }
        });
        ProbeServer {
            endpoint: format!("http://{address}"),
            requests,
            stop,
            thread,
        }
    }

    fn read_http_request(stream: &mut TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            let Some(headers_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let body_start = headers_end + 4;
            let headers = String::from_utf8_lossy(&request[..headers_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or_default();
            if request.len() >= body_start + content_length {
                break;
            }
        }
    }

    fn response(status: &str, body: &str, extra_headers: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn login_request(password: &str) -> LoginRequest {
        LoginRequest {
            email: "seeded-email@example.test".to_string(),
            password: password.to_string(),
            device_name: None,
            device_platform: None,
            device_fingerprint: None,
            device_os: None,
            device_os_version: None,
            device_app_version: None,
        }
    }

    #[tokio::test]
    async fn exactly_once_redirect_is_ambiguous_and_is_not_followed() {
        let server = spawn_server(
            response(
                "302 Found",
                "",
                "Location: /redirect-target\r\nContent-Type: application/json\r\n",
            ),
            Duration::ZERO,
            true,
        );
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(
            transport
                .password_login(&login_request("redirect-secret"))
                .await,
            "redirect must not be followed",
        );
        assert_eq!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
        assert_eq!(error.status(), Some(302));
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn subprocess_loopback_refresh_for_proxy_test() {
        if std::env::var(PROXY_CHILD_MODE_ENV).ok().as_deref() != Some("1") {
            return;
        }
        let endpoint = std::env::var(PROXY_CHILD_ORIGIN_ENV).expect("origin endpoint is set");
        let transport = AuthHttpTransport::new(&endpoint).expect("build loopback transport");
        let response = transport
            .refresh(&RefreshRequest {
                refresh_token: "loopback-proxy-regression-secret".to_string(),
            })
            .await
            .expect("direct loopback refresh");
        assert_eq!(response.access_token, "direct-access");
        assert_eq!(response.refresh_token, "direct-refresh");
    }

    #[test]
    fn loopback_plaintext_auth_bypasses_environment_proxy() {
        let origin = spawn_server(
            response(
                "200 OK",
                r#"{"access_token":"direct-access","refresh_token":"direct-refresh","expires_in":3600}"#,
                "Content-Type: application/json\r\n",
            ),
            Duration::ZERO,
            false,
        );
        let proxy = spawn_proxy_probe();
        let helper_name = "remote::auth::network_tests::subprocess_loopback_refresh_for_proxy_test";
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg(helper_name)
            .arg("--test-threads=1")
            .env(PROXY_CHILD_MODE_ENV, "1")
            .env(PROXY_CHILD_ORIGIN_ENV, &origin.endpoint)
            .env("HTTP_PROXY", &proxy.endpoint)
            .env("http_proxy", &proxy.endpoint)
            .env("ALL_PROXY", &proxy.endpoint)
            .env("all_proxy", &proxy.endpoint)
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .status()
            .expect("run isolated proxy helper");

        assert!(status.success(), "proxy helper failed: {status}");
        assert_eq!(origin.join(), 1, "loopback origin must receive refresh");
        assert_eq!(proxy.join(), 0, "environment proxy must receive no secret");
    }

    #[tokio::test]
    async fn missing_rotated_refresh_token_is_an_ambiguous_outcome() {
        let body = r#"{"access_token":"new-access","expires_in":3600}"#;
        let server = spawn_server(
            response("200 OK", body, "Content-Type: application/json\r\n"),
            Duration::ZERO,
            false,
        );
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(
            transport
                .refresh(&RefreshRequest {
                    refresh_token: "old-refresh-secret".to_string(),
                })
                .await,
            "missing refresh token must fail",
        );
        assert_eq!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
        assert_eq!(error.status(), Some(200));
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn oversized_exactly_once_success_is_an_ambiguous_outcome() {
        let declared = MAX_RESPONSE_BODY_BYTES + 1;
        let response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n")
                .into_bytes();
        let server = spawn_server(response, Duration::ZERO, false);
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(
            transport
                .refresh(&RefreshRequest {
                    refresh_token: "old-refresh-secret".to_string(),
                })
                .await,
            "oversized refresh response must be ambiguous",
        );
        assert_eq!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
        assert_eq!(error.status(), Some(200));
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn oversized_refresh_error_body_preserves_terminal_status_semantics() {
        for (status, expected_kind, expected_status) in [
            ("401 Unauthorized", AuthHttpErrorKind::SessionExpired, 401),
            (
                "408 Request Timeout",
                AuthHttpErrorKind::AmbiguousOutcome,
                408,
            ),
        ] {
            let declared = MAX_RESPONSE_BODY_BYTES + 1;
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
            )
            .into_bytes();
            let server = spawn_server(response, Duration::ZERO, false);
            let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
            let error = expect_auth_error(
                transport
                    .refresh(&RefreshRequest {
                        refresh_token: "old-refresh-secret".to_string(),
                    })
                    .await,
                "oversized error body must retain refresh status semantics",
            );
            assert_eq!(error.kind(), expected_kind);
            assert_eq!(error.status(), Some(expected_status));
            assert_eq!(server.join(), 1);
        }
    }

    #[tokio::test]
    async fn oversized_password_unauthorized_is_ambiguous_without_a_proven_code() {
        let declared = MAX_RESPONSE_BODY_BYTES + 1;
        let response = format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let server = spawn_server(response, Duration::ZERO, false);
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(
            transport
                .password_login(&login_request("password-secret"))
                .await,
            "oversized password rejection must remain ambiguous",
        );
        assert_eq!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
        assert_eq!(error.status(), Some(401));
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn malformed_exactly_once_success_is_an_ambiguous_outcome() {
        let server = spawn_server(
            response("200 OK", "{not-json", "Content-Type: application/json\r\n"),
            Duration::ZERO,
            false,
        );
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(
            transport
                .refresh(&RefreshRequest {
                    refresh_token: "old-refresh-secret".to_string(),
                })
                .await,
            "malformed refresh response must be ambiguous",
        );
        assert_eq!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
        assert_eq!(error.status(), Some(200));
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn truncated_exactly_once_success_is_an_ambiguous_outcome() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{"
            .to_vec();
        let server = spawn_server(response, Duration::ZERO, false);
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(
            transport
                .refresh(&RefreshRequest {
                    refresh_token: "old-refresh-secret".to_string(),
                })
                .await,
            "truncated refresh response must be ambiguous",
        );
        assert_eq!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_before_buffering() {
        let declared = MAX_RESPONSE_BODY_BYTES + 1;
        let response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n")
                .into_bytes();
        let server = spawn_server(response, Duration::ZERO, false);
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(transport.oidc_config().await, "oversized body must fail");
        assert_eq!(error.kind(), AuthHttpErrorKind::BodyTooLarge);
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn refresh_invalid_token_maps_to_session_expired() {
        let body = r#"{"error":"invalid_token","future_detail":"ignored"}"#;
        let server = spawn_server(
            response(
                "401 Unauthorized",
                body,
                "Content-Type: application/json\r\n",
            ),
            Duration::ZERO,
            false,
        );
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(
            transport
                .refresh(&RefreshRequest {
                    refresh_token: "expired-refresh-secret".to_string(),
                })
                .await,
            "refresh must fail",
        );
        assert_eq!(error.kind(), AuthHttpErrorKind::SessionExpired);
        assert_eq!(error.server_code(), Some("invalid_token"));
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn refresh_unauthorized_without_a_canonical_body_is_terminal() {
        let server = spawn_server(response("401 Unauthorized", "", ""), Duration::ZERO, false);
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(
            transport
                .refresh(&RefreshRequest {
                    refresh_token: "expired-refresh-secret".to_string(),
                })
                .await,
            "unclassified refresh 401 must fail closed",
        );
        assert_eq!(error.kind(), AuthHttpErrorKind::SessionExpired);
        assert_eq!(error.server_code(), None);
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn refresh_request_timeout_status_is_ambiguous() {
        let server = spawn_server(
            response("408 Request Timeout", "", ""),
            Duration::ZERO,
            false,
        );
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(
            transport
                .refresh(&RefreshRequest {
                    refresh_token: "refresh-secret".to_string(),
                })
                .await,
            "408 after refresh dispatch must be ambiguous",
        );
        assert_eq!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
        assert_eq!(error.status(), Some(408));
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn exactly_once_server_error_is_an_ambiguous_outcome() {
        let body = r#"{"error":"db_error"}"#;
        let server = spawn_server(
            response(
                "500 Internal Server Error",
                body,
                "Content-Type: application/json\r\n",
            ),
            Duration::ZERO,
            false,
        );
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(
            transport
                .refresh(&RefreshRequest {
                    refresh_token: "refresh-secret".to_string(),
                })
                .await,
            "server error after exactly-once dispatch is ambiguous",
        );
        assert_eq!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
        assert_eq!(error.status(), Some(500));
        assert_eq!(error.server_code(), Some("db_error"));
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn timeout_after_secret_post_has_ambiguous_outcome() {
        let server = spawn_server(
            response("200 OK", "{}", "Content-Type: application/json\r\n"),
            Duration::from_millis(250),
            false,
        );
        let transport =
            AuthHttpTransport::with_timeout(&server.endpoint, Duration::from_millis(40))
                .expect("build transport");
        let error = expect_auth_error(
            transport
                .password_login(&login_request("timeout-secret"))
                .await,
            "request must time out",
        );
        assert_eq!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn errors_never_render_request_or_reflected_secrets() {
        let password = "seeded-password-DO-NOT-LEAK";
        let body = format!(r#"{{"error":"{password}"}}"#);
        let server = spawn_server(
            response(
                "401 Unauthorized",
                &body,
                "Content-Type: application/json\r\n",
            ),
            Duration::ZERO,
            false,
        );
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let error = expect_auth_error(
            transport.password_login(&login_request(password)).await,
            "login must fail",
        );
        let display = format!("{error}");
        let debug = format!("{error:?}");
        for secret in [password, "seeded-email@example.test"] {
            assert!(!display.contains(secret));
            assert!(!debug.contains(secret));
        }
        assert_eq!(server.join(), 1);
    }

    #[tokio::test]
    async fn safe_get_connection_failure_is_not_ambiguous() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve local address");
        let address = listener.local_addr().expect("reserved address");
        drop(listener);
        let transport = AuthHttpTransport::with_timeout(
            &format!("http://{address}"),
            Duration::from_millis(250),
        )
        .expect("build transport");
        let error = expect_auth_error(
            transport.prelogin("safe-read@example.test").await,
            "connection must fail",
        );
        assert_ne!(error.kind(), AuthHttpErrorKind::AmbiguousOutcome);
        assert!(matches!(
            error.kind(),
            AuthHttpErrorKind::Timeout | AuthHttpErrorKind::Unavailable
        ));
    }

    #[tokio::test]
    async fn me_decodes_the_full_canonical_identity() {
        let user_id = "0196f4c6-42bb-7df0-bfd2-a5cb6b736a74";
        let device_id = "0196f4c6-42bb-7df0-bfd2-a5cb6b736a75";
        let body = format!(
            r#"{{"user_id":"{user_id}","email":"person@example.test","display_name":"Person","avatar_url":null,"avatar_initials":"P","groups":["admins"],"source":{{"type":"internal"}},"device_id":"{device_id}","service_account_id":null}}"#
        );
        let server = spawn_server(
            response("200 OK", &body, "Content-Type: application/json\r\n"),
            Duration::ZERO,
            false,
        );
        let transport = AuthHttpTransport::new(&server.endpoint).expect("build transport");
        let identity = transport.me("access-token-secret").await.expect("fetch me");
        assert_eq!(identity.user_id.to_string(), user_id);
        assert_eq!(
            identity.device_id.map(|id| id.to_string()).as_deref(),
            Some(device_id)
        );
        assert_eq!(identity.email, "person@example.test");
        assert_eq!(identity.groups, ["admins"]);
        assert_eq!(server.join(), 1);
    }

    #[test]
    fn bearer_authorization_header_is_marked_sensitive() {
        let header = bearer_authorization_header("access-token-secret").expect("valid header");
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains("access-token-secret"));
    }
}
