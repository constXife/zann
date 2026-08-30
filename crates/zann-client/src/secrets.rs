//! Bounded machine-secrets HTTP capability.
//!
//! The client owns endpoint construction, bearer handling, response bounds and
//! error sanitization. Callers receive typed wire responses but never raw
//! response bodies or request builders.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;

use chrono::DateTime;
use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::{RequestBuilder, StatusCode, Url};
use serde::de::DeserializeOwned;
use uuid::Uuid;
use zeroize::Zeroizing;

use zann_core::api::secrets::ErrorResponse;
pub use zann_core::api::secrets::{
    BatchEnsureRequest, BatchGetRequest, BatchResult, RotateAbortRequest, RotateStartRequest,
    RotationCandidateResponse, RotationCommitResponse, RotationStatusResponse, SecretListResponse,
    SecretRequest, SecretResponse, SecretSetRequest, SecretSummary,
};

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ACCESS_TOKEN_BYTES: usize = 64 * 1024;
pub const MAX_SECRET_VALUE_BYTES: usize = 256 * 1024;
pub const MAX_BATCH_SECRETS: usize = 64;
pub const MAX_SECRET_LIST_LIMIT: usize = 100;
// A server plaintext item is capped at 256 KiB. JSON escaping can expand a
// valid string by up to six bytes per input byte, so keep a bounded 2 MiB
// envelope rather than rejecting a valid worst-case response.
const MAX_SECRET_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_BATCH_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SECRET_LIST_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CURSOR_BYTES: usize = 1024;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_ROTATION_REASON_BYTES: usize = 1024;
const MAX_SECRET_PATH_BYTES: usize = 500;
const MAX_SECRET_PATH_SEGMENTS: usize = 32;
const MAX_SECRET_PATH_SEGMENT_BYTES: usize = 200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretsTransportSecurity {
    RequireTls,
    AllowLoopbackHttp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretOperation {
    Configure,
    List,
    Get,
    GetPrevious,
    Set,
    Ensure,
    Rotate,
    BatchGet,
    BatchEnsure,
    RotationStart,
    RotationStatus,
    RotationCandidate,
    RotationRecover,
    RotationCommit,
    RotationAbort,
}

impl fmt::Display for SecretOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configure => "configure",
            Self::List => "list",
            Self::Get => "get",
            Self::GetPrevious => "get_previous",
            Self::Set => "set",
            Self::Ensure => "ensure",
            Self::Rotate => "rotate",
            Self::BatchGet => "batch_get",
            Self::BatchEnsure => "batch_ensure",
            Self::RotationStart => "rotation_start",
            Self::RotationStatus => "rotation_status",
            Self::RotationCandidate => "rotation_candidate",
            Self::RotationRecover => "rotation_recover",
            Self::RotationCommit => "rotation_commit",
            Self::RotationAbort => "rotation_abort",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretsClientErrorKind {
    InvalidEndpoint,
    InvalidInput,
    InsecureTransport,
    Timeout,
    Unavailable,
    Protocol,
    BodyTooLarge,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Rejected,
    Server,
}

impl fmt::Display for SecretsClientErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::InvalidInput => "invalid_input",
            Self::InsecureTransport => "insecure_transport",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::Protocol => "protocol",
            Self::BodyTooLarge => "body_too_large",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Rejected => "rejected",
            Self::Server => "server",
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretsClientError {
    operation: SecretOperation,
    kind: SecretsClientErrorKind,
    status: Option<u16>,
    server_code: Option<&'static str>,
}

impl SecretsClientError {
    const fn new(operation: SecretOperation, kind: SecretsClientErrorKind) -> Self {
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

    #[must_use]
    pub const fn operation(&self) -> SecretOperation {
        self.operation
    }

    #[must_use]
    pub const fn kind(&self) -> SecretsClientErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.status
    }

    #[must_use]
    pub const fn server_code(&self) -> Option<&'static str> {
        self.server_code
    }
}

impl fmt::Debug for SecretsClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretsClientError")
            .field("operation", &self.operation)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("server_code", &self.server_code)
            .finish()
    }
}

impl fmt::Display for SecretsClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "machine_secrets:{}:{}",
            self.operation, self.kind
        )?;
        if let Some(status) = self.status {
            write!(formatter, ":status_{status}")?;
        }
        if let Some(code) = self.server_code {
            write!(formatter, ":{code}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SecretsClientError {}

pub struct SecretsClient {
    client: reqwest::Client,
    base_url: Url,
    access_token: Zeroizing<String>,
    request_timeout: Duration,
}

impl fmt::Debug for SecretsClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretsClient")
            .field("base_url", &self.base_url)
            .field("access_token", &"<redacted>")
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl SecretsClient {
    pub fn new(
        endpoint: &str,
        access_token: impl Into<String>,
        security: SecretsTransportSecurity,
    ) -> Result<Self, SecretsClientError> {
        let base_url = canonical_base_url(endpoint)?;
        let loopback_http = base_url.scheme() == "http"
            && endpoint_is_loopback(&base_url)
            && security == SecretsTransportSecurity::AllowLoopbackHttp;
        if base_url.scheme() != "https" && !loopback_http {
            return Err(SecretsClientError::new(
                SecretOperation::Configure,
                SecretsClientErrorKind::InsecureTransport,
            ));
        }

        let access_token = Zeroizing::new(access_token.into());
        if access_token.trim().is_empty() || access_token.len() > MAX_ACCESS_TOKEN_BYTES {
            return Err(SecretsClientError::new(
                SecretOperation::Configure,
                SecretsClientErrorKind::InvalidInput,
            ));
        }

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .connect_timeout(DEFAULT_REQUEST_TIMEOUT);
        if loopback_http {
            builder = builder.no_proxy();
        }
        let client = builder.build().map_err(|_| {
            SecretsClientError::new(
                SecretOperation::Configure,
                SecretsClientErrorKind::InvalidEndpoint,
            )
        })?;

        Ok(Self {
            client,
            base_url,
            access_token,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    pub async fn get(&self, vault: &str, path: &str) -> Result<SecretResponse, SecretsClientError> {
        self.get_version(vault, path, false).await
    }

    pub async fn get_previous(
        &self,
        vault: &str,
        path: &str,
    ) -> Result<SecretResponse, SecretsClientError> {
        self.get_version(vault, path, true).await
    }

    async fn get_version(
        &self,
        vault: &str,
        path: &str,
        previous: bool,
    ) -> Result<SecretResponse, SecretsClientError> {
        let operation = if previous {
            SecretOperation::GetPrevious
        } else {
            SecretOperation::Get
        };
        let mut url = self.secret_path_url(operation, vault, path)?;
        if previous {
            url.query_pairs_mut().append_pair("version", "previous");
        }
        let request = self
            .client
            .get(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout);
        let response = self.execute_json(operation, request).await?;
        validate_secret_response(operation, path, &response)?;
        Ok(response)
    }

    pub async fn list(
        &self,
        vault: &str,
        prefix: Option<&str>,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<SecretListResponse, SecretsClientError> {
        let operation = SecretOperation::List;
        if !(1..=MAX_SECRET_LIST_LIMIT).contains(&limit) {
            return Err(SecretsClientError::new(
                operation,
                SecretsClientErrorKind::InvalidInput,
            ));
        }
        let prefix = normalize_secret_prefix(operation, prefix)?;
        let cursor = validate_cursor(operation, cursor)?;
        let mut url = self.action_url(operation, vault, &[])?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(prefix) = prefix.as_deref() {
                query.append_pair("prefix", prefix);
            }
            query.append_pair("limit", &limit.to_string());
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
        }
        let request = self
            .client
            .get(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout);
        let response: SecretListResponse = self
            .execute_json_with_limit(operation, request, MAX_SECRET_LIST_RESPONSE_BYTES)
            .await?;
        validate_list_response(operation, limit, &response)?;
        Ok(response)
    }

    pub async fn ensure(
        &self,
        vault: &str,
        path: &str,
        policy: Option<&str>,
        meta: Option<HashMap<String, String>>,
    ) -> Result<SecretResponse, SecretsClientError> {
        let operation = SecretOperation::Ensure;
        let normalized_path = normalize_secret_path(operation, path)?;
        let url = self.ensure_url(operation, vault)?;
        let payload = SecretRequest {
            path: normalized_path,
            policy: policy.map(str::to_string),
            meta,
        };
        let request = self
            .client
            .post(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout)
            .json(&payload);
        let response = self.execute_json(operation, request).await?;
        validate_secret_response(operation, path, &response)?;
        Ok(response)
    }

    pub async fn rotate(
        &self,
        vault: &str,
        path: &str,
        policy: Option<&str>,
        meta: Option<HashMap<String, String>>,
    ) -> Result<SecretResponse, SecretsClientError> {
        let operation = SecretOperation::Rotate;
        let normalized_path = normalize_secret_path(operation, path)?;
        let url = self.action_url(operation, vault, &["rotate"])?;
        let payload = SecretRequest {
            path: normalized_path,
            policy: policy.map(str::to_string),
            meta,
        };
        let request = self
            .client
            .post(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout)
            .json(&payload);
        let response = self.execute_json(operation, request).await?;
        validate_secret_response(operation, path, &response)?;
        Ok(response)
    }

    pub async fn batch_get(
        &self,
        vault: &str,
        paths: &[String],
    ) -> Result<Vec<BatchResult>, SecretsClientError> {
        let operation = SecretOperation::BatchGet;
        validate_batch_count(operation, paths.len())?;
        let paths = paths
            .iter()
            .map(|path| normalize_secret_path(operation, path))
            .collect::<Result<Vec<_>, _>>()?;
        let url = self.action_url(operation, vault, &["batch", "get"])?;
        let payload = BatchGetRequest {
            paths: paths.clone(),
        };
        let request = self
            .client
            .post(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout)
            .json(&payload);
        let response: Vec<BatchResult> = self
            .execute_json_with_limit(operation, request, MAX_BATCH_RESPONSE_BYTES)
            .await?;
        validate_batch_response(operation, &paths, &response)?;
        Ok(response)
    }

    pub async fn batch_ensure(
        &self,
        vault: &str,
        mut secrets: Vec<SecretRequest>,
    ) -> Result<Vec<BatchResult>, SecretsClientError> {
        let operation = SecretOperation::BatchEnsure;
        validate_batch_count(operation, secrets.len())?;
        for secret in &mut secrets {
            secret.path = normalize_secret_path(operation, &secret.path)?;
        }
        let expected_paths = secrets
            .iter()
            .map(|secret| secret.path.clone())
            .collect::<Vec<_>>();
        let url = self.action_url(operation, vault, &["batch", "ensure"])?;
        let payload = BatchEnsureRequest { secrets };
        let request = self
            .client
            .post(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout)
            .json(&payload);
        let response: Vec<BatchResult> = self
            .execute_json_with_limit(operation, request, MAX_BATCH_RESPONSE_BYTES)
            .await?;
        validate_batch_response(operation, &expected_paths, &response)?;
        Ok(response)
    }

    pub async fn set(
        &self,
        vault: &str,
        path: &str,
        payload: &SecretSetRequest,
    ) -> Result<SecretResponse, SecretsClientError> {
        let operation = SecretOperation::Set;
        if payload.value.len() > MAX_SECRET_VALUE_BYTES {
            return Err(SecretsClientError::new(
                operation,
                SecretsClientErrorKind::InvalidInput,
            ));
        }
        let url = self.secret_path_url(operation, vault, path)?;
        let request = self
            .client
            .put(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout)
            .json(payload);
        let response = self.execute_json(operation, request).await?;
        validate_secret_response(operation, path, &response)?;
        Ok(response)
    }

    pub async fn rotation_start(
        &self,
        item_id: Uuid,
        policy: Option<&str>,
    ) -> Result<RotationCandidateResponse, SecretsClientError> {
        let operation = SecretOperation::RotationStart;
        validate_optional_text(operation, policy, MAX_SECRET_PATH_SEGMENT_BYTES)?;
        let url = self.rotation_url(operation, item_id, "start")?;
        let payload = RotateStartRequest {
            policy: policy.map(str::to_string),
        };
        let request = self
            .client
            .post(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout)
            .json(&payload);
        let response = self.execute_json(operation, request).await?;
        validate_candidate_response(operation, &response, "rotating", true)?;
        Ok(response)
    }

    pub async fn rotation_status(
        &self,
        item_id: Uuid,
    ) -> Result<RotationStatusResponse, SecretsClientError> {
        let operation = SecretOperation::RotationStatus;
        let url = self.rotation_url(operation, item_id, "status")?;
        let request = self
            .client
            .get(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout);
        let response = self.execute_json(operation, request).await?;
        validate_rotation_status(operation, &response)?;
        Ok(response)
    }

    pub async fn rotation_candidate(
        &self,
        item_id: Uuid,
    ) -> Result<RotationCandidateResponse, SecretsClientError> {
        self.fetch_rotation_candidate(
            SecretOperation::RotationCandidate,
            item_id,
            "candidate",
            "rotating",
        )
        .await
    }

    pub async fn rotation_recover(
        &self,
        item_id: Uuid,
    ) -> Result<RotationCandidateResponse, SecretsClientError> {
        self.fetch_rotation_candidate(
            SecretOperation::RotationRecover,
            item_id,
            "recover",
            "stale",
        )
        .await
    }

    async fn fetch_rotation_candidate(
        &self,
        operation: SecretOperation,
        item_id: Uuid,
        action: &str,
        expected_state: &str,
    ) -> Result<RotationCandidateResponse, SecretsClientError> {
        let url = self.rotation_url(operation, item_id, action)?;
        let request = self
            .client
            .post(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout);
        let response = self.execute_json(operation, request).await?;
        validate_candidate_response(operation, &response, expected_state, false)?;
        Ok(response)
    }

    pub async fn rotation_commit(
        &self,
        item_id: Uuid,
    ) -> Result<RotationCommitResponse, SecretsClientError> {
        let operation = SecretOperation::RotationCommit;
        let url = self.rotation_url(operation, item_id, "commit")?;
        let request = self
            .client
            .post(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout);
        let response: RotationCommitResponse = self.execute_json(operation, request).await?;
        if response.status != "committed" || response.version < 1 {
            return Err(SecretsClientError::new(
                operation,
                SecretsClientErrorKind::Protocol,
            ));
        }
        Ok(response)
    }

    pub async fn rotation_abort(
        &self,
        item_id: Uuid,
        reason: Option<&str>,
        force: bool,
    ) -> Result<RotationStatusResponse, SecretsClientError> {
        let operation = SecretOperation::RotationAbort;
        validate_optional_text(operation, reason, MAX_ROTATION_REASON_BYTES)?;
        let url = self.rotation_url(operation, item_id, "abort")?;
        let payload = RotateAbortRequest {
            reason: reason.map(str::to_string),
            force,
        };
        let request = self
            .client
            .post(url)
            .header(AUTHORIZATION, self.authorization_header(operation)?)
            .timeout(self.request_timeout)
            .json(&payload);
        let response = self.execute_json(operation, request).await?;
        validate_rotation_status(operation, &response)?;
        Ok(response)
    }

    async fn execute_json<T>(
        &self,
        operation: SecretOperation,
        request: RequestBuilder,
    ) -> Result<T, SecretsClientError>
    where
        T: DeserializeOwned,
    {
        self.execute_json_with_limit(operation, request, MAX_SECRET_RESPONSE_BYTES)
            .await
    }

    async fn execute_json_with_limit<T>(
        &self,
        operation: SecretOperation,
        request: RequestBuilder,
        max_response_bytes: usize,
    ) -> Result<T, SecretsClientError>
    where
        T: DeserializeOwned,
    {
        let response = request
            .send()
            .await
            .map_err(|error| request_error(operation, &error))?;
        let (status, body) = read_bounded_body(operation, response, max_response_bytes).await?;
        if !status.is_success() {
            return Err(status_error(operation, status, &body));
        }
        serde_json::from_slice(&body).map_err(|_| {
            SecretsClientError::new(operation, SecretsClientErrorKind::Protocol).with_status(status)
        })
    }

    fn secret_path_url(
        &self,
        operation: SecretOperation,
        vault: &str,
        path: &str,
    ) -> Result<Url, SecretsClientError> {
        let vault = validate_vault(operation, vault)?;
        let path = normalize_secret_path(operation, path)?;
        let mut url = self.base_url.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|_| {
                SecretsClientError::new(operation, SecretsClientErrorKind::InvalidEndpoint)
            })?;
            segments.extend(["v1", "vaults", vault, "secrets"]);
            segments.extend(path.split('/'));
        }
        Ok(url)
    }

    fn ensure_url(
        &self,
        operation: SecretOperation,
        vault: &str,
    ) -> Result<Url, SecretsClientError> {
        self.action_url(operation, vault, &["ensure"])
    }

    fn action_url(
        &self,
        operation: SecretOperation,
        vault: &str,
        action: &[&str],
    ) -> Result<Url, SecretsClientError> {
        let vault = validate_vault(operation, vault)?;
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| {
                SecretsClientError::new(operation, SecretsClientErrorKind::InvalidEndpoint)
            })?
            .extend(["v1", "vaults", vault, "secrets"])
            .extend(action.iter().copied());
        Ok(url)
    }

    fn rotation_url(
        &self,
        operation: SecretOperation,
        item_id: Uuid,
        action: &str,
    ) -> Result<Url, SecretsClientError> {
        if item_id.is_nil() {
            return Err(SecretsClientError::new(
                operation,
                SecretsClientErrorKind::InvalidInput,
            ));
        }
        let item_id = item_id.to_string();
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| {
                SecretsClientError::new(operation, SecretsClientErrorKind::InvalidEndpoint)
            })?
            .extend(["v1", "shared", "items", item_id.as_str(), "rotate", action]);
        Ok(url)
    }

    fn authorization_header(
        &self,
        operation: SecretOperation,
    ) -> Result<HeaderValue, SecretsClientError> {
        let encoded = Zeroizing::new(format!("Bearer {}", self.access_token.as_str()));
        let mut header = HeaderValue::from_str(encoded.as_str()).map_err(|_| {
            SecretsClientError::new(operation, SecretsClientErrorKind::InvalidInput)
        })?;
        header.set_sensitive(true);
        Ok(header)
    }
}

fn canonical_base_url(endpoint: &str) -> Result<Url, SecretsClientError> {
    let invalid = || {
        SecretsClientError::new(
            SecretOperation::Configure,
            SecretsClientErrorKind::InvalidEndpoint,
        )
    };
    let mut url = Url::parse(endpoint).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(invalid());
    }
    url.set_path("/");
    Ok(url)
}

fn endpoint_is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn validate_vault(operation: SecretOperation, vault: &str) -> Result<&str, SecretsClientError> {
    let vault = vault.trim();
    if vault.is_empty() || vault.contains('/') {
        return Err(SecretsClientError::new(
            operation,
            SecretsClientErrorKind::InvalidInput,
        ));
    }
    Ok(vault)
}

fn normalize_secret_path(
    operation: SecretOperation,
    path: &str,
) -> Result<String, SecretsClientError> {
    let path = path.trim().trim_matches('/');
    let segments = path.split('/').collect::<Vec<_>>();
    if path.is_empty()
        || path.len() > MAX_SECRET_PATH_BYTES
        || segments.len() > MAX_SECRET_PATH_SEGMENTS
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.len() > MAX_SECRET_PATH_SEGMENT_BYTES
                || segment.starts_with('.')
                || segment.trim() != *segment
                || segment.chars().any(char::is_control)
        })
    {
        return Err(SecretsClientError::new(
            operation,
            SecretsClientErrorKind::InvalidInput,
        ));
    }
    Ok(path.to_string())
}

fn normalize_secret_prefix(
    operation: SecretOperation,
    prefix: Option<&str>,
) -> Result<Option<String>, SecretsClientError> {
    let Some(prefix) = prefix else {
        return Ok(None);
    };
    let prefix = prefix.trim().trim_matches('/');
    if prefix.is_empty() {
        return Ok(None);
    }
    normalize_secret_path(operation, prefix).map(Some)
}

fn validate_cursor(
    operation: SecretOperation,
    cursor: Option<&str>,
) -> Result<Option<&str>, SecretsClientError> {
    if cursor.is_some_and(|cursor| {
        cursor.is_empty() || cursor.len() > MAX_CURSOR_BYTES || cursor.chars().any(char::is_control)
    }) {
        return Err(SecretsClientError::new(
            operation,
            SecretsClientErrorKind::InvalidInput,
        ));
    }
    Ok(cursor)
}

fn validate_list_response(
    operation: SecretOperation,
    limit: usize,
    response: &SecretListResponse,
) -> Result<(), SecretsClientError> {
    if response.secrets.len() > limit
        || validate_cursor(operation, response.next_cursor.as_deref()).is_err()
    {
        return Err(SecretsClientError::new(
            operation,
            SecretsClientErrorKind::Protocol,
        ));
    }
    let mut paths = HashSet::with_capacity(response.secrets.len());
    for secret in &response.secrets {
        let normalized = normalize_secret_path(operation, &secret.path)
            .map_err(|_| SecretsClientError::new(operation, SecretsClientErrorKind::Protocol))?;
        if secret.path != format!("/{normalized}")
            || secret.version < 1
            || !is_utc_rfc3339(&secret.updated_at)
            || !paths.insert(normalized)
        {
            return Err(SecretsClientError::new(
                operation,
                SecretsClientErrorKind::Protocol,
            ));
        }
    }
    Ok(())
}

fn validate_secret_response(
    operation: SecretOperation,
    expected_path: &str,
    response: &SecretResponse,
) -> Result<(), SecretsClientError> {
    let expected = normalize_secret_path(operation, expected_path)?;
    let item_id = Uuid::parse_str(&response.item_id).ok();
    let valid_item_id =
        item_id.is_some_and(|item_id| !item_id.is_nil() && item_id.to_string() == response.item_id);
    if !valid_item_id
        || response.path != format!("/{expected}")
        || response.version < 1
        || response.value.len() > MAX_SECRET_VALUE_BYTES
        || response.policy.is_empty()
        || response.policy.len() > MAX_SECRET_PATH_SEGMENT_BYTES
        || response.policy.chars().any(char::is_control)
    {
        return Err(SecretsClientError::new(
            operation,
            SecretsClientErrorKind::Protocol,
        ));
    }
    Ok(())
}

fn validate_optional_text(
    operation: SecretOperation,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<(), SecretsClientError> {
    if value.is_some_and(|value| {
        value.is_empty()
            || value.len() > max_bytes
            || value.trim() != value
            || value.chars().any(char::is_control)
    }) {
        return Err(SecretsClientError::new(
            operation,
            SecretsClientErrorKind::InvalidInput,
        ));
    }
    Ok(())
}

fn validate_candidate_response(
    operation: SecretOperation,
    response: &RotationCandidateResponse,
    expected_state: &str,
    require_expiry: bool,
) -> Result<(), SecretsClientError> {
    let expires_valid = response.expires_at.as_deref().is_none_or(is_utc_rfc3339);
    let recover_valid = response.recover_until.as_deref().is_none_or(is_utc_rfc3339);
    if response.state != expected_state
        || response.candidate.as_str().is_empty()
        || response.candidate.as_str().len() > MAX_SECRET_VALUE_BYTES
        || response.previous_version < 1
        || !expires_valid
        || !recover_valid
        || (require_expiry && response.expires_at.is_none())
    {
        return Err(SecretsClientError::new(
            operation,
            SecretsClientErrorKind::Protocol,
        ));
    }
    Ok(())
}

fn validate_rotation_status(
    operation: SecretOperation,
    response: &RotationStatusResponse,
) -> Result<(), SecretsClientError> {
    let timestamps_valid = [
        response.started_at.as_deref(),
        response.expires_at.as_deref(),
        response.recover_until.as_deref(),
    ]
    .into_iter()
    .flatten()
    .all(is_utc_rfc3339);
    let started_by_valid = response.started_by.as_deref().is_none_or(|value| {
        Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
    });
    let reason_valid = response.aborted_reason.as_deref().is_none_or(|value| {
        value.len() <= MAX_ROTATION_REASON_BYTES && !value.chars().any(char::is_control)
    });
    if !matches!(
        response.state.as_str(),
        "idle" | "active" | "rotating" | "stale"
    ) || !timestamps_valid
        || !started_by_valid
        || !reason_valid
    {
        return Err(SecretsClientError::new(
            operation,
            SecretsClientErrorKind::Protocol,
        ));
    }
    Ok(())
}

fn is_utc_rfc3339(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_TIMESTAMP_BYTES
        || value.trim() != value
        || !value.contains('T')
        || !(value.ends_with('Z') || value.ends_with("+00:00"))
    {
        return false;
    }
    DateTime::parse_from_rfc3339(value).is_ok_and(|parsed| parsed.offset().local_minus_utc() == 0)
}

fn validate_batch_count(
    operation: SecretOperation,
    count: usize,
) -> Result<(), SecretsClientError> {
    if count == 0 || count > MAX_BATCH_SECRETS {
        return Err(SecretsClientError::new(
            operation,
            SecretsClientErrorKind::InvalidInput,
        ));
    }
    Ok(())
}

fn validate_batch_response(
    operation: SecretOperation,
    expected_paths: &[String],
    response: &[BatchResult],
) -> Result<(), SecretsClientError> {
    if response.len() != expected_paths.len() {
        return Err(SecretsClientError::new(
            operation,
            SecretsClientErrorKind::Protocol,
        ));
    }
    for (result, expected) in response.iter().zip(expected_paths) {
        if result.path.trim_matches('/') != expected {
            return Err(SecretsClientError::new(
                operation,
                SecretsClientErrorKind::Protocol,
            ));
        }
        let shape_is_valid = match (operation, result.status.as_str()) {
            (SecretOperation::BatchGet, "ok")
            | (SecretOperation::BatchEnsure, "created" | "existing") => {
                result.secret.as_ref().is_some_and(|secret| {
                    validate_secret_response(operation, expected, secret).is_ok()
                        && result.error.is_none()
                })
            }
            (SecretOperation::BatchGet | SecretOperation::BatchEnsure, "error") => {
                result.secret.is_none() && result.error.is_some()
            }
            _ => false,
        };
        if !shape_is_valid {
            return Err(SecretsClientError::new(
                operation,
                SecretsClientErrorKind::Protocol,
            ));
        }
    }
    Ok(())
}

fn request_error(operation: SecretOperation, error: &reqwest::Error) -> SecretsClientError {
    let kind = if error.is_timeout() {
        SecretsClientErrorKind::Timeout
    } else {
        SecretsClientErrorKind::Unavailable
    };
    SecretsClientError::new(operation, kind)
}

async fn read_bounded_body(
    operation: SecretOperation,
    mut response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<(StatusCode, Zeroizing<Vec<u8>>), SecretsClientError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(
            SecretsClientError::new(operation, SecretsClientErrorKind::BodyTooLarge)
                .with_status(status),
        );
    }

    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default()
        .min(max_response_bytes);
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| request_error(operation, &error))?
    {
        let next_length = body.len().checked_add(chunk.len()).ok_or_else(|| {
            SecretsClientError::new(operation, SecretsClientErrorKind::BodyTooLarge)
                .with_status(status)
        })?;
        if next_length > max_response_bytes {
            return Err(
                SecretsClientError::new(operation, SecretsClientErrorKind::BodyTooLarge)
                    .with_status(status),
            );
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

fn status_error(operation: SecretOperation, status: StatusCode, body: &[u8]) -> SecretsClientError {
    let kind = match status {
        StatusCode::BAD_REQUEST => SecretsClientErrorKind::Rejected,
        StatusCode::UNAUTHORIZED => SecretsClientErrorKind::Unauthorized,
        StatusCode::FORBIDDEN => SecretsClientErrorKind::Forbidden,
        StatusCode::NOT_FOUND => SecretsClientErrorKind::NotFound,
        StatusCode::CONFLICT => SecretsClientErrorKind::Conflict,
        StatusCode::PAYLOAD_TOO_LARGE => SecretsClientErrorKind::BodyTooLarge,
        status if status.is_server_error() => SecretsClientErrorKind::Server,
        _ => SecretsClientErrorKind::Protocol,
    };
    let server_code = serde_json::from_slice::<ErrorResponse>(body)
        .ok()
        .and_then(|response| known_server_code(&response.error));
    SecretsClientError::new(operation, kind)
        .with_status(status)
        .with_server_code(server_code)
}

fn known_server_code(code: &str) -> Option<&'static str> {
    Some(match code {
        "vault_not_server_encrypted" => "vault_not_server_encrypted",
        "unknown_policy" => "unknown_policy",
        "policy_mismatch" => "policy_mismatch",
        "path_empty" => "path_empty",
        "path_too_long" => "path_too_long",
        "path_invalid" => "path_invalid",
        "invalid_path" => "invalid_path",
        "invalid_cursor" => "invalid_cursor",
        "invalid_name" => "invalid_name",
        "invalid_type" => "invalid_type",
        "invalid_version" => "invalid_version",
        "invalid_payload" => "invalid_payload",
        "not_found" => "not_found",
        "forbidden" => "forbidden",
        "path_in_use" => "path_in_use",
        "concurrent_create" => "concurrent_create",
        "row_version_conflict" => "row_version_conflict",
        "batch_too_large" => "batch_too_large",
        "payload_too_large" => "payload_too_large",
        "secret_payload_too_large" => "secret_payload_too_large",
        "db_error" => "db_error",
        "decode_failed" => "decode_failed",
        "payload_decrypt_failed" => "payload_decrypt_failed",
        "payload_encode_failed" => "payload_encode_failed",
        "payload_encrypt_failed" => "payload_encrypt_failed",
        "smk_missing" => "smk_missing",
        "vault_key_decrypt_failed" => "vault_key_decrypt_failed",
        "no_changes" => "no_changes",
        "invalid_password" => "invalid_password",
        "invalid_credentials" => "invalid_credentials",
        "kdf_error" => "kdf_error",
        "device_required" => "device_required",
        "rotation_in_progress" => "rotation_in_progress",
        "rotation_not_active" => "rotation_not_active",
        "rotation_active" => "rotation_active",
        "rotation_expired" => "rotation_expired",
        "rotation_invalid_state" => "rotation_invalid_state",
        "rotation_conflict" => "rotation_conflict",
        "rotation_missing" => "rotation_missing",
        "password_field_missing" => "password_field_missing",
        "password_field_ambiguous" => "password_field_ambiguous",
        "version_conflict" => "version_conflict",
        "history_conflict" => "history_conflict",
        "invalid_abort_reason" => "invalid_abort_reason",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Matcher, Server};
    use serde_json::json;

    fn response_body(path: &str, value: &str) -> String {
        json!({
            "item_id": "00000000-0000-0000-0000-000000000001",
            "path": path,
            "vault_id": "vault-id",
            "value": value,
            "policy": "default",
            "version": 1
        })
        .to_string()
    }

    #[test]
    fn transport_only_allows_plaintext_for_explicit_loopback() {
        for security in [
            SecretsTransportSecurity::RequireTls,
            SecretsTransportSecurity::AllowLoopbackHttp,
        ] {
            let error = SecretsClient::new("http://example.com", "access-token", security)
                .expect_err("remote plaintext transport must be rejected");
            assert_eq!(error.kind(), SecretsClientErrorKind::InsecureTransport);
        }

        let error = SecretsClient::new(
            "http://127.0.0.1:8080",
            "access-token",
            SecretsTransportSecurity::RequireTls,
        )
        .expect_err("loopback plaintext transport must be explicit");
        assert_eq!(error.kind(), SecretsClientErrorKind::InsecureTransport);

        SecretsClient::new(
            "http://127.0.0.1:8080",
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("explicit loopback plaintext transport");
    }

    #[tokio::test]
    async fn get_encodes_path_segments_and_sends_sensitive_bearer() {
        let mut server = Server::new_async().await;
        server
            .mock(
                "GET",
                "/v1/vaults/infra/secrets/services/db%20prod/%23primary",
            )
            .match_header("authorization", "Bearer access-token")
            .with_status(200)
            .with_body(response_body("/services/db prod/#primary", "secret-value"))
            .create_async()
            .await;

        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let response = client
            .get("infra", "services/db prod/#primary")
            .await
            .expect("get secret");
        assert_eq!(response.value, "secret-value");
        assert!(!format!("{client:?}").contains("access-token"));
    }

    #[tokio::test]
    async fn list_returns_only_bounded_metadata_and_preserves_cursor() {
        let mut server = Server::new_async().await;
        server
            .mock("GET", "/v1/vaults/infra/secrets")
            .match_header("authorization", "Bearer access-token")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("prefix".into(), "services/api".into()),
                Matcher::UrlEncoded("limit".into(), "2".into()),
                Matcher::UrlEncoded("cursor".into(), "opaque|cursor".into()),
            ]))
            .with_status(200)
            .with_body(
                json!({
                    "secrets": [{
                        "path": "/services/api/database",
                        "version": 3,
                        "updated_at": "2026-08-29T12:00:00Z"
                    }],
                    "next_cursor": "next|cursor"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let response = client
            .list("infra", Some("/services/api/"), 2, Some("opaque|cursor"))
            .await
            .expect("list secrets");

        assert_eq!(response.secrets.len(), 1);
        assert_eq!(response.secrets[0].path, "/services/api/database");
        assert_eq!(response.next_cursor.as_deref(), Some("next|cursor"));
        let output = serde_json::to_value(response).expect("serialize response");
        assert!(output["secrets"][0].get("value").is_none());
    }

    #[tokio::test]
    async fn list_rejects_invalid_limits_and_response_shapes() {
        let client = SecretsClient::new(
            "https://zann.example.test",
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        for limit in [0, MAX_SECRET_LIST_LIMIT + 1] {
            let error = client
                .list("infra", None, limit, None)
                .await
                .expect_err("invalid list limit");
            assert_eq!(error.kind(), SecretsClientErrorKind::InvalidInput);
        }

        let mut server = Server::new_async().await;
        server
            .mock("GET", "/v1/vaults/infra/secrets")
            .match_query(Matcher::UrlEncoded("limit".into(), "2".into()))
            .with_status(200)
            .with_body(
                json!({
                    "secrets": [
                        {"path": "/duplicate", "version": 1, "updated_at": "2026-08-29T12:00:00Z"},
                        {"path": "/duplicate", "version": 1, "updated_at": "2026-08-29T12:00:00Z"}
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;
        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let error = client
            .list("infra", None, 2, None)
            .await
            .expect_err("duplicate path");
        assert_eq!(error.kind(), SecretsClientErrorKind::Protocol);
    }

    #[tokio::test]
    async fn list_rejects_non_rfc3339_timestamps() {
        let mut server = Server::new_async().await;
        server
            .mock("GET", "/v1/vaults/infra/secrets")
            .match_query(Matcher::UrlEncoded("limit".into(), "1".into()))
            .with_status(200)
            .with_body(
                json!({
                    "secrets": [
                        {"path": "/database", "version": 1, "updated_at": "now"}
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;
        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");

        let error = client
            .list("infra", None, 1, None)
            .await
            .expect_err("invalid timestamp");
        assert_eq!(error.kind(), SecretsClientErrorKind::Protocol);
    }

    #[tokio::test]
    async fn ensure_uses_canonical_contract() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/v1/vaults/infra/secrets/ensure")
            .match_header("authorization", "Bearer access-token")
            .match_body(Matcher::Json(json!({
                "path": "services/api/database",
                "policy": "strong",
                "meta": {"owner": "platform"}
            })))
            .with_status(200)
            .with_body(response_body("/services/api/database", "generated-value"))
            .create_async()
            .await;

        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let response = client
            .ensure(
                "infra",
                "/services/api/database/",
                Some("strong"),
                Some(HashMap::from([(
                    "owner".to_string(),
                    "platform".to_string(),
                )])),
            )
            .await
            .expect("ensure secret");
        assert_eq!(response.value, "generated-value");
    }

    #[tokio::test]
    async fn set_preserves_the_exact_secret_value() {
        let mut server = Server::new_async().await;
        server
            .mock("PUT", "/v1/vaults/infra/secrets/services/api/database")
            .match_header("authorization", "Bearer access-token")
            .match_body(Matcher::Json(json!({
                "value": "line one\nline two\n",
                "policy": "strong",
                "meta": null
            })))
            .with_status(200)
            .with_body(response_body(
                "/services/api/database",
                "line one\nline two\n",
            ))
            .create_async()
            .await;

        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let payload = SecretSetRequest {
            value: "line one\nline two\n".to_string(),
            policy: Some("strong".to_string()),
            meta: None,
        };
        let response = client
            .set("infra", "services/api/database", &payload)
            .await
            .expect("set secret");
        assert_eq!(response.value, "line one\nline two\n");
        assert!(!format!("{payload:?}").contains("line one"));
    }

    #[tokio::test]
    async fn rotate_returns_the_new_and_previous_versions() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/v1/vaults/infra/secrets/rotate")
            .match_header("authorization", "Bearer access-token")
            .match_body(Matcher::Json(json!({
                "path": "services/api/database",
                "policy": "strong",
                "meta": null
            })))
            .with_status(200)
            .with_body(
                json!({
                    "item_id": "00000000-0000-0000-0000-000000000001",
                    "path": "/services/api/database",
                    "vault_id": "vault-id",
                    "value": "rotated-value",
                    "policy": "strong",
                    "version": 4,
                    "previous_version": 3
                })
                .to_string(),
            )
            .create_async()
            .await;

        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let response = client
            .rotate("infra", "/services/api/database/", Some("strong"), None)
            .await
            .expect("rotate secret");
        assert_eq!(response.value, "rotated-value");
        assert_eq!(response.version, 4);
        assert_eq!(response.previous_version, Some(3));
    }

    #[tokio::test]
    async fn previous_read_and_coordinated_rotation_use_canonical_contracts() {
        let item_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid");
        let mut server = Server::new_async().await;
        server
            .mock("GET", "/v1/vaults/infra/secrets/services/api/database")
            .match_query(Matcher::UrlEncoded("version".into(), "previous".into()))
            .with_status(200)
            .with_body(
                json!({
                    "item_id": item_id,
                    "path": "/services/api/database",
                    "vault_id": "vault-id",
                    "value": "previous-value",
                    "policy": "database",
                    "version": 3
                })
                .to_string(),
            )
            .create_async()
            .await;
        server
            .mock(
                "POST",
                "/v1/shared/items/00000000-0000-0000-0000-000000000001/rotate/start",
            )
            .match_body(Matcher::Json(json!({"policy": "database"})))
            .with_status(200)
            .with_body(
                json!({
                    "state": "rotating",
                    "candidate": "candidate-value",
                    "previous_version": 3,
                    "expires_at": "2026-08-29T12:10:00Z",
                    "recover_until": "2026-08-30T12:10:00Z"
                })
                .to_string(),
            )
            .create_async()
            .await;
        server
            .mock(
                "POST",
                "/v1/shared/items/00000000-0000-0000-0000-000000000001/rotate/commit",
            )
            .with_status(200)
            .with_body(json!({"status": "committed", "version": 4}).to_string())
            .create_async()
            .await;
        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");

        let previous = client
            .get_previous("infra", "services/api/database")
            .await
            .expect("previous");
        assert_eq!(previous.version, 3);
        let started = client
            .rotation_start(item_id, Some("database"))
            .await
            .expect("start");
        assert_eq!(started.candidate.as_str(), "candidate-value");
        let committed = client.rotation_commit(item_id).await.expect("commit");
        assert_eq!(committed.version, 4);
    }

    #[tokio::test]
    async fn rotate_classifies_unauthorized_without_exposing_a_body() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/v1/vaults/infra/secrets/rotate")
            .with_status(401)
            .with_body("sentinel-unauthorized-body")
            .create_async()
            .await;

        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let error = client
            .rotate("infra", "services/api/database", None, None)
            .await
            .expect_err("unauthorized");
        assert_eq!(error.operation(), SecretOperation::Rotate);
        assert_eq!(error.kind(), SecretsClientErrorKind::Unauthorized);
        assert!(!error.to_string().contains("sentinel-unauthorized-body"));
    }

    #[tokio::test]
    async fn batch_get_preserves_per_item_success_and_error() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/v1/vaults/infra/secrets/batch/get")
            .match_header("authorization", "Bearer access-token")
            .match_body(Matcher::Json(json!({
                "paths": ["services/api/database", "services/api/missing"]
            })))
            .with_status(200)
            .with_body(
                json!([
                    {
                        "path": "services/api/database",
                        "status": "ok",
                        "secret": {
                            "item_id": "00000000-0000-0000-0000-000000000001",
                            "path": "/services/api/database",
                            "vault_id": "vault-id",
                            "value": "database-password",
                            "policy": "default",
                            "version": 3
                        }
                    },
                    {
                        "path": "services/api/missing",
                        "status": "error",
                        "error": {"error": "not_found"}
                    }
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let response = client
            .batch_get(
                "infra",
                &[
                    "services/api/database".to_string(),
                    "services/api/missing".to_string(),
                ],
            )
            .await
            .expect("batch get");
        assert_eq!(response.len(), 2);
        assert_eq!(response[0].status, "ok");
        assert_eq!(response[1].status, "error");
    }

    #[tokio::test]
    async fn batch_ensure_uses_the_canonical_request_shape() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/v1/vaults/infra/secrets/batch/ensure")
            .match_header("authorization", "Bearer access-token")
            .match_body(Matcher::Json(json!({
                "secrets": [{
                    "path": "services/api/key",
                    "policy": "strong",
                    "meta": null
                }]
            })))
            .with_status(200)
            .with_body(
                json!([{
                    "path": "services/api/key",
                    "status": "created",
                    "secret": {
                        "item_id": "00000000-0000-0000-0000-000000000001",
                        "path": "/services/api/key",
                        "vault_id": "vault-id",
                        "value": "generated-value",
                        "policy": "strong",
                        "version": 1,
                        "created": true
                    }
                }])
                .to_string(),
            )
            .create_async()
            .await;

        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let response = client
            .batch_ensure(
                "infra",
                vec![SecretRequest {
                    path: "/services/api/key/".to_string(),
                    policy: Some("strong".to_string()),
                    meta: None,
                }],
            )
            .await
            .expect("batch ensure");
        assert_eq!(response[0].status, "created");
    }

    #[tokio::test]
    async fn batch_rejects_invalid_counts_and_mismatched_response_paths() {
        let client = SecretsClient::new(
            "https://zann.example.test",
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        for paths in [Vec::new(), vec!["path".to_string(); MAX_BATCH_SECRETS + 1]] {
            let error = client
                .batch_get("infra", &paths)
                .await
                .expect_err("invalid batch count");
            assert_eq!(error.kind(), SecretsClientErrorKind::InvalidInput);
        }

        let mut server = Server::new_async().await;
        server
            .mock("POST", "/v1/vaults/infra/secrets/batch/get")
            .with_status(200)
            .with_body(
                json!([{
                    "path": "services/wrong",
                    "status": "ok",
                    "secret": {
                        "item_id": "00000000-0000-0000-0000-000000000001",
                        "path": "/services/wrong",
                        "vault_id": "vault-id",
                        "value": "wrong-value",
                        "policy": "default",
                        "version": 1
                    }
                }])
                .to_string(),
            )
            .create_async()
            .await;
        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let error = client
            .batch_get("infra", &["services/expected".to_string()])
            .await
            .expect_err("mismatched response path");
        assert_eq!(error.kind(), SecretsClientErrorKind::Protocol);
    }

    #[tokio::test]
    async fn oversized_set_value_is_rejected_before_network_io() {
        let client = SecretsClient::new(
            "https://zann.example.test",
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let payload = SecretSetRequest {
            value: "x".repeat(MAX_SECRET_VALUE_BYTES + 1),
            policy: None,
            meta: None,
        };
        let error = client
            .set("infra", "services/api", &payload)
            .await
            .expect_err("oversized value");
        assert_eq!(error.kind(), SecretsClientErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn untrusted_error_body_is_not_exposed() {
        let mut server = Server::new_async().await;
        server
            .mock("GET", "/v1/vaults/infra/secrets/services/api")
            .with_status(500)
            .with_body(json!({"error": "sentinel-secret-body"}).to_string())
            .create_async()
            .await;

        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let error = client
            .get("infra", "services/api")
            .await
            .expect_err("server error");
        assert_eq!(error.kind(), SecretsClientErrorKind::Server);
        assert!(!format!("{error:?}").contains("sentinel-secret-body"));
        assert!(!error.to_string().contains("sentinel-secret-body"));
    }

    #[tokio::test]
    async fn oversized_secret_response_is_rejected_before_decode() {
        let mut server = Server::new_async().await;
        server
            .mock("GET", "/v1/vaults/infra/secrets/services/api")
            .with_status(200)
            .with_body(vec![b'x'; MAX_SECRET_RESPONSE_BYTES + 1])
            .create_async()
            .await;

        let client = SecretsClient::new(
            &server.url(),
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        let error = client
            .get("infra", "services/api")
            .await
            .expect_err("oversized response");
        assert_eq!(error.kind(), SecretsClientErrorKind::BodyTooLarge);
    }

    #[tokio::test]
    async fn traversal_like_secret_paths_are_rejected_locally() {
        let client = SecretsClient::new(
            "https://zann.example.test",
            "access-token",
            SecretsTransportSecurity::AllowLoopbackHttp,
        )
        .expect("client");
        for path in ["", "services//api", "services/../api", "./api"] {
            let error = client.get("infra", path).await.expect_err("invalid path");
            assert_eq!(error.kind(), SecretsClientErrorKind::InvalidInput);
        }
    }
}
