//! Browser OIDC authorization-code flow with PKCE and explicit callback transport.
//!
//! This module obtains one external provider token and immediately hands it to
//! [`crate::app::AppClient`]. Provider and Zann session tokens never cross the
//! public API boundary.

use std::net::IpAddr;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore as _;
use reqwest::redirect::Policy;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use url::Url;
use zann_core::api::auth::OidcConfigResponse;
use zeroize::{Zeroize, Zeroizing};

use crate::app::{AppClient, OidcLoginInput, OidcToken};
use crate::remote::auth::AuthHttpTransport;
use crate::session::{SessionAccess, SessionOperation, SessionTarget};

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_CALLBACK_BYTES: usize = 8 * 1024;
const MAX_METADATA_FIELD_BYTES: usize = 8 * 1024;

mod callback;
mod error;
pub use callback::OidcCallback;
use callback::{Callback, CallbackTransport};
pub use error::{OidcBrowserError, OidcBrowserErrorKind};

/// Prepared browser login. The caller opens [`Self::authorization_url`] and
/// then awaits [`Self::finish`] or supplies its native callback through
/// [`Self::finish_with_callback`]. Dropping it closes any loopback port.
pub struct OidcBrowserLogin {
    authorization_url: String,
    callback: CallbackTransport,
    oauth_state: Zeroizing<String>,
    code_verifier: Zeroizing<String>,
    oidc_config: OidcConfigResponse,
    discovery: OidcDiscovery,
    target: SessionTarget,
    operation: SessionOperation,
    http: reqwest::Client,
}

impl OidcBrowserLogin {
    #[must_use]
    pub fn authorization_url(&self) -> &str {
        &self.authorization_url
    }

    /// Scheme the native system session must admit for this prepared login.
    pub fn callback_scheme(&self) -> &str {
        self.callback.redirect_uri().scheme()
    }

    pub fn remaining_timeout_ms(&self) -> u64 {
        self.operation
            .deadline()
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// Waits for the exact loopback callback, exchanges its code with the
    /// provider, and commits the resulting Zann session.
    pub async fn finish(self, client: &AppClient) -> Result<SessionAccess, OidcBrowserError> {
        let callback = self
            .callback
            .receive(&self.operation, &self.oauth_state)
            .await?;
        self.complete(client, callback).await
    }

    /// Native web sessions supply only the OS-delivered URI; matching the
    /// exact redirect, state, and exchanging its single-use code stay here.
    pub async fn finish_with_callback(
        self,
        client: &AppClient,
        uri: String,
    ) -> Result<SessionAccess, OidcBrowserError> {
        let callback = self.callback.application_callback(uri)?;
        self.complete(client, callback).await
    }

    async fn complete(
        mut self,
        client: &AppClient,
        callback: Callback,
    ) -> Result<SessionAccess, OidcBrowserError> {
        check_operation(&self.operation)?;
        let code = callback.authorization_code(&self.oauth_state)?;
        let exchange = exchange_authorization_code(
            &self.http,
            &self.discovery.token_endpoint,
            &self.oidc_config.client_id,
            &code,
            self.callback.redirect_uri().as_str(),
            self.code_verifier.as_str(),
        );
        let mut provider_token = within_operation(&self.operation, exchange).await?;
        self.code_verifier.zeroize();
        let token = provider_token
            .id_token
            .take()
            .unwrap_or_else(|| std::mem::take(&mut provider_token.access_token));
        let token = OidcToken::new(token)
            .map_err(|error| OidcBrowserError::caused_by(OidcBrowserErrorKind::Protocol, error))?;
        client
            .oidc_login(OidcLoginInput::new(self.target, token), self.operation)
            .await
            .map_err(OidcBrowserError::session)
    }
}

impl AppClient {
    /// Prepares a provider authorization URL for an already verified and
    /// pinned connection. No authentication secret is read at this stage.
    pub async fn begin_oidc_login(
        &self,
        target: SessionTarget,
        operation: SessionOperation,
        callback: OidcCallback,
    ) -> Result<OidcBrowserLogin, OidcBrowserError> {
        check_operation(&operation)?;
        let callback = CallbackTransport::new(callback)?;
        let snapshot = self.repository.snapshot().map_err(|error| {
            OidcBrowserError::caused_by(OidcBrowserErrorKind::Configuration, error)
        })?;
        let connection = snapshot
            .config()
            .connections
            .get(target.connection_id())
            .ok_or_else(|| OidcBrowserError::new(OidcBrowserErrorKind::Configuration))?;
        let metadata = connection.metadata();
        if metadata.server_id.is_none() || metadata.server_fingerprint.is_none() {
            return Err(OidcBrowserError::new(OidcBrowserErrorKind::Configuration));
        }
        let transport = AuthHttpTransport::new(&metadata.address).map_err(|error| {
            OidcBrowserError::caused_by(OidcBrowserErrorKind::Configuration, error)
        })?;
        let oidc_config = within_operation(&operation, async {
            transport.oidc_config().await.map_err(|error| {
                OidcBrowserError::caused_by(OidcBrowserErrorKind::Transport, error)
            })
        })
        .await?;
        validate_oidc_config(&oidc_config)?;

        let http = crate::http::client_builder()
            .redirect(Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|error| OidcBrowserError::caused_by(OidcBrowserErrorKind::Transport, error))?;
        let discovery_url = discovery_url(&oidc_config.issuer)?;
        let discovery: OidcDiscovery =
            within_operation(&operation, bounded_json(&http, discovery_url)).await?;
        validate_sensitive_url(&discovery.authorization_endpoint)?;
        validate_sensitive_url(&discovery.token_endpoint)?;

        let oauth_state = Zeroizing::new(random_url_safe(24));
        let code_verifier = Zeroizing::new(random_url_safe(48));
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let mut authorization_url =
            Url::parse(&discovery.authorization_endpoint).map_err(|error| {
                OidcBrowserError::caused_by(OidcBrowserErrorKind::InvalidProvider, error)
            })?;
        {
            let mut query = authorization_url.query_pairs_mut();
            query.append_pair("client_id", &oidc_config.client_id);
            query.append_pair("response_type", "code");
            query.append_pair("redirect_uri", callback.redirect_uri().as_str());
            query.append_pair("scope", &oidc_config.scopes.join(" "));
            query.append_pair("state", &oauth_state);
            query.append_pair("code_challenge", &code_challenge);
            query.append_pair("code_challenge_method", "S256");
            if let Some(audience) = oidc_config.audience.as_deref() {
                query.append_pair("audience", audience);
            }
        }
        Ok(OidcBrowserLogin {
            authorization_url: authorization_url.to_string(),
            callback,
            oauth_state,
            code_verifier,
            oidc_config,
            discovery,
            target,
            operation,
            http,
        })
    }
}

fn check_operation(operation: &SessionOperation) -> Result<(), OidcBrowserError> {
    match operation.pre_dispatch_error() {
        Some(crate::session::SessionErrorKind::Cancelled) => {
            Err(OidcBrowserError::new(OidcBrowserErrorKind::Cancelled))
        }
        Some(_) => Err(OidcBrowserError::new(
            OidcBrowserErrorKind::DeadlineExceeded,
        )),
        None => Ok(()),
    }
}

async fn within_operation<T>(
    operation: &SessionOperation,
    work: impl std::future::Future<Output = Result<T, OidcBrowserError>>,
) -> Result<T, OidcBrowserError> {
    check_operation(operation)?;
    tokio::select! {
        biased;
        _ = operation.cancelled() => Err(OidcBrowserError::new(OidcBrowserErrorKind::Cancelled)),
        _ = tokio::time::sleep_until(operation.deadline().into()) => Err(OidcBrowserError::new(OidcBrowserErrorKind::DeadlineExceeded)),
        result = work => result,
    }
}

#[derive(Deserialize)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct ProviderTokenResponse {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
}

impl Drop for ProviderTokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(token) = self.id_token.as_mut() {
            token.zeroize();
        }
    }
}

fn random_url_safe(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn validate_oidc_config(config: &OidcConfigResponse) -> Result<(), OidcBrowserError> {
    if config.issuer.is_empty()
        || config.client_id.is_empty()
        || config.scopes.is_empty()
        || config.issuer.len() > MAX_METADATA_FIELD_BYTES
        || config.client_id.len() > MAX_METADATA_FIELD_BYTES
        || config
            .scopes
            .iter()
            .any(|scope| scope.is_empty() || scope.len() > MAX_METADATA_FIELD_BYTES)
        || config
            .audience
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_METADATA_FIELD_BYTES)
    {
        return Err(OidcBrowserError::new(OidcBrowserErrorKind::InvalidProvider));
    }
    validate_sensitive_url(&config.issuer)
}

fn validate_sensitive_url(value: &str) -> Result<(), OidcBrowserError> {
    if value.len() > MAX_METADATA_FIELD_BYTES {
        return Err(OidcBrowserError::new(OidcBrowserErrorKind::InvalidProvider));
    }
    let url = Url::parse(value).map_err(|error| {
        OidcBrowserError::caused_by(OidcBrowserErrorKind::InvalidProvider, error)
    })?;
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
        || url.host_str() == Some("localhost");
    if url.username().is_empty()
        && url.password().is_none()
        && (url.scheme() == "https" || (url.scheme() == "http" && loopback))
    {
        Ok(())
    } else {
        Err(OidcBrowserError::new(OidcBrowserErrorKind::InvalidProvider))
    }
}

fn discovery_url(issuer: &str) -> Result<Url, OidcBrowserError> {
    let value = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    Url::parse(&value)
        .map_err(|error| OidcBrowserError::caused_by(OidcBrowserErrorKind::InvalidProvider, error))
}

async fn bounded_json<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    url: Url,
) -> Result<T, OidcBrowserError> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|error| OidcBrowserError::caused_by(OidcBrowserErrorKind::Transport, error))?;
    if !response.status().is_success() {
        return Err(OidcBrowserError::new(OidcBrowserErrorKind::Transport));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(OidcBrowserError::new(OidcBrowserErrorKind::Protocol));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| OidcBrowserError::caused_by(OidcBrowserErrorKind::Transport, error))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(OidcBrowserError::new(OidcBrowserErrorKind::Protocol));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|error| OidcBrowserError::caused_by(OidcBrowserErrorKind::Protocol, error))
}

async fn exchange_authorization_code(
    client: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<ProviderTokenResponse, OidcBrowserError> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
    ];
    let mut response = client
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|error| OidcBrowserError::caused_by(OidcBrowserErrorKind::Transport, error))?;
    if !response.status().is_success() {
        return Err(OidcBrowserError::new(
            OidcBrowserErrorKind::AuthorizationRejected,
        ));
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| OidcBrowserError::caused_by(OidcBrowserErrorKind::Transport, error))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(OidcBrowserError::new(OidcBrowserErrorKind::Protocol));
        }
        body.extend_from_slice(&chunk);
    }
    let token: ProviderTokenResponse = serde_json::from_slice(&body)
        .map_err(|error| OidcBrowserError::caused_by(OidcBrowserErrorKind::Protocol, error))?;
    if token.access_token.is_empty()
        || token.access_token.len() > MAX_RESPONSE_BYTES
        || token
            .id_token
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_RESPONSE_BYTES)
    {
        return Err(OidcBrowserError::new(OidcBrowserErrorKind::Protocol));
    }
    Ok(token)
}

#[cfg(test)]
mod tests;
