//! Browser OIDC authorization-code flow with PKCE and an ephemeral loopback callback.
//!
//! This module obtains one external provider token and immediately hands it to
//! [`crate::app::AppClient`]. Provider and Zann session tokens never cross the
//! public API boundary.

use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcBrowserErrorKind {
    Configuration,
    InvalidProvider,
    Transport,
    Protocol,
    Cancelled,
    DeadlineExceeded,
    AuthorizationRejected,
    Session,
}

pub struct OidcBrowserError {
    kind: OidcBrowserErrorKind,
}

impl OidcBrowserError {
    fn new(kind: OidcBrowserErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub fn kind(&self) -> OidcBrowserErrorKind {
        self.kind
    }
}

impl fmt::Debug for OidcBrowserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcBrowserError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for OidcBrowserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            OidcBrowserErrorKind::Configuration => "OIDC target is not configured",
            OidcBrowserErrorKind::InvalidProvider => "OIDC provider metadata is invalid",
            OidcBrowserErrorKind::Transport => "OIDC provider is unavailable",
            OidcBrowserErrorKind::Protocol => "OIDC protocol response is invalid",
            OidcBrowserErrorKind::Cancelled => "OIDC login was cancelled",
            OidcBrowserErrorKind::DeadlineExceeded => "OIDC login timed out",
            OidcBrowserErrorKind::AuthorizationRejected => "OIDC authorization was rejected",
            OidcBrowserErrorKind::Session => "OIDC session could not be committed",
        })
    }
}

impl std::error::Error for OidcBrowserError {}

/// Prepared browser login. The caller opens [`Self::authorization_url`] and
/// then awaits [`Self::finish`]. Dropping the value closes the callback port.
pub struct OidcBrowserLogin {
    authorization_url: String,
    listener: TcpListener,
    callback_port: u16,
    oauth_state: Zeroizing<String>,
    code_verifier: Zeroizing<String>,
    redirect_uri: String,
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

    /// Waits for the exact loopback callback, exchanges its code with the
    /// provider, and commits the resulting Zann session.
    pub async fn finish(mut self, client: &AppClient) -> Result<SessionAccess, OidcBrowserError> {
        let listener = self
            .listener
            .try_clone()
            .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))?;
        let port = self.callback_port;
        let callback_operation = self.operation.detached_copy();
        let callback = tokio::task::spawn_blocking(move || {
            wait_for_callback(listener, port, &callback_operation)
        })
        .await
        .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))??;
        if callback.state != *self.oauth_state {
            return Err(OidcBrowserError::new(OidcBrowserErrorKind::Protocol));
        }
        let mut provider_token = exchange_authorization_code(
            &self.http,
            &self.discovery.token_endpoint,
            &self.oidc_config.client_id,
            &callback.code,
            &self.redirect_uri,
            self.code_verifier.as_str(),
        )
        .await?;
        self.code_verifier.zeroize();
        let token = provider_token
            .id_token
            .take()
            .unwrap_or_else(|| std::mem::take(&mut provider_token.access_token));
        let token = OidcToken::new(token)
            .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Protocol))?;
        client
            .oidc_login(OidcLoginInput::new(self.target, token), self.operation)
            .await
            .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Session))
    }
}

impl AppClient {
    /// Prepares a provider authorization URL for an already verified and
    /// pinned connection. No authentication secret is read at this stage.
    pub async fn begin_oidc_login(
        &self,
        target: SessionTarget,
        operation: SessionOperation,
    ) -> Result<OidcBrowserLogin, OidcBrowserError> {
        if let Some(kind) = operation.pre_dispatch_error() {
            return Err(OidcBrowserError::new(match kind {
                crate::session::SessionErrorKind::Cancelled => OidcBrowserErrorKind::Cancelled,
                _ => OidcBrowserErrorKind::DeadlineExceeded,
            }));
        }
        let snapshot = self
            .repository
            .snapshot()
            .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Configuration))?;
        let connection = snapshot
            .config()
            .connections
            .get(target.connection_id())
            .ok_or_else(|| OidcBrowserError::new(OidcBrowserErrorKind::Configuration))?;
        let metadata = connection.metadata();
        if metadata.server_id.is_none() || metadata.server_fingerprint.is_none() {
            return Err(OidcBrowserError::new(OidcBrowserErrorKind::Configuration));
        }
        let transport = AuthHttpTransport::new(&metadata.address)
            .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Configuration))?;
        let oidc_config = transport
            .oidc_config()
            .await
            .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))?;
        validate_oidc_config(&oidc_config)?;

        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))?;
        let discovery_url = discovery_url(&oidc_config.issuer)?;
        let discovery: OidcDiscovery = bounded_json(&http, discovery_url).await?;
        validate_sensitive_url(&discovery.authorization_endpoint)?;
        validate_sensitive_url(&discovery.token_endpoint)?;

        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))?;
        let callback_port = listener
            .local_addr()
            .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))?
            .port();
        let redirect_uri = format!("http://127.0.0.1:{callback_port}/oidc/callback");
        let oauth_state = Zeroizing::new(random_url_safe(24));
        let code_verifier = Zeroizing::new(random_url_safe(48));
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let mut authorization_url = Url::parse(&discovery.authorization_endpoint)
            .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::InvalidProvider))?;
        {
            let mut query = authorization_url.query_pairs_mut();
            query.append_pair("client_id", &oidc_config.client_id);
            query.append_pair("response_type", "code");
            query.append_pair("redirect_uri", &redirect_uri);
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
            listener,
            callback_port,
            oauth_state,
            code_verifier,
            redirect_uri,
            oidc_config,
            discovery,
            target,
            operation,
            http,
        })
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

struct Callback {
    code: String,
    state: String,
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
    let url = Url::parse(value)
        .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::InvalidProvider))?;
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
    Url::parse(&value).map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::InvalidProvider))
}

async fn bounded_json<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    url: Url,
) -> Result<T, OidcBrowserError> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))?;
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
        .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(OidcBrowserError::new(OidcBrowserErrorKind::Protocol));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Protocol))
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
        .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))?;
    if !response.status().is_success() {
        return Err(OidcBrowserError::new(
            OidcBrowserErrorKind::AuthorizationRejected,
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(OidcBrowserError::new(OidcBrowserErrorKind::Protocol));
        }
        body.extend_from_slice(&chunk);
    }
    let token: ProviderTokenResponse = serde_json::from_slice(&body)
        .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Protocol))?;
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

fn wait_for_callback(
    listener: TcpListener,
    port: u16,
    operation: &SessionOperation,
) -> Result<Callback, OidcBrowserError> {
    loop {
        if let Some(kind) = operation.pre_dispatch_error() {
            return Err(OidcBrowserError::new(match kind {
                crate::session::SessionErrorKind::Cancelled => OidcBrowserErrorKind::Cancelled,
                _ => OidcBrowserErrorKind::DeadlineExceeded,
            }));
        }
        match listener.accept() {
            Ok((mut stream, _)) => match parse_callback(&mut stream, port) {
                Ok(Some(callback)) => {
                    let _ = respond(&mut stream, 200, "Login complete. You can return to Zann.");
                    return Ok(callback);
                }
                Ok(None) => {
                    let _ = respond(&mut stream, 404, "Not found");
                }
                Err(error) if error.kind() == OidcBrowserErrorKind::AuthorizationRejected => {
                    let _ = respond(&mut stream, 400, "Authorization was rejected.");
                    return Err(error);
                }
                Err(_) => {
                    let _ = respond(&mut stream, 404, "Not found");
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return Err(OidcBrowserError::new(OidcBrowserErrorKind::Transport)),
        }
    }
}

fn parse_callback(stream: &mut TcpStream, port: u16) -> Result<Option<Callback>, OidcBrowserError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Transport))?;
    let mut buffer = [0_u8; MAX_CALLBACK_BYTES];
    let size = stream
        .read(&mut buffer)
        .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Protocol))?;
    let request = std::str::from_utf8(&buffer[..size])
        .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Protocol))?;
    let mut parts = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    if parts.next() != Some("GET") {
        return Ok(None);
    }
    let path = parts.next().unwrap_or_default();
    let url = Url::parse(&format!("http://127.0.0.1:{port}{path}"))
        .map_err(|_| OidcBrowserError::new(OidcBrowserErrorKind::Protocol))?;
    if url.path() != "/oidc/callback" {
        return Ok(None);
    }
    let mut code = None;
    let mut state = None;
    let mut rejected = false;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            "error" => rejected = true,
            _ => {}
        }
    }
    if rejected {
        return Err(OidcBrowserError::new(
            OidcBrowserErrorKind::AuthorizationRejected,
        ));
    }
    Ok(match (code, state) {
        (Some(code), Some(state)) if !code.is_empty() && !state.is_empty() => {
            Some(Callback { code, state })
        }
        _ => None,
    })
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Not Found" };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_urls_require_tls_except_loopback() {
        assert!(validate_sensitive_url("https://id.example.test/authorize").is_ok());
        assert!(validate_sensitive_url("http://127.0.0.1:8080/authorize").is_ok());
        assert!(validate_sensitive_url("http://id.example.test/authorize").is_err());
        assert!(validate_sensitive_url("https://user@id.example.test/authorize").is_err());
    }
}
