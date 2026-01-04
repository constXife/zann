use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

use crate::config::OidcConfig;
use crate::infra::metrics;

#[derive(Debug, Deserialize)]
pub struct OidcClaims {
    pub iss: String,
    pub sub: String,
    pub email: Option<String>,
    #[serde(flatten)]
    pub other: serde_json::Map<String, Value>,
}

#[derive(Default)]
struct JwksCacheState {
    jwks: Option<jsonwebtoken::jwk::JwkSet>,
    fetched_at: Option<Instant>,
    jwks_uri: Option<String>,
    userinfo_uri: Option<String>,
    discovery_attempted_at: Option<Instant>,
}

#[derive(Clone)]
pub struct OidcJwksCache {
    client: reqwest::Client,
    state: std::sync::Arc<RwLock<JwksCacheState>>,
}

impl Default for OidcJwksCache {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcJwksCache {
    #[must_use]
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|err| {
                warn!(event = "oidc_http_client_failed", error = %err);
                reqwest::Client::new()
            });
        Self {
            client,
            state: std::sync::Arc::new(RwLock::new(JwksCacheState::default())),
        }
    }

    pub async fn get_jwks(&self, config: &OidcConfig) -> Result<jsonwebtoken::jwk::JwkSet, String> {
        if let Some(path) = config.jwks_file.as_deref() {
            let jwks_json = fs::read_to_string(path).map_err(|_| "oidc_jwks_read_failed")?;
            let jwks: jsonwebtoken::jwk::JwkSet =
                serde_json::from_str(&jwks_json).map_err(|_| "oidc_jwks_parse_failed")?;
            return Ok(jwks);
        }

        let ttl = parse_duration(config.jwks_cache_ttl.as_deref())
            .unwrap_or_else(|| Duration::from_secs(15 * 60));
        {
            let state = self.state.read().await;
            if let (Some(jwks), Some(fetched_at)) = (&state.jwks, &state.fetched_at) {
                if fetched_at.elapsed() <= ttl {
                    return Ok(jwks.clone());
                }
            }
        }

        let jwks_uri = self.resolve_jwks_uri(config).await?;
        let fetch_result = self.fetch_jwks(&jwks_uri).await;

        let mut state = self.state.write().await;
        match fetch_result {
            Ok(jwks) => {
                state.jwks = Some(jwks.clone());
                state.fetched_at = Some(Instant::now());
                state.jwks_uri = Some(jwks_uri);
                Ok(jwks)
            }
            Err(err) => state.jwks.clone().ok_or(err),
        }
    }

    async fn resolve_jwks_uri(&self, config: &OidcConfig) -> Result<String, String> {
        let ttl = parse_duration(config.jwks_cache_ttl.as_deref())
            .unwrap_or_else(|| Duration::from_secs(15 * 60));
        if let Some(url) = config.jwks_url.as_deref() {
            return Ok(url.to_string());
        }
        if config.issuer.is_empty() {
            return Err("oidc_jwks_missing".to_string());
        }

        let (cached_uri, last_attempt) = {
            let state = self.state.read().await;
            (state.jwks_uri.clone(), state.discovery_attempted_at)
        };
        if let Some(uri) = cached_uri {
            return Ok(uri);
        }
        if last_attempt.is_some_and(|value| value.elapsed() <= ttl) {
            return Err("oidc_discovery_failed".to_string());
        }

        let well_known = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        );
        let discovery_result = self.client.get(&well_known).send().await;
        let mut state = self.state.write().await;
        state.discovery_attempted_at = Some(Instant::now());
        let response = discovery_result.map_err(|_| "oidc_discovery_failed")?;
        if !response.status().is_success() {
            return Err("oidc_discovery_failed".to_string());
        }
        let doc: OidcDiscovery = response.json().await.map_err(|_| "oidc_discovery_failed")?;
        state.jwks_uri = Some(doc.jwks_uri.clone());
        state.userinfo_uri = doc.userinfo_endpoint.clone();
        Ok(doc.jwks_uri)
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<jsonwebtoken::jwk::JwkSet, String> {
        let response = self.client.get(jwks_uri).send().await.map_err(|_| {
            metrics::oidc_jwks_fetch("error");
            "oidc_jwks_fetch_failed".to_string()
        })?;
        if !response.status().is_success() {
            metrics::oidc_jwks_fetch("error");
            return Err("oidc_jwks_fetch_failed".to_string());
        }
        let jwks = response
            .json::<jsonwebtoken::jwk::JwkSet>()
            .await
            .map_err(|_| {
                metrics::oidc_jwks_fetch("error");
                "oidc_jwks_parse_failed".to_string()
            })?;
        metrics::oidc_jwks_fetch("ok");
        Ok(jwks)
    }
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
    userinfo_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcUserinfoResponse {
    email: Option<String>,
}

impl OidcJwksCache {
    pub async fn fetch_userinfo_email(
        &self,
        token: &str,
        config: &OidcConfig,
    ) -> Result<Option<String>, String> {
        let endpoint = self.resolve_userinfo_endpoint(config).await?;
        tracing::debug!(
            event = "oidc_userinfo_request",
            endpoint = %endpoint,
            issuer = %config.issuer,
            "Fetching OIDC userinfo"
        );
        let response = self
            .client
            .get(&endpoint)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| "oidc_userinfo_fetch_failed")?;
        if !response.status().is_success() {
            return Err("oidc_userinfo_fetch_failed".to_string());
        }
        let payload = response
            .json::<OidcUserinfoResponse>()
            .await
            .map_err(|_| "oidc_userinfo_parse_failed")?;
        Ok(payload.email)
    }

    async fn resolve_userinfo_endpoint(&self, config: &OidcConfig) -> Result<String, String> {
        let ttl = parse_duration(config.jwks_cache_ttl.as_deref())
            .unwrap_or_else(|| Duration::from_secs(15 * 60));
        let (cached_uri, last_attempt) = {
            let state = self.state.read().await;
            (state.userinfo_uri.clone(), state.discovery_attempted_at)
        };
        if let Some(uri) = cached_uri {
            return Ok(uri);
        }
        if last_attempt.is_some_and(|value| value.elapsed() <= ttl) {
            return Err("oidc_userinfo_missing".to_string());
        }
        if config.issuer.is_empty() {
            return Err("oidc_userinfo_missing".to_string());
        }

        let well_known = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        );
        let discovery_result = self.client.get(&well_known).send().await;
        let mut state = self.state.write().await;
        state.discovery_attempted_at = Some(Instant::now());
        let response = discovery_result.map_err(|_| "oidc_discovery_failed")?;
        if !response.status().is_success() {
            return Err("oidc_discovery_failed".to_string());
        }
        let doc: OidcDiscovery = response.json().await.map_err(|_| "oidc_discovery_failed")?;
        let Some(endpoint) = doc.userinfo_endpoint.clone() else {
            return Err("oidc_userinfo_missing".to_string());
        };
        state.userinfo_uri = Some(endpoint.clone());
        Ok(endpoint)
    }
}

pub async fn validate_oidc_jwt(
    token: &str,
    config: &OidcConfig,
    cache: &OidcJwksCache,
) -> Result<OidcClaims, String> {
    let jwks = cache.get_jwks(config).await?;

    let header = decode_header(token).map_err(|err| {
        tracing::warn!(event = "oidc_header_invalid", error = %err);
        "oidc_header_invalid".to_string()
    })?;
    if header.alg != Algorithm::RS256 {
        return Err("oidc_alg_unsupported".to_string());
    }
    let kid = header.kid.ok_or_else(|| "oidc_kid_missing".to_string())?;

    let jwk = jwks
        .keys
        .iter()
        .find(|jwk| jwk.common.key_id.as_deref() == Some(&kid))
        .ok_or_else(|| "oidc_key_not_found".to_string())?;

    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|err| {
        tracing::warn!(event = "oidc_key_invalid", error = %err);
        "oidc_key_invalid".to_string()
    })?;

    let mut validation = Validation::new(Algorithm::RS256);
    if !config.issuer.is_empty() {
        validation.set_issuer(std::slice::from_ref(&config.issuer));
    }
    let audience = config
        .audience
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(aud) = audience {
        validation.set_audience(&[aud]);
    }

    let token_data = decode::<OidcClaims>(token, &decoding_key, &validation).map_err(|err| {
        tracing::warn!(event = "oidc_token_invalid", error = %err);
        "oidc_token_invalid".to_string()
    })?;

    Ok(token_data.claims)
}

fn parse_duration(raw: Option<&str>) -> Option<Duration> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let (num, suffix) = raw.split_at(raw.len().saturating_sub(1));
    let (value, unit) = if suffix.chars().all(|c| c.is_ascii_digit()) {
        (raw, "s")
    } else {
        (num, suffix)
    };
    let value = value.parse::<u64>().ok()?;
    match unit {
        "s" => Some(Duration::from_secs(value)),
        "m" => Some(Duration::from_secs(value * 60)),
        "h" => Some(Duration::from_secs(value * 60 * 60)),
        _ => None,
    }
}
