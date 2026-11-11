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
    pub email_verified: Option<bool>,
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
            let jwks_json = fs::read_to_string(path).map_err(|err| {
                warn!(event = "oidc_jwks_read_failed", error = %err, path = %path);
                "oidc_jwks_read_failed".to_string()
            })?;
            let jwks: jsonwebtoken::jwk::JwkSet =
                serde_json::from_str(&jwks_json).map_err(|err| {
                    warn!(event = "oidc_jwks_parse_failed", error = %err, path = %path);
                    "oidc_jwks_parse_failed".to_string()
                })?;
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
        let response = discovery_result.map_err(|err| {
            warn!(
                event = "oidc_discovery_failed",
                error = %err,
                url = %well_known
            );
            "oidc_discovery_failed".to_string()
        })?;
        if !response.status().is_success() {
            return Err("oidc_discovery_failed".to_string());
        }
        let doc: OidcDiscovery = response.json().await.map_err(|err| {
            warn!(
                event = "oidc_discovery_failed",
                error = %err,
                url = %well_known
            );
            "oidc_discovery_failed".to_string()
        })?;
        state.jwks_uri = Some(doc.jwks_uri.clone());
        state.userinfo_uri = doc.userinfo_endpoint.clone();
        Ok(doc.jwks_uri)
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<jsonwebtoken::jwk::JwkSet, String> {
        let response = self.client.get(jwks_uri).send().await.map_err(|err| {
            metrics::oidc_jwks_fetch("error");
            warn!(
                event = "oidc_jwks_fetch_failed",
                error = %err,
                url = %jwks_uri
            );
            "oidc_jwks_fetch_failed".to_string()
        })?;
        if !response.status().is_success() {
            metrics::oidc_jwks_fetch("error");
            return Err("oidc_jwks_fetch_failed".to_string());
        }
        let jwks = response
            .json::<jsonwebtoken::jwk::JwkSet>()
            .await
            .map_err(|err| {
                metrics::oidc_jwks_fetch("error");
                warn!(
                    event = "oidc_jwks_parse_failed",
                    error = %err,
                    url = %jwks_uri
                );
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
    email_verified: Option<bool>,
}

/// Email attributes resolved from the issuer's userinfo endpoint.
#[derive(Debug, Clone)]
pub struct OidcUserinfo {
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

impl OidcJwksCache {
    pub async fn fetch_userinfo(
        &self,
        token: &str,
        config: &OidcConfig,
    ) -> Result<OidcUserinfo, String> {
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
            .map_err(|err| {
                warn!(
                    event = "oidc_userinfo_fetch_failed",
                    error = %err,
                    url = %endpoint
                );
                "oidc_userinfo_fetch_failed".to_string()
            })?;
        if !response.status().is_success() {
            return Err("oidc_userinfo_fetch_failed".to_string());
        }
        let payload = response
            .json::<OidcUserinfoResponse>()
            .await
            .map_err(|err| {
                warn!(
                    event = "oidc_userinfo_parse_failed",
                    error = %err,
                    url = %endpoint
                );
                "oidc_userinfo_parse_failed".to_string()
            })?;
        Ok(OidcUserinfo {
            email: payload.email,
            email_verified: payload.email_verified,
        })
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
        let response = discovery_result.map_err(|err| {
            warn!(
                event = "oidc_discovery_failed",
                error = %err,
                url = %well_known
            );
            "oidc_discovery_failed".to_string()
        })?;
        if !response.status().is_success() {
            return Err("oidc_discovery_failed".to_string());
        }
        let doc: OidcDiscovery = response.json().await.map_err(|err| {
            warn!(
                event = "oidc_discovery_failed",
                error = %err,
                url = %well_known
            );
            "oidc_discovery_failed".to_string()
        })?;
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

#[cfg(test)]
mod tests {
    use jsonwebtoken::{decode, jwk::Jwk, Algorithm, DecodingKey, Validation};

    // RFC 7515 Appendix A.2: an RS256 JWS and the public half of its key.
    const RFC7515_A2_JWK: &str = r#"{"kty":"RSA","e":"AQAB","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"}"#;
    const RFC7515_A2_JWS: &str = concat!(
        "eyJhbGciOiJSUzI1NiJ9",
        ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw",
    );

    // Pins the jsonwebtoken crypto backend that `validate_oidc_jwt` relies on:
    // an RS256 signature checked against a JWK. The vector's `exp` is in 2011,
    // so expiry is disabled here; claim validation is not under test.
    fn verify(token: &str) -> jsonwebtoken::errors::Result<serde_json::Value> {
        let jwk: Jwk = serde_json::from_str(RFC7515_A2_JWK).expect("jwk");
        let key = DecodingKey::from_jwk(&jwk)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        decode::<serde_json::Value>(token, &key, &validation).map(|data| data.claims)
    }

    #[test]
    fn rs256_jwk_signature_verifies() {
        let claims = verify(RFC7515_A2_JWS).expect("valid RFC 7515 A.2 signature");
        assert_eq!(claims["iss"], "joe");
    }

    #[test]
    fn rs256_jwk_rejects_tampered_payload() {
        // Same header and signature over a payload with "iss":"jof".
        let tampered = RFC7515_A2_JWS.replacen("eyJpc3MiOiJqb2Ui", "eyJpc3MiOiJqb2Yi", 1);
        assert!(verify(&tampered).is_err());
    }
}
