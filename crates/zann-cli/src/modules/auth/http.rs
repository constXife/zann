use chrono::{Duration as ChronoDuration, Utc};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
#[cfg(test)]
use std::collections::HashMap;
use std::io::{self, IsTerminal, Write};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
#[cfg(test)]
use tokio::sync::Mutex as TokioMutex;
use tracing::debug;
#[cfg(not(test))]
use tracing::warn;

use zann_core::api::auth::PreloginResponse;

use crate::modules::auth::{
    AuthResponse, DeviceAuthResponse, OidcConfigResponse, OidcDiscovery, RefreshRequest,
    ServiceAccountAuthRequest, ServiceAccountAuthResponse, TokenErrorResponse, TokenResponse,
};
use crate::modules::system::{
    load_known_hosts, normalize_server_key, save_known_hosts, CliConfig, IdentityConfig,
};
use crate::{REFRESH_SKEW_SECONDS, SERVER_FINGERPRINT_ENV};

use crate::modules::system::http::{fetch_json, fetch_system_info, parse_rfc3339};

pub(crate) fn auth_headers(token: &str) -> anyhow::Result<HeaderMap> {
    if token.trim().is_empty() {
        anyhow::bail!("token is required (ZANN_TOKEN, --token, or config context)");
    }
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("Bearer {token}"))?;
    headers.insert(AUTHORIZATION, value);
    Ok(headers)
}

fn keyring_key(kind: &str, context_name: &str, token_name: &str) -> String {
    format!("{kind}::{}::{}", context_name, token_name)
}

#[cfg(test)]
fn keyring_store() -> &'static Mutex<HashMap<String, String>> {
    static STORE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
static KEYRING_TEST_LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn lock_keyring_tests_sync() -> tokio::sync::MutexGuard<'static, ()> {
    KEYRING_TEST_LOCK
        .get_or_init(|| TokioMutex::new(()))
        .blocking_lock()
}

#[cfg(test)]
pub(crate) async fn lock_keyring_tests_async() -> tokio::sync::MutexGuard<'static, ()> {
    KEYRING_TEST_LOCK
        .get_or_init(|| TokioMutex::new(()))
        .lock()
        .await
}

#[cfg(not(test))]
fn keyring_entry(
    kind: &str,
    context_name: &str,
    token_name: &str,
) -> anyhow::Result<keyring::Entry> {
    let service = "zann-cli";
    let key = keyring_key(kind, context_name, token_name);
    keyring::Entry::new(service, &key)
        .map_err(|err| anyhow::anyhow!("failed to access keyring: {err}"))
}

#[cfg(not(test))]
fn keyring_set(
    kind: &str,
    context_name: &str,
    token_name: &str,
    value: &str,
) -> anyhow::Result<()> {
    let entry = keyring_entry(kind, context_name, token_name)?;
    entry
        .set_password(value)
        .map_err(|err| anyhow::anyhow!("failed to store {kind} token: {err}"))
}

#[cfg(not(test))]
fn keyring_get(kind: &str, context_name: &str, token_name: &str) -> anyhow::Result<Option<String>> {
    let entry = keyring_entry(kind, context_name, token_name)?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(anyhow::anyhow!(
            "failed to load {kind} token from keychain for context '{}', token '{}': {err}",
            context_name,
            token_name
        )),
    }
}

#[cfg(not(test))]
fn keyring_delete(kind: &str, context_name: &str, token_name: &str) -> anyhow::Result<()> {
    let entry = keyring_entry(kind, context_name, token_name)?;
    match entry.delete_password() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => {
            warn!(context = %context_name, token = %token_name, "failed to delete {kind} token: {err}");
            Ok(())
        }
    }
}

#[cfg(test)]
fn keyring_set(
    kind: &str,
    context_name: &str,
    token_name: &str,
    value: &str,
) -> anyhow::Result<()> {
    let key = keyring_key(kind, context_name, token_name);
    let mut store = keyring_store()
        .lock()
        .map_err(|_| anyhow::anyhow!("failed to lock keyring store"))?;
    store.insert(key, value.to_string());
    Ok(())
}

#[cfg(test)]
fn keyring_get(kind: &str, context_name: &str, token_name: &str) -> anyhow::Result<Option<String>> {
    let key = keyring_key(kind, context_name, token_name);
    let store = keyring_store()
        .lock()
        .map_err(|_| anyhow::anyhow!("failed to lock keyring store"))?;
    Ok(store.get(&key).cloned())
}

#[cfg(test)]
fn keyring_delete(kind: &str, context_name: &str, token_name: &str) -> anyhow::Result<()> {
    let key = keyring_key(kind, context_name, token_name);
    let mut store = keyring_store()
        .lock()
        .map_err(|_| anyhow::anyhow!("failed to lock keyring store"))?;
    store.remove(&key);
    Ok(())
}

#[cfg(test)]
pub(crate) fn clear_keyring_mock() {
    if let Ok(mut map) = keyring_store().lock() {
        map.clear();
    }
}

pub(crate) fn store_refresh_token(
    context_name: &str,
    token_name: &str,
    refresh_token: &str,
) -> anyhow::Result<()> {
    keyring_set("refresh", context_name, token_name, refresh_token)?;
    debug!(context = %context_name, token = %token_name, "stored refresh token in keyring");
    Ok(())
}

pub(crate) fn load_refresh_token(
    context_name: &str,
    token_name: &str,
) -> anyhow::Result<Option<String>> {
    keyring_get("refresh", context_name, token_name)
}

pub(crate) fn refresh_token_missing_error(context_name: &str, token_name: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "refresh token missing in keychain for context '{}', token '{}'; run `zann login`",
        context_name,
        token_name
    )
}

pub(crate) fn delete_refresh_token(context_name: &str, token_name: &str) -> anyhow::Result<()> {
    keyring_delete("refresh", context_name, token_name)
}

pub(crate) fn store_access_token(
    context_name: &str,
    token_name: &str,
    access_token: &str,
) -> anyhow::Result<()> {
    keyring_set("access", context_name, token_name, access_token)?;
    debug!(context = %context_name, token = %token_name, "stored access token in keyring");
    Ok(())
}

pub(crate) fn store_service_token(
    context_name: &str,
    token_name: &str,
    service_token: &str,
) -> anyhow::Result<()> {
    keyring_set("service", context_name, token_name, service_token)?;
    debug!(context = %context_name, token = %token_name, "stored service token in keyring");
    Ok(())
}

pub(crate) fn load_service_token(
    context_name: &str,
    token_name: &str,
) -> anyhow::Result<Option<String>> {
    keyring_get("service", context_name, token_name)
}

pub(crate) fn delete_service_token(context_name: &str, token_name: &str) -> anyhow::Result<()> {
    keyring_delete("service", context_name, token_name)
}

pub(crate) fn load_access_token(
    context_name: &str,
    token_name: &str,
) -> anyhow::Result<Option<String>> {
    keyring_get("access", context_name, token_name)
}

pub(crate) fn delete_access_token(context_name: &str, token_name: &str) -> anyhow::Result<()> {
    keyring_delete("access", context_name, token_name)
}

pub(crate) async fn fetch_prelogin(
    client: &reqwest::Client,
    addr: &str,
    email: &str,
) -> anyhow::Result<PreloginResponse> {
    let base = format!("{}/v1/auth/prelogin", addr.trim_end_matches('/'));
    let mut url = reqwest::Url::parse(&base)?;
    url.query_pairs_mut().append_pair("email", email);
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Prelogin failed: {status} {body}");
    }
    Ok(response.json::<PreloginResponse>().await?)
}

pub(crate) async fn fetch_me_email(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
) -> anyhow::Result<String> {
    #[derive(serde::Deserialize)]
    struct MeResponse {
        email: String,
    }
    let url = format!("{}/v1/users/me", addr.trim_end_matches('/'));
    let response = client
        .get(url)
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Failed to fetch user profile: {status} {body}");
    }
    let me: MeResponse = response.json().await?;
    Ok(me.email)
}

pub(crate) fn verify_server_fingerprint(
    config: &CliConfig,
    context_name: Option<&str>,
    addr: &str,
    server_fingerprint: &str,
) -> anyhow::Result<()> {
    if let Ok(expected) = std::env::var(SERVER_FINGERPRINT_ENV) {
        if expected != server_fingerprint {
            anyhow::bail!(
                "CRITICAL: Server fingerprint mismatch! Expected (env): {expected}, actual: {server_fingerprint}"
            );
        }
        return Ok(());
    }

    if let Some(context_name) = context_name {
        if let Some(context) = config.contexts.get(context_name) {
            if let Some(expected) = context.server_fingerprint.as_deref() {
                if expected != server_fingerprint {
                    anyhow::bail!(
                        "CRITICAL: Server fingerprint mismatch! Expected (config): {expected}, actual: {server_fingerprint}"
                    );
                }
                return Ok(());
            }
        }
    }

    let key = normalize_server_key(addr);
    let mut known_hosts = load_known_hosts()?;
    if let Some(expected) = known_hosts.get(&key) {
        if expected == server_fingerprint {
            return Ok(());
        }
        eprintln!("SECURITY WARNING: Server fingerprint has changed!");
        eprintln!("Old fingerprint: {expected}");
        eprintln!("New fingerprint: {server_fingerprint}");
        eprintln!("This could mean the server was re-deployed or under attack.");
        if !confirm_trust_prompt()? {
            anyhow::bail!("fingerprint changed; login aborted");
        }
    } else {
        eprintln!("SECURITY WARNING: Unknown server fingerprint.");
        eprintln!("Fingerprint: {server_fingerprint}");
        if !confirm_trust_prompt()? {
            anyhow::bail!(
                "running without pinned fingerprint; set ZANN_SERVER_FINGERPRINT or context server_fingerprint"
            );
        }
    }

    known_hosts.insert(key, server_fingerprint.to_string());
    save_known_hosts(&known_hosts)?;
    Ok(())
}

pub(crate) fn check_kdf_fingerprint(
    config: &CliConfig,
    email: &str,
    kdf_fingerprint: &str,
) -> anyhow::Result<()> {
    let Some(identity) = config.identity.as_ref() else {
        return Ok(());
    };
    if identity.email != email || identity.salt_fingerprint == kdf_fingerprint {
        return Ok(());
    }

    eprintln!("SECURITY WARNING: Identity KDF parameters have changed!");
    eprintln!("Old fingerprint: {}", identity.salt_fingerprint);
    eprintln!("New fingerprint: {kdf_fingerprint}");
    eprintln!("This could mean the server was re-deployed or under attack.");
    if !confirm_trust_prompt()? {
        anyhow::bail!("identity parameters changed; login aborted");
    }
    Ok(())
}

pub(crate) fn store_prelogin(
    config: &mut CliConfig,
    context_name: &str,
    email: &str,
    prelogin: PreloginResponse,
) {
    let now = Utc::now().to_rfc3339();
    let first_seen_at = config
        .identity
        .as_ref()
        .and_then(|identity| identity.first_seen_at.clone())
        .unwrap_or(now);
    config.identity = Some(IdentityConfig {
        email: email.to_string(),
        kdf_salt: prelogin.kdf_salt,
        kdf_params: prelogin.kdf_params,
        salt_fingerprint: prelogin.salt_fingerprint,
        first_seen_at: Some(first_seen_at),
    });
    if let Some(context) = config.contexts.get_mut(context_name) {
        context.needs_salt_update = false;
    }
}

pub(crate) fn confirm_trust_prompt() -> anyhow::Result<bool> {
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    print!("Do you want to trust this new identity? (y/N): ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();
    Ok(input == "y" || input == "yes")
}

pub(crate) async fn fetch_oidc_config(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<OidcConfigResponse> {
    fetch_json(client, url).await
}

pub(crate) async fn fetch_oidc_discovery(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<OidcDiscovery> {
    fetch_json(client, url).await
}

pub(crate) async fn fetch_auth_system_info(
    client: &reqwest::Client,
    addr: &str,
) -> anyhow::Result<crate::modules::system::SystemInfoResponse> {
    fetch_system_info(client, addr).await
}

pub(crate) async fn request_device_code(
    client: &reqwest::Client,
    discovery: &OidcDiscovery,
    oidc: &OidcConfigResponse,
) -> anyhow::Result<DeviceAuthResponse> {
    let scope = oidc.scopes.join(" ");
    let mut params = vec![
        ("client_id", oidc.client_id.as_str()),
        ("scope", scope.as_str()),
    ];
    if let Some(audience) = oidc.audience.as_deref() {
        params.push(("audience", audience));
    }

    let response = client
        .post(&discovery.device_authorization_endpoint)
        .form(&params)
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Device authorization failed: {status} {body}");
    }
    Ok(response.json::<DeviceAuthResponse>().await?)
}

pub(crate) async fn poll_device_token(
    client: &reqwest::Client,
    discovery: &OidcDiscovery,
    oidc: &OidcConfigResponse,
    device: &DeviceAuthResponse,
) -> anyhow::Result<TokenResponse> {
    let mut interval = device.interval.unwrap_or(5);
    let expires_at = Utc::now() + ChronoDuration::seconds(device.expires_in);
    loop {
        if Utc::now() > expires_at {
            anyhow::bail!("device code expired");
        }

        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device.device_code.as_str()),
            ("client_id", oidc.client_id.as_str()),
        ];
        let response = client
            .post(&discovery.token_endpoint)
            .form(&params)
            .send()
            .await?;

        if response.status().is_success() {
            return Ok(response.json::<TokenResponse>().await?);
        }

        let error = response
            .json::<TokenErrorResponse>()
            .await
            .unwrap_or(TokenErrorResponse {
                error: "unknown".to_string(),
                error_description: None,
            });

        match error.error.as_str() {
            "authorization_pending" => {
                tokio::time::sleep(Duration::from_secs(interval as u64)).await;
            }
            "slow_down" => {
                interval += 5;
                tokio::time::sleep(Duration::from_secs(interval as u64)).await;
            }
            "access_denied" => anyhow::bail!("access denied"),
            "expired_token" => anyhow::bail!("device code expired"),
            _ => {
                let detail = error.error_description.unwrap_or_default();
                anyhow::bail!("token error: {} {}", error.error, detail);
            }
        }
    }
}

pub(crate) async fn exchange_service_account_token(
    client: &reqwest::Client,
    addr: &str,
    token: &str,
) -> anyhow::Result<ServiceAccountAuthResponse> {
    let url = format!("{}/v1/auth/service-account", addr.trim_end_matches('/'));
    let payload = ServiceAccountAuthRequest {
        token: token.to_string(),
    };
    let response = client.post(url).json(&payload).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Service account login failed: {status} {body}");
    }
    Ok(response.json::<ServiceAccountAuthResponse>().await?)
}

pub(crate) async fn ensure_access_token(
    client: &reqwest::Client,
    addr: &str,
    context_name: &str,
    token_name: &str,
    config: &mut CliConfig,
) -> anyhow::Result<String> {
    let context = config
        .contexts
        .get(context_name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("context not found: {}", context_name))?;
    let entry = context
        .tokens
        .get(token_name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("token not found: {}", token_name))?;

    let stored_service_token = load_service_token(context_name, token_name)?;
    if let Some(service_account_token) = stored_service_token.as_deref() {
        let info = fetch_system_info(client, addr).await?;
        verify_server_fingerprint(config, Some(context_name), addr, &info.server_fingerprint)?;

        let expires_at = entry.access_expires_at.as_deref().and_then(parse_rfc3339);
        let needs_refresh = expires_at
            .map(|expires_at| {
                Utc::now() + ChronoDuration::seconds(REFRESH_SKEW_SECONDS) >= expires_at
            })
            .unwrap_or(true);
        if !needs_refresh {
            if let Some(access_token) = load_access_token(context_name, token_name)? {
                return Ok(access_token);
            }
        }

        let auth = exchange_service_account_token(client, addr, service_account_token).await?;
        let new_expires =
            (Utc::now() + ChronoDuration::seconds(auth.expires_in as i64)).to_rfc3339();
        store_access_token(context_name, token_name, &auth.access_token)?;

        if let Some(entry) = config
            .contexts
            .get_mut(context_name)
            .and_then(|ctx| ctx.tokens.get_mut(token_name))
        {
            entry.access_expires_at = Some(new_expires);
        }

        return Ok(auth.access_token);
    }

    let expires_at = entry.access_expires_at.as_deref().and_then(parse_rfc3339);
    let needs_refresh = expires_at
        .map(|expires_at| Utc::now() + ChronoDuration::seconds(REFRESH_SKEW_SECONDS) >= expires_at)
        .unwrap_or(false);

    if !needs_refresh {
        if let Some(access_token) = load_access_token(context_name, token_name)? {
            return Ok(access_token);
        }
    }

    let refresh_token = load_refresh_token(context_name, token_name)?
        .ok_or_else(|| refresh_token_missing_error(context_name, token_name))?;
    refresh_token_for_context(
        client,
        addr,
        context_name,
        token_name,
        &refresh_token,
        config,
    )
    .await
}

pub(crate) async fn refresh_token_for_context(
    client: &reqwest::Client,
    addr: &str,
    context_name: &str,
    token_name: &str,
    refresh_token: &str,
    config: &mut CliConfig,
) -> anyhow::Result<String> {
    let url = format!("{}/v1/auth/refresh", addr.trim_end_matches('/'));
    let payload = RefreshRequest {
        refresh_token: refresh_token.to_string(),
    };
    let response = client.post(url).json(&payload).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Refresh failed: {status} {body}");
    }

    let auth: AuthResponse = response.json().await?;
    let new_expires = (Utc::now() + ChronoDuration::seconds(auth.expires_in as i64)).to_rfc3339();

    store_refresh_token(context_name, token_name, &auth.refresh_token)?;
    store_access_token(context_name, token_name, &auth.access_token)?;
    if let Some(entry) = config
        .contexts
        .get_mut(context_name)
        .and_then(|ctx| ctx.tokens.get_mut(token_name))
    {
        entry.access_expires_at = Some(new_expires);
    }

    Ok(auth.access_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::system::{CliConfig, CliContext, TokenEntry};
    use std::collections::HashMap;

    #[test]
    fn keyring_access_roundtrip() -> anyhow::Result<()> {
        let _guard = lock_keyring_tests_sync();
        clear_keyring_mock();
        store_access_token("ctx", "token", "access")?;
        assert_eq!(
            load_access_token("ctx", "token")?,
            Some("access".to_string())
        );
        delete_access_token("ctx", "token")?;
        assert_eq!(load_access_token("ctx", "token")?, None);
        Ok(())
    }

    #[test]
    fn keyring_refresh_roundtrip() -> anyhow::Result<()> {
        let _guard = lock_keyring_tests_sync();
        clear_keyring_mock();
        store_refresh_token("ctx", "token", "refresh")?;
        assert_eq!(
            load_refresh_token("ctx", "token")?,
            Some("refresh".to_string())
        );
        delete_refresh_token("ctx", "token")?;
        assert_eq!(load_refresh_token("ctx", "token")?, None);
        Ok(())
    }

    #[test]
    fn keyring_service_roundtrip() -> anyhow::Result<()> {
        let _guard = lock_keyring_tests_sync();
        clear_keyring_mock();
        store_service_token("ctx", "token", "service")?;
        assert_eq!(
            load_service_token("ctx", "token")?,
            Some("service".to_string())
        );
        delete_service_token("ctx", "token")?;
        assert_eq!(load_service_token("ctx", "token")?, None);
        Ok(())
    }

    #[tokio::test]
    async fn ensure_access_token_uses_keyring() -> anyhow::Result<()> {
        let _guard = lock_keyring_tests_async().await;
        clear_keyring_mock();
        let mut config = CliConfig {
            current_context: None,
            contexts: HashMap::new(),
            identity: None,
        };
        config.contexts.insert(
            "ctx".to_string(),
            CliContext {
                addr: "http://example".to_string(),
                needs_salt_update: false,
                server_fingerprint: None,
                tokens: HashMap::from([(
                    "token".to_string(),
                    TokenEntry {
                        access_expires_at: None,
                    },
                )]),
                current_token: None,
                vault: None,
            },
        );
        store_access_token("ctx", "token", "access")?;
        let token = ensure_access_token(
            &reqwest::Client::new(),
            "http://example",
            "ctx",
            "token",
            &mut config,
        )
        .await?;
        assert_eq!(token, "access");
        Ok(())
    }
}
