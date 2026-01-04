use reqwest::header::AUTHORIZATION;
use serde::Deserialize;

use crate::infra::http::fetch_json;
use crate::types::{
    OidcConfigResponse, OidcDiscovery, OidcExchangeResponse, SystemInfoResponse, TokenErrorResponse,
    TokenResponse,
};

pub async fn exchange_authorization_code(
    client: &reqwest::Client,
    discovery: &OidcDiscovery,
    oidc: &OidcConfigResponse,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenResponse, String> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", oidc.client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
    ];
    let response = client
        .post(&discovery.token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if response.status().is_success() {
        return response
            .json::<TokenResponse>()
            .await
            .map_err(|err| err.to_string());
    }

    let error = response
        .json::<TokenErrorResponse>()
        .await
        .unwrap_or(TokenErrorResponse {
            error: "unknown".to_string(),
            error_description: None,
        });
    Err(error.error)
}

pub async fn exchange_oidc_for_session(
    client: &reqwest::Client,
    server_url: &str,
    oidc_token: &str,
) -> Result<OidcExchangeResponse, String> {
    let url = format!("{}/v1/auth/login/oidc", server_url.trim_end_matches('/'));
    let body = serde_json::json!({ "token": oidc_token });

    let response = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("OIDC exchange failed: {status} {body}"));
    }

    response
        .json::<OidcExchangeResponse>()
        .await
        .map_err(|e| e.to_string())
}

pub async fn fetch_system_info(
    client: &reqwest::Client,
    addr: &str,
) -> Result<SystemInfoResponse, String> {
    let url = format!("{}/v1/system/info", addr.trim_end_matches('/'));
    fetch_json(client, &url).await
}

pub async fn fetch_me_email(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
) -> Result<String, String> {
    #[derive(Deserialize)]
    struct MeResponse {
        email: String,
    }
    let url = format!("{}/v1/users/me", addr.trim_end_matches('/'));
    let response = client
        .get(url)
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Failed to fetch user profile: {status} {body}"));
    }
    let me: MeResponse = response.json().await.map_err(|err| err.to_string())?;
    Ok(me.email)
}

pub async fn fetch_prelogin(
    client: &reqwest::Client,
    addr: &str,
    email: &str,
) -> Result<zann_core::api::auth::PreloginResponse, String> {
    let base = format!("{}/v1/auth/prelogin", addr.trim_end_matches('/'));
    let mut url = reqwest::Url::parse(&base).map_err(|err| err.to_string())?;
    url.query_pairs_mut().append_pair("email", email);
    let response = client.get(url).send().await.map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Prelogin failed: {status} {body}"));
    }
    response
        .json::<zann_core::api::auth::PreloginResponse>()
        .await
        .map_err(|err| err.to_string())
}
