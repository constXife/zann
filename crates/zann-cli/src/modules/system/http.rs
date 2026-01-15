use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::Method;
use serde::Deserialize;
use tracing::{debug, info};

use crate::modules::auth::{
    auth_headers, exchange_service_account_token, load_service_token, store_access_token,
    verify_server_fingerprint,
};
use crate::modules::system::CommandContext;

pub(crate) async fn send_request(
    ctx: &mut CommandContext<'_>,
    method: Method,
    url: String,
    payload: Option<serde_json::Value>,
) -> anyhow::Result<reqwest::Response> {
    let mut response = send_request_once(ctx, method.clone(), &url, payload.clone()).await?;
    if response.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Ok(response);
    }

    info!(
        method = %method,
        url = %url,
        "http request unauthorized; attempting service token exchange"
    );

    let Some(context_name) = ctx.context_name.clone() else {
        return Ok(response);
    };
    let Some(token_name) = ctx.token_name.clone() else {
        return Ok(response);
    };

    let Some(service_account_token) = load_service_token(&context_name, &token_name)? else {
        return Ok(response);
    };

    let info = fetch_system_info(ctx.client, ctx.addr).await?;
    verify_server_fingerprint(
        ctx.config,
        Some(&context_name),
        ctx.addr,
        &info.server_fingerprint,
    )?;
    let auth = exchange_service_account_token(ctx.client, ctx.addr, &service_account_token).await?;
    let new_expires =
        (Utc::now() + ChronoDuration::seconds(auth.expires_in as i64)).to_rfc3339();
    store_access_token(&context_name, &token_name, &auth.access_token)?;
    if let Some(entry) = ctx
        .config
        .contexts
        .get_mut(&context_name)
        .and_then(|context| context.tokens.get_mut(&token_name))
    {
        entry.access_expires_at = Some(new_expires);
    }
    ctx.access_token = auth.access_token;

    response = send_request_once(ctx, method, &url, payload).await?;
    Ok(response)
}

pub(crate) async fn send_request_once(
    ctx: &CommandContext<'_>,
    method: Method,
    url: &str,
    payload: Option<serde_json::Value>,
) -> anyhow::Result<reqwest::Response> {
    if url.starts_with("http://") && !ctx.allow_insecure {
        anyhow::bail!("refusing to use http:// without --insecure");
    }
    let headers = auth_headers(&ctx.access_token)?;
    let method_clone = method.clone();
    let builder = ctx.client.request(method, url).headers(headers);
    let builder = if let Some(payload) = payload {
        builder.json(&payload)
    } else {
        builder
    };
    debug!(method = %method_clone, url = %url, "http request");
    let start = std::time::Instant::now();
    let response = builder.send().await?;
    debug!(
        method = %method_clone,
        url = %url,
        status = %response.status(),
        elapsed_ms = start.elapsed().as_millis(),
        "http response"
    );
    Ok(response)
}

pub(crate) async fn print_json_response(response: reqwest::Response) -> anyhow::Result<()> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Request failed: {status} {body}");
    }
    let body: serde_json::Value = response.json().await?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

pub(crate) async fn fetch_json<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<T> {
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Request failed: {status} {body}");
    }
    Ok(response.json::<T>().await?)
}

pub(crate) async fn fetch_system_info(
    client: &reqwest::Client,
    addr: &str,
) -> anyhow::Result<crate::modules::system::SystemInfoResponse> {
    let url = format!("{}/v1/system/info", addr.trim_end_matches('/'));
    fetch_json(client, &url).await
}

pub(crate) fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

pub(crate) fn build_params<const N: usize>(
    pairs: [Option<(String, String)>; N],
) -> Vec<(String, String)> {
    pairs.into_iter().flatten().collect()
}

pub(crate) fn opt_param(key: &str, value: Option<String>) -> Option<(String, String)> {
    value.map(|value| (key.to_string(), value))
}

pub(crate) fn append_params(url: &mut String, params: Vec<(String, String)>) {
    if params.is_empty() {
        return;
    }
    let query = params
        .into_iter()
        .map(|(key, value)| format!("{}={}", key, urlencoding::encode(&value)))
        .collect::<Vec<String>>()
        .join("&");
    url.push('?');
    url.push_str(&query);
}
