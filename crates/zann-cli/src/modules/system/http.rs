use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::Deserialize;
use tracing::{debug, info};

use crate::modules::auth::{
    auth_headers, load_refresh_token, refresh_token_for_context, refresh_token_missing_error,
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

    info!(method = %method, url = %url, "http request unauthorized; attempting refresh");

    let Some(context_name) = ctx.context_name.clone() else {
        return Ok(response);
    };
    let Some(token_name) = ctx.token_name.clone() else {
        return Ok(response);
    };

    let refresh_token = load_refresh_token(&context_name, &token_name)?
        .ok_or_else(|| refresh_token_missing_error(&context_name, &token_name))?;

    let new_token = refresh_token_for_context(
        ctx.client,
        ctx.addr,
        &context_name,
        &token_name,
        &refresh_token,
        ctx.config,
    )
    .await?;
    ctx.access_token = new_token;

    response = send_request_once(ctx, method, &url, payload).await?;
    Ok(response)
}

pub(crate) async fn send_request_once(
    ctx: &CommandContext<'_>,
    method: Method,
    url: &str,
    payload: Option<serde_json::Value>,
) -> anyhow::Result<reqwest::Response> {
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

pub(crate) async fn print_empty_response(
    response: reqwest::Response,
    message: &str,
) -> anyhow::Result<()> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Request failed: {status} {body}");
    }
    println!("{message}");
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

pub(crate) fn parse_base64(value: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("invalid base64 value");
    }
    Ok(base64::engine::general_purpose::STANDARD.decode(trimmed)?)
}

pub(crate) async fn send_json<T: for<'de> Deserialize<'de>>(
    ctx: &mut CommandContext<'_>,
    method: Method,
    url: String,
    payload: Option<serde_json::Value>,
) -> anyhow::Result<T> {
    let response = send_request(ctx, method, url, payload).await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Request failed: {status} {body}");
    }
    Ok(response.json::<T>().await?)
}
