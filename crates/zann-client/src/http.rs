use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::de::DeserializeOwned;

pub fn auth_headers(token: &str) -> Result<HeaderMap, String> {
    if token.trim().is_empty() {
        return Err("token is required".to_string());
    }
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|err| err.to_string())?;
    headers.insert(AUTHORIZATION, value);
    Ok(headers)
}

pub async fn status_body(response: reqwest::Response) -> String {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    format!("{status} {body}")
}

pub async fn ensure_success(response: reqwest::Response) -> Result<reqwest::Response, String> {
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(status_body(response).await)
    }
}

pub async fn decode_json_response<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, String> {
    let status = response.status();
    let body = response.text().await.map_err(|err| err.to_string())?;
    serde_json::from_str::<T>(&body).map_err(|err| {
        let snippet: String = body.chars().take(512).collect();
        format!("error decoding response body: {err} (status {status}) body: {snippet}")
    })
}

pub async fn fetch_json<T: for<'de> serde::Deserialize<'de>>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    let response = client.get(url).send().await.map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Request failed: {status} {body}"));
    }
    response
        .json::<T>()
        .await
        .map_err(|err| err.to_string())
}
