use uuid::Uuid;

use crate::modules::shared::{SharedItemResponse, SharedItemsResponse};
use crate::modules::system::http::{append_params, build_params, opt_param};

pub(crate) async fn fetch_shared_items(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
    vault_id: &str,
    prefix: Option<&str>,
    limit: Option<i64>,
    cursor: Option<&str>,
) -> anyhow::Result<SharedItemsResponse> {
    let mut url = format!("{}/v1/shared/items", addr.trim_end_matches('/'));
    let params = build_params([
        Some(("vault_id".to_string(), vault_id.to_string())),
        opt_param("prefix", prefix.map(|value| value.to_string())),
        opt_param("limit", limit.map(|value| value.to_string())),
        opt_param("cursor", cursor.map(|value| value.to_string())),
    ]);
    append_params(&mut url, params);
    let response = client.get(url).bearer_auth(access_token).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Shared list failed: {status} {body}");
    }
    Ok(response.json::<SharedItemsResponse>().await?)
}

pub(crate) async fn fetch_shared_item(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
    item_id: Uuid,
) -> anyhow::Result<SharedItemResponse> {
    let url = format!("{}/v1/shared/items/{}", addr.trim_end_matches('/'), item_id);
    let response = client.get(url).bearer_auth(access_token).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Shared get failed: {status} {body}");
    }
    Ok(response.json::<SharedItemResponse>().await?)
}
