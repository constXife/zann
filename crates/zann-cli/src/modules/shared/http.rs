use serde_json::Value as JsonValue;

use crate::modules::shared::{SharedItemResponse, VaultListResponse};

pub(crate) async fn fetch_vaults(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
) -> anyhow::Result<VaultListResponse> {
    let url = format!("{}/v1/vaults", addr.trim_end_matches('/'));
    let response = client.get(url).bearer_auth(access_token).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Vault list failed: {status} {body}");
    }
    Ok(response.json::<VaultListResponse>().await?)
}

pub(crate) async fn create_shared_item(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
    vault_id: &str,
    path: &str,
    type_id: &str,
    payload: JsonValue,
) -> anyhow::Result<SharedItemResponse> {
    let url = format!("{}/v1/shared/items", addr.trim_end_matches('/'));
    let body = serde_json::json!({
        "vault_id": vault_id,
        "path": path,
        "type_id": type_id,
        "payload": payload,
    });
    let response = client
        .post(url)
        .bearer_auth(access_token)
        .json(&body)
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Create failed: {status} {body}");
    }
    Ok(response.json::<SharedItemResponse>().await?)
}

pub(crate) async fn update_shared_item(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
    item_id: &str,
    payload: JsonValue,
) -> anyhow::Result<SharedItemResponse> {
    let url = format!(
        "{}/v1/shared/items/{}",
        addr.trim_end_matches('/'),
        item_id
    );
    let body = serde_json::json!({
        "payload": payload,
    });
    let response = client
        .put(url)
        .bearer_auth(access_token)
        .json(&body)
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Update failed: {status} {body}");
    }
    Ok(response.json::<SharedItemResponse>().await?)
}

pub(crate) async fn delete_shared_item(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
    item_id: &str,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/v1/shared/items/{}",
        addr.trim_end_matches('/'),
        item_id
    );
    let response = client
        .delete(url)
        .bearer_auth(access_token)
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Delete failed: {status} {body}");
    }
    Ok(())
}
