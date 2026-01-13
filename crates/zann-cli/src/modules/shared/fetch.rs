use uuid::Uuid;

use crate::modules::shared::{
    cursor_allows, encode_cursor, normalize_prefix, parse_cursor, parse_item_timestamp,
    prefix_match, ItemSummaryResponse, ItemsResponse, SharedItemResponse, SharedItemsResponse,
};
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
    let items = fetch_item_summaries(client, addr, access_token, vault_id, prefix).await?;
    let limit = limit.unwrap_or(100).clamp(1, 500) as usize;
    let cursor = cursor.and_then(parse_cursor);
    let prefix = normalize_prefix(prefix);

    let mut page = Vec::new();
    let mut has_more = false;
    let mut last_cursor = None;

    for item in items {
        if !prefix_match(prefix.as_deref(), &item.path) {
            continue;
        }
        let updated_at = parse_item_timestamp(&item.updated_at)?;
        let item_id = Uuid::parse_str(&item.id)
            .map_err(|err| anyhow::anyhow!("invalid item id {}: {err}", item.id))?;
        if !cursor_allows(cursor.as_ref(), updated_at, item_id) {
            continue;
        }
        if page.len() >= limit {
            has_more = true;
            break;
        }
        last_cursor = Some((updated_at, item_id));
        page.push(item);
    }

    let mut response_items = Vec::with_capacity(page.len());
    for item in page {
        let item_id = Uuid::parse_str(&item.id)
            .map_err(|err| anyhow::anyhow!("invalid item id {}: {err}", item.id))?;
        let item = fetch_shared_item(client, addr, access_token, vault_id, item_id).await?;
        response_items.push(item);
    }

    Ok(SharedItemsResponse {
        items: response_items,
        next_cursor: if has_more {
            last_cursor.map(|(ts, id)| encode_cursor(&ts, id))
        } else {
            None
        },
    })
}

pub(crate) async fn fetch_shared_item(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
    vault_id: &str,
    item_id: Uuid,
) -> anyhow::Result<SharedItemResponse> {
    let url = format!(
        "{}/v1/vaults/{}/items/{}",
        addr.trim_end_matches('/'),
        vault_id,
        item_id
    );
    let response = client.get(url).bearer_auth(access_token).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Shared get failed: {status} {body}");
    }
    Ok(response.json::<SharedItemResponse>().await?)
}

async fn fetch_item_summaries(
    client: &reqwest::Client,
    addr: &str,
    access_token: &str,
    vault_id: &str,
    prefix: Option<&str>,
) -> anyhow::Result<Vec<ItemSummaryResponse>> {
    let mut url = format!(
        "{}/v1/vaults/{}/items",
        addr.trim_end_matches('/'),
        vault_id
    );
    let params = build_params([opt_param(
        "prefix",
        normalize_prefix(prefix).map(|value| value.to_string()),
    )]);
    append_params(&mut url, params);
    let response = client.get(url).bearer_auth(access_token).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Items list failed: {status} {body}");
    }
    Ok(response.json::<ItemsResponse>().await?.items)
}
