use super::items::{fetch_item_summaries, fetch_shared_item};
use super::{ServerClient, ServerError};
use uuid::Uuid;
use zann_core::api::items::*;

pub fn normalize_prefix(prefix: Option<&str>) -> Option<String> {
    let trimmed = prefix?.trim().trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

pub fn prefix_match(prefix: Option<&str>, path: &str) -> bool {
    let Some(prefix) = prefix else {
        return true;
    };
    let path = path.trim().trim_matches('/').to_string();
    path == prefix || path.starts_with(&format!("{}/", prefix))
}

pub fn parse_cursor(cursor: &str) -> Option<(chrono::DateTime<chrono::Utc>, uuid::Uuid)> {
    let (ts, id) = cursor.split_once('|')?;
    let ts = chrono::DateTime::parse_from_rfc3339(ts)
        .ok()?
        .with_timezone(&chrono::Utc);
    let id = uuid::Uuid::parse_str(id).ok()?;
    Some((ts, id))
}

pub fn encode_cursor(timestamp: &chrono::DateTime<chrono::Utc>, item_id: uuid::Uuid) -> String {
    format!("{}|{}", timestamp.to_rfc3339(), item_id)
}

pub fn cursor_allows(
    cursor: Option<&(chrono::DateTime<chrono::Utc>, uuid::Uuid)>,
    updated_at: chrono::DateTime<chrono::Utc>,
    item_id: uuid::Uuid,
) -> bool {
    let Some((cursor_ts, cursor_id)) = cursor else {
        return true;
    };
    updated_at < *cursor_ts || (updated_at == *cursor_ts && item_id < *cursor_id)
}

pub fn parse_item_timestamp(value: &str) -> Result<chrono::DateTime<chrono::Utc>, ServerError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|ts| ts.with_timezone(&chrono::Utc))
        .map_err(Into::into)
}

pub async fn fetch_shared_items(
    client: &ServerClient,
    addr: &str,
    access_token: &str,
    vault_id: &str,
    prefix: Option<&str>,
    limit: Option<i64>,
    cursor: Option<&str>,
) -> Result<SharedItemsResponse, ServerError> {
    let summaries =
        fetch_shared_item_summaries(client, addr, access_token, vault_id, prefix, limit, cursor)
            .await?;

    let mut response_items = Vec::with_capacity(summaries.items.len());
    for item in summaries.items {
        let item_id = Uuid::parse_str(&item.id)?;
        let item = fetch_shared_item(client, addr, access_token, vault_id, item_id).await?;
        response_items.push(item);
    }

    Ok(SharedItemsResponse {
        items: response_items,
        next_cursor: summaries.next_cursor,
    })
}

pub async fn fetch_shared_item_summaries(
    client: &ServerClient,
    addr: &str,
    access_token: &str,
    vault_id: &str,
    prefix: Option<&str>,
    limit: Option<i64>,
    cursor: Option<&str>,
) -> Result<SharedItemSummariesResponse, ServerError> {
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
        let item_id = Uuid::parse_str(&item.id)?;
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

    Ok(SharedItemSummariesResponse {
        items: page,
        next_cursor: if has_more {
            last_cursor.map(|(ts, id)| encode_cursor(&ts, id))
        } else {
            None
        },
    })
}
