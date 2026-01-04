use reqwest::Method;
use uuid::Uuid;

use crate::modules::items::{CreateItemRequest, UpdateItemRequest};
use crate::modules::system::http::send_request;
use crate::modules::system::CommandContext;

pub(crate) async fn list_items(
    ctx: &mut CommandContext<'_>,
    vault_id: &str,
) -> anyhow::Result<reqwest::Response> {
    let url = format!(
        "{}/v1/vaults/{}/items",
        ctx.addr.trim_end_matches('/'),
        vault_id
    );
    send_request(ctx, Method::GET, url, None).await
}

pub(crate) async fn create_item(
    ctx: &mut CommandContext<'_>,
    vault_id: &str,
    payload: CreateItemRequest,
) -> anyhow::Result<reqwest::Response> {
    let url = format!(
        "{}/v1/vaults/{}/items",
        ctx.addr.trim_end_matches('/'),
        vault_id
    );
    send_request(
        ctx,
        Method::POST,
        url,
        Some(serde_json::to_value(&payload)?),
    )
    .await
}

pub(crate) async fn get_item(
    ctx: &mut CommandContext<'_>,
    vault_id: &str,
    item_id: &Uuid,
) -> anyhow::Result<reqwest::Response> {
    let url = format!(
        "{}/v1/vaults/{}/items/{}",
        ctx.addr.trim_end_matches('/'),
        vault_id,
        item_id
    );
    send_request(ctx, Method::GET, url, None).await
}

pub(crate) async fn update_item(
    ctx: &mut CommandContext<'_>,
    vault_id: &str,
    item_id: &Uuid,
    payload: UpdateItemRequest,
) -> anyhow::Result<reqwest::Response> {
    let url = format!(
        "{}/v1/vaults/{}/items/{}",
        ctx.addr.trim_end_matches('/'),
        vault_id,
        item_id
    );
    send_request(ctx, Method::PUT, url, Some(serde_json::to_value(&payload)?)).await
}

pub(crate) async fn delete_item(
    ctx: &mut CommandContext<'_>,
    vault_id: &str,
    item_id: &Uuid,
) -> anyhow::Result<reqwest::Response> {
    let url = format!(
        "{}/v1/vaults/{}/items/{}",
        ctx.addr.trim_end_matches('/'),
        vault_id,
        item_id
    );
    send_request(ctx, Method::DELETE, url, None).await
}
