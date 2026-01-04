use reqwest::Method;

use crate::modules::system::http::{append_params, build_params, opt_param, send_request};
use crate::modules::system::CommandContext;
use crate::modules::vaults::CreateVaultRequest;

pub(crate) async fn list_vaults(
    ctx: &mut CommandContext<'_>,
    limit: Option<i64>,
    offset: Option<i64>,
    sort: Option<String>,
) -> anyhow::Result<reqwest::Response> {
    let mut url = format!("{}/v1/vaults", ctx.addr.trim_end_matches('/'));
    let params = build_params([
        opt_param("limit", limit.map(|value| value.to_string())),
        opt_param("offset", offset.map(|value| value.to_string())),
        opt_param("sort", sort),
    ]);
    append_params(&mut url, params);
    send_request(ctx, Method::GET, url, None).await
}

pub(crate) async fn create_vault(
    ctx: &mut CommandContext<'_>,
    payload: CreateVaultRequest,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}/v1/vaults", ctx.addr.trim_end_matches('/'));
    send_request(
        ctx,
        Method::POST,
        url,
        Some(serde_json::to_value(&payload)?),
    )
    .await
}

pub(crate) async fn get_vault(
    ctx: &mut CommandContext<'_>,
    id_or_slug: &str,
) -> anyhow::Result<reqwest::Response> {
    let url = format!(
        "{}/v1/vaults/{}",
        ctx.addr.trim_end_matches('/'),
        id_or_slug
    );
    send_request(ctx, Method::GET, url, None).await
}

pub(crate) async fn delete_vault(
    ctx: &mut CommandContext<'_>,
    id_or_slug: &str,
) -> anyhow::Result<reqwest::Response> {
    let url = format!(
        "{}/v1/vaults/{}",
        ctx.addr.trim_end_matches('/'),
        id_or_slug
    );
    send_request(ctx, Method::DELETE, url, None).await
}
