use reqwest::Method;
use uuid::Uuid;

use crate::modules::system::http::{append_params, build_params, opt_param, send_request};
use crate::modules::system::CommandContext;

pub(crate) async fn list_devices(
    ctx: &mut CommandContext<'_>,
    limit: Option<i64>,
    offset: Option<i64>,
    sort: Option<String>,
) -> anyhow::Result<reqwest::Response> {
    let mut url = format!("{}/v1/devices", ctx.addr.trim_end_matches('/'));
    let params = build_params([
        opt_param("limit", limit.map(|value| value.to_string())),
        opt_param("offset", offset.map(|value| value.to_string())),
        opt_param("sort", sort),
    ]);
    append_params(&mut url, params);
    send_request(ctx, Method::GET, url, None).await
}

pub(crate) async fn current_device(
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}/v1/devices/current", ctx.addr.trim_end_matches('/'));
    send_request(ctx, Method::GET, url, None).await
}

pub(crate) async fn revoke_device(
    ctx: &mut CommandContext<'_>,
    device_id: &Uuid,
) -> anyhow::Result<reqwest::Response> {
    let url = format!(
        "{}/v1/devices/{}",
        ctx.addr.trim_end_matches('/'),
        device_id
    );
    send_request(ctx, Method::DELETE, url, None).await
}
