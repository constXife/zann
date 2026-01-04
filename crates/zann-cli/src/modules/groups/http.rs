use reqwest::Method;
use uuid::Uuid;

use crate::modules::groups::{AddMemberRequest, CreateGroupRequest, UpdateGroupRequest};
use crate::modules::system::http::{append_params, build_params, opt_param, send_request};
use crate::modules::system::CommandContext;

pub(crate) async fn list_groups(
    ctx: &mut CommandContext<'_>,
    limit: Option<i64>,
    offset: Option<i64>,
    sort: Option<String>,
) -> anyhow::Result<reqwest::Response> {
    let mut url = format!("{}/v1/groups", ctx.addr.trim_end_matches('/'));
    let params = build_params([
        opt_param("limit", limit.map(|value| value.to_string())),
        opt_param("offset", offset.map(|value| value.to_string())),
        opt_param("sort", sort),
    ]);
    append_params(&mut url, params);
    send_request(ctx, Method::GET, url, None).await
}

pub(crate) async fn create_group(
    ctx: &mut CommandContext<'_>,
    payload: CreateGroupRequest,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}/v1/groups", ctx.addr.trim_end_matches('/'));
    send_request(
        ctx,
        Method::POST,
        url,
        Some(serde_json::to_value(&payload)?),
    )
    .await
}

pub(crate) async fn get_group(
    ctx: &mut CommandContext<'_>,
    slug: &str,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}/v1/groups/{}", ctx.addr.trim_end_matches('/'), slug);
    send_request(ctx, Method::GET, url, None).await
}

pub(crate) async fn update_group(
    ctx: &mut CommandContext<'_>,
    slug: &str,
    payload: UpdateGroupRequest,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}/v1/groups/{}", ctx.addr.trim_end_matches('/'), slug);
    send_request(ctx, Method::PUT, url, Some(serde_json::to_value(&payload)?)).await
}

pub(crate) async fn delete_group(
    ctx: &mut CommandContext<'_>,
    slug: &str,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}/v1/groups/{}", ctx.addr.trim_end_matches('/'), slug);
    send_request(ctx, Method::DELETE, url, None).await
}

pub(crate) async fn add_member(
    ctx: &mut CommandContext<'_>,
    slug: &str,
    payload: AddMemberRequest,
) -> anyhow::Result<reqwest::Response> {
    let url = format!(
        "{}/v1/groups/{}/members",
        ctx.addr.trim_end_matches('/'),
        slug
    );
    send_request(
        ctx,
        Method::POST,
        url,
        Some(serde_json::to_value(&payload)?),
    )
    .await
}

pub(crate) async fn remove_member(
    ctx: &mut CommandContext<'_>,
    slug: &str,
    user_id: &Uuid,
) -> anyhow::Result<reqwest::Response> {
    let url = format!(
        "{}/v1/groups/{}/members/{}",
        ctx.addr.trim_end_matches('/'),
        slug,
        user_id
    );
    send_request(ctx, Method::DELETE, url, None).await
}
