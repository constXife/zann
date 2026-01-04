use reqwest::Method;
use uuid::Uuid;

use crate::modules::system::http::{append_params, build_params, opt_param, send_request};
use crate::modules::system::CommandContext;
use crate::modules::users::{CreateUserRequest, ResetPasswordRequest};

pub(crate) async fn list_users(
    ctx: &mut CommandContext<'_>,
    status: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    sort: Option<String>,
) -> anyhow::Result<reqwest::Response> {
    let mut url = format!("{}/v1/users", ctx.addr.trim_end_matches('/'));
    let params = build_params([
        opt_param("status", status),
        opt_param("limit", limit.map(|value| value.to_string())),
        opt_param("offset", offset.map(|value| value.to_string())),
        opt_param("sort", sort),
    ]);
    append_params(&mut url, params);
    send_request(ctx, Method::GET, url, None).await
}

pub(crate) async fn create_user(
    ctx: &mut CommandContext<'_>,
    payload: CreateUserRequest,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}/v1/users", ctx.addr.trim_end_matches('/'));
    send_request(
        ctx,
        Method::POST,
        url,
        Some(serde_json::to_value(&payload)?),
    )
    .await
}

pub(crate) async fn get_user(
    ctx: &mut CommandContext<'_>,
    id: &Uuid,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}/v1/users/{}", ctx.addr.trim_end_matches('/'), id);
    send_request(ctx, Method::GET, url, None).await
}

pub(crate) async fn delete_user(
    ctx: &mut CommandContext<'_>,
    id: &Uuid,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}/v1/users/{}", ctx.addr.trim_end_matches('/'), id);
    send_request(ctx, Method::DELETE, url, None).await
}

pub(crate) async fn block_user(
    ctx: &mut CommandContext<'_>,
    id: &Uuid,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}/v1/users/{}/block", ctx.addr.trim_end_matches('/'), id);
    send_request(ctx, Method::POST, url, None).await
}

pub(crate) async fn unblock_user(
    ctx: &mut CommandContext<'_>,
    id: &Uuid,
) -> anyhow::Result<reqwest::Response> {
    let url = format!("{}/v1/users/{}/unblock", ctx.addr.trim_end_matches('/'), id);
    send_request(ctx, Method::POST, url, None).await
}

pub(crate) async fn reset_password(
    ctx: &mut CommandContext<'_>,
    id: &Uuid,
    payload: ResetPasswordRequest,
) -> anyhow::Result<reqwest::Response> {
    let url = format!(
        "{}/v1/users/{}/reset-password",
        ctx.addr.trim_end_matches('/'),
        id
    );
    send_request(
        ctx,
        Method::POST,
        url,
        Some(serde_json::to_value(&payload)?),
    )
    .await
}
