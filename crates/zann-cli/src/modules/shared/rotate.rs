use reqwest::Method;
use uuid::Uuid;

use crate::modules::shared::{
    RotateAbortRequest, RotateStartRequest, RotationCandidateResponse, RotationCommitResponse,
    RotationStatusResponse,
};
use crate::modules::system::http::send_json;
use crate::modules::system::CommandContext;

pub(crate) async fn rotate_start(
    ctx: &mut CommandContext<'_>,
    item_id: Uuid,
    payload: RotateStartRequest,
) -> anyhow::Result<RotationCandidateResponse> {
    let url = format!(
        "{}/v1/shared/items/{}/rotate/start",
        ctx.addr.trim_end_matches('/'),
        item_id
    );
    send_json(
        ctx,
        Method::POST,
        url,
        Some(serde_json::to_value(&payload)?),
    )
    .await
}

pub(crate) async fn rotate_status(
    ctx: &mut CommandContext<'_>,
    item_id: Uuid,
) -> anyhow::Result<RotationStatusResponse> {
    let url = format!(
        "{}/v1/shared/items/{}/rotate/status",
        ctx.addr.trim_end_matches('/'),
        item_id
    );
    send_json(ctx, Method::GET, url, None).await
}

pub(crate) async fn rotate_candidate(
    ctx: &mut CommandContext<'_>,
    item_id: Uuid,
) -> anyhow::Result<RotationCandidateResponse> {
    let url = format!(
        "{}/v1/shared/items/{}/rotate/candidate",
        ctx.addr.trim_end_matches('/'),
        item_id
    );
    send_json(ctx, Method::GET, url, None).await
}

pub(crate) async fn rotate_commit(
    ctx: &mut CommandContext<'_>,
    item_id: Uuid,
) -> anyhow::Result<RotationCommitResponse> {
    let url = format!(
        "{}/v1/shared/items/{}/rotate/commit",
        ctx.addr.trim_end_matches('/'),
        item_id
    );
    send_json(ctx, Method::POST, url, None).await
}

pub(crate) async fn rotate_abort(
    ctx: &mut CommandContext<'_>,
    item_id: Uuid,
    payload: RotateAbortRequest,
) -> anyhow::Result<RotationStatusResponse> {
    let url = format!(
        "{}/v1/shared/items/{}/rotate/abort",
        ctx.addr.trim_end_matches('/'),
        item_id
    );
    send_json(
        ctx,
        Method::POST,
        url,
        Some(serde_json::to_value(&payload)?),
    )
    .await
}

pub(crate) async fn rotate_recover(
    ctx: &mut CommandContext<'_>,
    item_id: Uuid,
) -> anyhow::Result<RotationCandidateResponse> {
    let url = format!(
        "{}/v1/shared/items/{}/rotate/recover",
        ctx.addr.trim_end_matches('/'),
        item_id
    );
    send_json(ctx, Method::GET, url, None).await
}
