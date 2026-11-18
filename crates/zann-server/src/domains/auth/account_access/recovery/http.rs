use super::*;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
type HttpResult<T> = std::result::Result<T, Failure>;
struct Failure(AccessError);
impl From<AccessError> for Failure {
    fn from(error: AccessError) -> Self {
        Self(error)
    }
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        // Reuse causal/redacted diagnostics and status classification from the
        // auth owner. Recovery exposes only its closed protocol error codes.
        let response = self.0.into_response();
        let status = response.status();
        let code = match status {
            StatusCode::UNAUTHORIZED => "recovery_rejected",
            StatusCode::GONE => "recovery_stopped",
            StatusCode::CONFLICT => "mutation_conflict",
            StatusCode::TOO_MANY_REQUESTS => "recovery_rate_limit",
            StatusCode::SERVICE_UNAVAILABLE => "recovery_unavailable",
            StatusCode::BAD_REQUEST => "invalid_request",
            StatusCode::FORBIDDEN => "recovery_disabled",
            _ => "recovery_failed",
        };
        (
            status,
            Json(zann_core::api::auth::ApiErrorResponse::new(code)),
        )
            .into_response()
    }
}
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/recover", post(consume))
        .route("/v1/auth/recover/:id", get(status))
        .route("/v1/auth/recover/:id/credential/options", post(options))
        .route(
            "/v1/auth/recover/:id/credential/finish",
            post(finish_credential),
        )
        .route("/v1/auth/recover/:id/complete", post(complete))
        .route("/v1/auth/recover/:id/abandon", post(abandon))
        .route("/v1/auth/recover/:id/data", get(keys))
}
fn header(state: &AppState, headers: &HeaderMap) -> Result<(Uuid, Zeroizing<String>)> {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(AccessError::Rejected);
    }
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Recovery "))
        .ok_or(AccessError::Rejected)?;
    let (id, token) = value.split_once('.').ok_or(AccessError::Rejected)?;
    let operation: Uuid = id.parse().map_err(|_| AccessError::Rejected)?;
    if operation.get_version_num() != 4 || operation.to_string() != id {
        return Err(AccessError::Rejected);
    }
    Ok((
        operation,
        Zeroizing::new(zann_crypto::recovery::resume_token_hash(
            operation,
            token,
            &state.token_pepper,
        )?),
    ))
}
async fn actor(state: &AppState, id: Uuid, headers: &HeaderMap) -> Result<ResumeAuthority> {
    relying_party(state)?;
    let (bound, hash) = header(state, headers)?;
    if bound != id {
        return Err(AccessError::Rejected);
    }
    // Authenticate first: unauthenticated ids must not allocate limiter entries.
    let authority = ResumeAuthority::authenticate(state, id, hash).await?;
    state.account_access.admission.resume(id)?;
    Ok(authority)
}
async fn consume(
    State(state): State<AppState>,
    remote: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> HttpResult<Json<RecoveryConsumeReceipt>> {
    let input: RecoveryConsume = super::super::http::input(&body, 8192)?;
    let (id, hash) = header(&state, &headers)?;
    if id != input.operation_id {
        return Err(AccessError::Rejected.into());
    }
    let ip = crate::infra::request_context::client_ip(&headers, remote.map(|r| r.0), Some(&state));
    state
        .account_access
        .admission
        .consume(&input.locator, ip.as_deref())?;
    super::consume::consume(&state, &input, hash)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> HttpResult<Json<RecoveryView>> {
    let actor = actor(&state, id, &headers).await?;
    super::view(&state, &actor)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn options(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> HttpResult<Json<RecoveryStepReply>> {
    let actor = actor(&state, id, &headers).await?;
    let input: RecoveryCredentialOptions = super::super::http::input(&body, 8192)?;
    super::credential::options(&state, &actor, &input)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn finish_credential(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> HttpResult<Json<RecoveryStepReply>> {
    let actor = actor(&state, id, &headers).await?;
    let input: RecoveryCredentialFinish = super::super::http::input(&body, MAX_CEREMONY_BYTES)?;
    super::credential::finish(&state, &actor, &input)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn complete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> HttpResult<Json<RecoveryStepReply>> {
    let actor = actor(&state, id, &headers).await?;
    let input: RecoveryComplete = super::super::http::input(&body, 8192)?;
    super::finish::complete(&state, &actor, &input)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn abandon(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> HttpResult<Json<RecoveryStepReply>> {
    let actor = actor(&state, id, &headers).await?;
    let input: RecoveryAbandon = super::super::http::input(&body, 8192)?;
    super::finish::abandon(&state, &actor, &input)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn keys(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> HttpResult<Json<RecoveryKeyMaterial>> {
    let actor = actor(&state, id, &headers).await?;
    super::data::keys(&state, &actor)
        .await
        .map(Json)
        .map_err(Into::into)
}
