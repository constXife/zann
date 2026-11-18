//! Explicit, bounded RP handlers. No cookies, redirects or server-page PRF handling.
use super::*;
use crate::app::AppState;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::de::DeserializeOwned;
use uuid::Uuid;
use zann_core::{api::account_access::*, Session};
use zann_db::repo::{AccountAccessStoreError, SessionRepo, SessionWriteError, UserRepo};

mod actor;
use actor::ManagementActor;

pub fn router() -> Router<AppState> {
    let managed = Router::new()
        .route("/v1/users/me/security", get(security_snapshot))
        .route(
            "/v1/users/me/security/descriptor",
            post(descriptor_bootstrap),
        )
        .route(
            "/v1/users/me/security/custody/options",
            post(custody_options),
        )
        .route("/v1/users/me/security/uv/:id/options", post(uv_options))
        .route(
            "/v1/users/me/security/recovery-code/activate",
            post(activate_code),
        )
        .route("/v1/users/me/passkeys/options", post(enrollment_options))
        .route("/v1/users/me/passkeys/register", post(enrollment_register))
        .route("/v1/users/me/passkeys/test", post(enrollment_test))
        .route("/v1/users/me/passkeys/test/options", post(test_options))
        .route("/v1/users/me/passkeys/grant", post(enrollment_grant))
        .route("/v1/users/me/passkeys/activate", post(enrollment_activate))
        .route("/v1/users/me/passkeys/revoke", post(revoke))
        .layer(middleware::from_fn(
            crate::domains::auth::core::auth_middleware,
        ));
    Router::new()
        .route("/v1/auth/passkeys/config", get(config))
        .route("/v1/auth/passkeys/login/options", post(login_options))
        .route("/v1/auth/passkeys/login/finish", post(login_finish))
        .merge(managed)
        .merge(super::recovery::router())
        .layer(DefaultBodyLimit::max(MAX_CEREMONY_BYTES))
        .layer(middleware::map_response(
            |mut response: Response| async move {
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    header::HeaderValue::from_static("no-store"),
                );
                response
            },
        ))
}
pub(super) fn input<T: DeserializeOwned>(body: &[u8], limit: usize) -> Result<T> {
    if body.len() > limit {
        return Err(AccessError::BadRequest("request_too_large"));
    }
    zann_core::bounded_json::validate_json_shape(body, 256).map_err(AccessError::InvalidJson)?;
    serde_json::from_slice(body).map_err(AccessError::InvalidJson)
}
pub(super) async fn session(state: &AppState, headers: &HeaderMap) -> Result<Session> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AccessError::Rejected)?;
    if token.len() > 256 || token.contains('.') || token.starts_with("zann_sa_") {
        return Err(AccessError::Rejected);
    }
    let hash = crate::domains::auth::core::tokens::hash_token(token, &state.token_pepper);
    let session = SessionRepo::new(&state.db)
        .get_by_access_token_hash(&hash)
        .await?
        .ok_or(AccessError::Rejected)?;
    if session.access_expires_at <= Utc::now() {
        return Err(AccessError::Rejected);
    }
    Ok(session)
}
async fn config(State(state): State<AppState>) -> Result<Json<PasskeyConfiguration>> {
    security::configuration(&state).await.map(Json)
}
async fn security_snapshot(
    State(state): State<AppState>,
    actor: ManagementActor,
) -> Result<Json<AccountSecurity>> {
    let session = actor.0;
    security::snapshot(&state, &session).await.map(Json)
}
async fn descriptor_bootstrap(
    State(state): State<AppState>,
    actor: ManagementActor,
    body: Bytes,
) -> Result<Json<AccountSecurity>> {
    let session = actor.0;
    let data: DescriptorBootstrap = input(&body, 8192)?;
    state.account_access.admission.resume(session.id)?;
    security::bootstrap_descriptor(&state, &session, &data)
        .await
        .map(Json)
}
async fn custody_options(
    State(state): State<AppState>,
    actor: ManagementActor,
    body: Bytes,
) -> Result<Json<MutationContext>> {
    let session = actor.0;
    let data: MutationOptions = input(&body, 8192)?;
    state.account_access.admission.resume(session.id)?;
    security::custody_options(&state, &session, &data)
        .await
        .map(Json)
}
async fn uv_options(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: ManagementActor,
    body: Bytes,
) -> Result<Json<CeremonyOptions>> {
    let session = actor.0;
    let data: UvAuthorizationRequest = input(&body, 8192)?;
    state.account_access.admission.resume(session.id)?;
    security::uv_options(&state, &session, id, &data)
        .await
        .map(Json)
}
async fn enrollment_options(
    State(state): State<AppState>,
    actor: ManagementActor,
    body: Bytes,
) -> Result<Json<CeremonyOptions>> {
    let session = actor.0;
    let data: EnrollmentRequest = input(&body, 8192)?;
    state.account_access.admission.resume(session.id)?;
    let user = UserRepo::new(&state.db)
        .get_by_id(session.user_id)
        .await?
        .ok_or(AccessError::Rejected)?;
    enrollment::options(&state, &session, &user, &data)
        .await
        .map(Json)
}
async fn enrollment_register(
    State(state): State<AppState>,
    actor: ManagementActor,
    body: Bytes,
) -> Result<Json<CeremonyOptions>> {
    let session = actor.0;
    let data: CeremonyFinish = input(&body, MAX_CEREMONY_BYTES)?;
    state.account_access.admission.resume(session.id)?;
    enrollment::register(&state, &session, &data)
        .await
        .map(Json)
}
async fn enrollment_test(
    State(state): State<AppState>,
    actor: ManagementActor,
    body: Bytes,
) -> Result<Json<CandidateReceipt>> {
    let session = actor.0;
    let data: CeremonyFinish = input(&body, MAX_CEREMONY_BYTES)?;
    state.account_access.admission.resume(session.id)?;
    enrollment::test(&state, &session, &data).await.map(Json)
}
async fn enrollment_grant(
    State(state): State<AppState>,
    actor: ManagementActor,
    body: Bytes,
) -> Result<Json<CandidateReceipt>> {
    let session = actor.0;
    let data: StageGrant = input(&body, 8192)?;
    state.account_access.admission.resume(session.id)?;
    enrollment::grant(&state, &session, &data).await.map(Json)
}
async fn enrollment_activate(
    State(state): State<AppState>,
    actor: ManagementActor,
    body: Bytes,
) -> Result<Json<SecurityReceipt>> {
    let session = actor.0;
    let data: ActivateCredential = input(&body, MAX_CEREMONY_BYTES)?;
    state.account_access.admission.resume(session.id)?;
    enrollment::activate(&state, &session, &data)
        .await
        .map(Json)
}
async fn revoke(
    State(state): State<AppState>,
    actor: ManagementActor,
    body: Bytes,
) -> Result<Json<SecurityReceipt>> {
    let session = actor.0;
    let data: RevokeCredential = input(&body, MAX_CEREMONY_BYTES)?;
    state.account_access.admission.resume(session.id)?;
    management::revoke(&state, &session, &data).await.map(Json)
}
async fn login_options(
    State(state): State<AppState>,
    remote: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CeremonyOptions>> {
    let data: PasskeyLoginOptions = input(&body, 8192)?;
    let ip = crate::infra::request_context::client_ip(&headers, remote.map(|r| r.0), Some(&state));
    state.account_access.admission.login(ip.as_deref())?;
    login::options(&state, &data).await.map(Json)
}
async fn login_finish(
    State(state): State<AppState>,
    remote: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PasskeyLogin>> {
    let data: CeremonyFinish = input(&body, MAX_CEREMONY_BYTES)?;
    let ip = crate::infra::request_context::client_ip(&headers, remote.map(|r| r.0), Some(&state));
    state.account_access.admission.login(ip.as_deref())?;
    login::finish(&state, &data).await.map(Json)
}
impl IntoResponse for AccessError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Rejected
            | Self::Webauthn(_)
            | Self::Crypto(_)
            | Self::RecoverySecret(_)
            | Self::Session(SessionWriteError::Invalidated) => {
                (StatusCode::UNAUTHORIZED, "account_access_rejected")
            }
            Self::Issuance(
                crate::domains::auth::service::issuance::SessionIssueError::Session(
                    SessionWriteError::Invalidated,
                ),
            ) => (StatusCode::UNAUTHORIZED, "account_access_rejected"),
            Self::Recovery(zann_db::repo::RecoveryStoreError::Ended) => {
                (StatusCode::GONE, "recovery_stopped")
            }
            Self::Forbidden => (StatusCode::FORBIDDEN, "account_security_forbidden"),
            Self::Disabled => (StatusCode::FORBIDDEN, "passkey_disabled"),
            Self::Conflict
            | Self::Store(AccountAccessStoreError::Conflict)
            | Self::Recovery(zann_db::repo::RecoveryStoreError::Conflict) => {
                (StatusCode::CONFLICT, "account_access_conflict")
            }
            Self::Capacity
            | Self::Store(AccountAccessStoreError::Capacity)
            | Self::Recovery(zann_db::repo::RecoveryStoreError::Capacity) => {
                (StatusCode::SERVICE_UNAVAILABLE, "account_access_capacity")
            }
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "account_access_rate_limit"),
            Self::BadRequest(code) => (StatusCode::BAD_REQUEST, *code),
            Self::InvalidJson(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Timeout => (StatusCode::SERVICE_UNAVAILABLE, "account_access_timeout"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "account_access_failed"),
        };
        if status.is_server_error() {
            tracing::error!(event="account_access_failed",error=?self);
        }
        // Request JSON errors retain their source for diagnostics without echoing
        // secret-bearing attacker input, error strings or credential responses.
        if let Self::InvalidJson(error) = &self {
            tracing::debug!(
                event = "account_access_invalid_json",
                line = error.line(),
                column = error.column()
            );
        }
        (
            status,
            Json(zann_core::api::auth::ApiErrorResponse::new(code)),
        )
            .into_response()
    }
}

async fn activate_code(
    State(state): State<AppState>,
    actor: ManagementActor,
    body: Bytes,
) -> Result<Json<SecurityReceipt>> {
    let input: ActivateRecoveryCode = input(&body, 8192)?;
    state.account_access.admission.resume(actor.0.id)?;
    management::activate_code(&state, &actor.0, &input)
        .await
        .map(Json)
}

async fn test_options(
    State(state): State<AppState>,
    actor: ManagementActor,
    body: Bytes,
) -> Result<Json<CeremonyOptions>> {
    let input: CandidateTestOptions = input(&body, 8192)?;
    state.account_access.admission.resume(actor.0.id)?;
    enrollment::test_options(&state, &actor.0, &input)
        .await
        .map(Json)
}
