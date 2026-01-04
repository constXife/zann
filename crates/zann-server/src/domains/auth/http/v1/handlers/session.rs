use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use zann_core::api::auth::{LoginRequest, LogoutRequest, RefreshRequest};

use crate::app::AppState;
use crate::domains::auth::service::{self, AuthRequestContext};
use crate::infra::request_context::user_agent;
use crate::infra::request_context::{client_ip, request_id};

pub(crate) async fn login(
    State(state): State<AppState>,
    remote_addr: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let client_ip = client_ip(&headers, remote_addr.map(|value| value.0), Some(&state));
    let request_id = request_id(&headers);
    let ctx = AuthRequestContext {
        client_ip,
        request_id,
        user_agent: user_agent(&headers),
    };
    match service::login_internal(&state, &payload, &ctx).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(err) => super::map_auth_error(err),
    }
}

#[allow(clippy::cognitive_complexity)]
pub(crate) async fn refresh(
    State(state): State<AppState>,
    remote_addr: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<RefreshRequest>,
) -> impl IntoResponse {
    let client_ip = client_ip(&headers, remote_addr.map(|value| value.0), Some(&state));
    let ctx = AuthRequestContext {
        client_ip,
        request_id: request_id(&headers),
        user_agent: user_agent(&headers),
    };
    match service::refresh(&state, &payload, &ctx).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(err) => super::map_auth_error(err),
    }
}

#[allow(clippy::cognitive_complexity)]
pub(crate) async fn logout(
    State(state): State<AppState>,
    remote_addr: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<LogoutRequest>,
) -> impl IntoResponse {
    let client_ip = client_ip(&headers, remote_addr.map(|value| value.0), Some(&state));
    let ctx = AuthRequestContext {
        client_ip,
        request_id: request_id(&headers),
        user_agent: user_agent(&headers),
    };
    match service::logout(&state, &payload, &ctx).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => super::map_auth_error(err),
    }
}
