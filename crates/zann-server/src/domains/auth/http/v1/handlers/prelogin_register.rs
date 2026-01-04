use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use zann_core::api::auth::RegisterRequest;

use crate::app::AppState;
use crate::domains::auth::service::{self, AuthRequestContext};
use crate::infra::request_context::{client_ip, request_id};

use super::super::types::PreloginQuery;

pub(crate) async fn prelogin(
    State(state): State<AppState>,
    remote_addr: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Query(query): Query<PreloginQuery>,
) -> impl IntoResponse {
    let client_ip = client_ip(&headers, remote_addr.map(|value| value.0), Some(&state));
    let ctx = AuthRequestContext {
        client_ip,
        request_id: request_id(&headers),
        user_agent: None,
    };
    match service::prelogin(&state, &query.email, &ctx).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => super::map_auth_error(err),
    }
}

#[allow(clippy::cognitive_complexity)]
pub(crate) async fn register(
    State(state): State<AppState>,
    remote_addr: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let client_ip = client_ip(&headers, remote_addr.map(|value| value.0), Some(&state));
    let ctx = AuthRequestContext {
        client_ip,
        request_id: request_id(&headers),
        user_agent: None,
    };
    match service::register(&state, &payload, &ctx).await {
        Ok(body) => (StatusCode::CREATED, Json(body)).into_response(),
        Err(err) => super::map_auth_error(err),
    }
}
