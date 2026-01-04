use super::super::types::ServiceAccountLoginRequest;
use crate::app::AppState;
use crate::domains::auth::service::{self, AuthRequestContext};
use crate::infra::request_context::{client_ip, request_id, user_agent};
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};

pub(crate) async fn login_service_account(
    State(state): State<AppState>,
    remote_addr: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<ServiceAccountLoginRequest>,
) -> impl IntoResponse {
    let client_ip = client_ip(&headers, remote_addr.map(|value| value.0), Some(&state));
    let ctx = AuthRequestContext {
        client_ip,
        request_id: request_id(&headers),
        user_agent: user_agent(&headers),
    };
    match service::login_service_account(&state, &payload, &ctx).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(err) => super::map_auth_error(err),
    }
}
