use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use zann_core::api::auth::{OidcConfigResponse, OidcLoginRequest};

use super::super::types::ErrorResponse;
use crate::app::AppState;
use crate::domains::auth::service::{self, AuthRequestContext};
use crate::infra::request_context::user_agent;
use crate::infra::request_context::{client_ip, request_id};

pub(crate) async fn login_oidc(
    State(state): State<AppState>,
    remote_addr: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(payload): Json<OidcLoginRequest>,
) -> impl IntoResponse {
    let client_ip = client_ip(&headers, remote_addr.map(|value| value.0), Some(&state));
    let ctx = AuthRequestContext {
        client_ip,
        request_id: request_id(&headers),
        user_agent: user_agent(&headers),
    };
    match service::login_oidc(&state, &payload, &ctx).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(err) => super::map_auth_error(err),
    }
}

#[tracing::instrument(skip(state))]
pub(crate) async fn oidc_config(State(state): State<AppState>) -> axum::response::Response {
    let oidc = &state.config.auth.oidc;
    if !oidc.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "oidc_disabled",
            }),
        )
            .into_response();
    }

    let response = OidcConfigResponse {
        issuer: oidc.issuer.clone(),
        client_id: oidc.client_id.clone(),
        audience: oidc
            .audience
            .clone()
            .filter(|value| !value.trim().is_empty()),
        scopes: oidc
            .scopes
            .clone()
            .unwrap_or_else(|| {
                vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                    "offline_access".to_string(),
                ]
            })
            .into_iter()
            .filter(|scope| !scope.trim().is_empty())
            .collect(),
    };

    (StatusCode::OK, Json(response)).into_response()
}
