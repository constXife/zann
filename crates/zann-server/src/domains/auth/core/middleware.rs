use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use crate::app::AppState;
use crate::config::AuthMode;
use crate::domains::auth::core::identity::{
    identity_from_oidc, identity_from_service_account_token, identity_from_session_token,
};
use crate::infra::request_context::{client_ip, user_agent};

const SERVICE_ACCOUNT_PREFIX: &str = "zann_sa_";
use crate::domains::auth::core::oidc::validate_oidc_jwt;

pub async fn auth_middleware(
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let state = request
        .extensions()
        .get::<AppState>()
        .cloned()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok());

    let token = match auth_header {
        Some(value) if value.starts_with("Bearer ") => &value[7..],
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    let identity = if token.contains('.') {
        if !state.config.auth.oidc.enabled || matches!(state.config.auth.mode, AuthMode::Internal) {
            return Err(StatusCode::UNAUTHORIZED);
        }

        let claims =
            match validate_oidc_jwt(token, &state.config.auth.oidc, &state.oidc_jwks_cache).await {
                Ok(claims) => claims,
                Err(err) => {
                    tracing::warn!(event = "auth_failed", reason = %err, "OIDC token rejected");
                    return Err(StatusCode::UNAUTHORIZED);
                }
            };
        let email = if claims.email.is_some() {
            claims.email.clone()
        } else {
            state
                .oidc_jwks_cache
                .fetch_userinfo_email(token, &state.config.auth.oidc)
                .await
                .ok()
                .flatten()
        };
        let oidc_token = zann_core::OidcToken {
            issuer: claims.iss.clone(),
            subject: claims.sub.clone(),
            email,
            claims: claims.other.clone(),
        };
        match identity_from_oidc(&state, oidc_token).await {
            Ok(identity) => identity,
            Err(err) => {
                tracing::warn!(event = "auth_failed", reason = %err, "OIDC identity rejected");
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    } else if token.starts_with(SERVICE_ACCOUNT_PREFIX) {
        let remote_addr = request
            .extensions()
            .get::<ConnectInfo<std::net::SocketAddr>>()
            .map(|value| value.0);
        let ip = client_ip(request.headers(), remote_addr, Some(&state));
        let agent = user_agent(request.headers());
        match identity_from_service_account_token(&state, token, ip.as_deref(), agent.as_deref())
            .await
        {
            Ok(identity) => identity,
            Err("ip_not_allowed") => return Err(StatusCode::FORBIDDEN),
            Err("db_error") => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            Err(_) => return Err(StatusCode::UNAUTHORIZED),
        }
    } else {
        match identity_from_session_token(&state, token).await {
            Ok(identity) => identity,
            Err(err) => {
                tracing::warn!(event = "auth_failed", reason = %err, "Session token rejected");
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    };

    tracing::Span::current().record("user_id", identity.user_id.to_string());
    request.extensions_mut().insert(identity);
    Ok(next.run(request).await)
}
