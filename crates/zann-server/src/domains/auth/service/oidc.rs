use super::*;

pub async fn login_oidc(
    state: &AppState,
    payload: &OidcLoginRequest,
    ctx: &AuthRequestContext,
) -> Result<LoginResponse, AuthError> {
    if !state.config.auth.oidc.enabled || matches!(state.config.auth.mode, AuthMode::Internal) {
        metrics::auth_login("disabled", "oidc");
        tracing::warn!(
            event = "auth_login_rejected",
            reason = "oidc_disabled",
            method = "oidc",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login rejected"
        );
        return Err(AuthError::Forbidden("oidc_disabled"));
    }

    let claims = match validate_oidc_jwt(
        &payload.token,
        &state.config.auth.oidc,
        &state.oidc_jwks_cache,
    )
    .await
    {
        Ok(claims) => claims,
        Err(err) => {
            metrics::auth_login("invalid", "oidc");
            tracing::warn!(
                event = "auth_login_failed",
                reason = "invalid_token",
                detail = %err,
                method = "oidc",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Login failed"
            );
            return Err(AuthError::Unauthorized("invalid_token"));
        }
    };

    let userinfo = if claims.email.is_some() {
        None
    } else {
        state
            .oidc_jwks_cache
            .fetch_userinfo(&payload.token, &state.config.auth.oidc)
            .await
            .ok()
    };
    let oidc_token = zann_core::OidcToken {
        issuer: claims.iss.clone(),
        subject: claims.sub.clone(),
        email: claims.email.clone().or_else(|| {
            userinfo
                .as_ref()
                .and_then(|userinfo| userinfo.email.clone())
        }),
        email_verified: if claims.email.is_some() {
            claims.email_verified
        } else {
            userinfo
                .as_ref()
                .and_then(|userinfo| userinfo.email_verified)
        },
        claims: claims.other.clone(),
    };

    let identity = match identity_from_oidc(state, oidc_token).await {
        Ok(identity) => identity,
        Err(err) => {
            metrics::auth_login("invalid", "oidc");
            tracing::warn!(
                event = "auth_login_failed",
                reason = "oidc_identity_error",
                method = "oidc",
                error = %err,
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Login failed"
            );
            return Err(AuthError::Unauthorized(err));
        }
    };

    let user = UserRepo::new(&state.db)
        .get_by_id(identity.user_id)
        .await
        .map_err(|err| {
            tracing::error!(event = "auth_oidc_account_failed", error = %err);
            AuthError::DbError
        })?
        .ok_or(AuthError::Unauthorized("invalid_credentials"))?;
    let now = Utc::now();
    let device = build_device(
        identity.user_id,
        None,
        None,
        None,
        None,
        None,
        None,
        "oidc",
        "oidc",
        now,
    );

    let tokens =
        issuance::issue_login_session(state, &user, &device, now, ctx, issuance::LoginFactor::Oidc)
            .await?;

    metrics::auth_login("ok", "oidc");
    metrics::auth_tokens_issued("access");
    metrics::auth_tokens_issued("refresh");
    tracing::info!(
        event = "auth_login_ok",
        user_id = "redacted",
        method = "oidc",
        ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
        request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
        "Login succeeded"
    );
    Ok(build_login_response(
        state,
        tokens.access_token,
        tokens.refresh_token,
    ))
}
