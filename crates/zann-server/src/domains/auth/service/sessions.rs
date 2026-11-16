use super::*;

pub async fn refresh(
    state: &AppState,
    payload: &RefreshRequest,
    ctx: &AuthRequestContext,
) -> Result<LoginResponse, AuthError> {
    let session_repo = SessionRepo::new(&state.db);
    let refresh_hash = hash_token(&payload.refresh_token, &state.token_pepper);
    let session = match session_repo.get_by_refresh_token_hash(&refresh_hash).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            tracing::warn!(
                event = "auth_refresh_failed",
                reason = "invalid_token",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Refresh failed"
            );
            return Err(AuthError::Unauthorized("invalid_token"));
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                event = "auth_refresh_failed",
                reason = "db_error",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Refresh failed"
            );
            return Err(AuthError::DbError);
        }
    };

    if session.expires_at < Utc::now() {
        tracing::info!(
            event = "auth_refresh_expired",
            user_id = "redacted",
            device_id = %session.device_id,
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Refresh token expired"
        );
        return Err(AuthError::Unauthorized("token_expired"));
    }

    let new_refresh_token = Uuid::now_v7().to_string();
    let new_access_token = Uuid::now_v7().to_string();
    let new_refresh_hash = hash_token(&new_refresh_token, &state.token_pepper);
    let new_access_hash = hash_token(&new_access_token, &state.token_pepper);
    let new_access_expires_at =
        Utc::now() + chrono::Duration::seconds(state.access_token_ttl_seconds);
    let new_expires_at = Utc::now() + chrono::Duration::seconds(state.refresh_token_ttl_seconds);

    if let Err(err) = session_repo
        .update_refresh_token(
            &session,
            &new_access_hash,
            new_access_expires_at,
            &new_refresh_hash,
            new_expires_at,
        )
        .await
    {
        if matches!(err, zann_db::repo::SessionWriteError::Invalidated) {
            return Err(AuthError::Unauthorized("invalid_token"));
        }
        tracing::error!(
            event = "auth_refresh_failed",
            reason = "db_error",
            error = %err,
            user_id = "redacted",
            device_id = %session.device_id,
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Refresh failed"
        );
        return Err(AuthError::DbError);
    }

    metrics::auth_tokens_issued("access");
    metrics::auth_tokens_issued("refresh");
    tracing::info!(
        event = "auth_refresh_ok",
        user_id = "redacted",
        device_id = %session.device_id,
        ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
        "Refresh succeeded"
    );
    Ok(build_login_response(
        state,
        new_access_token,
        new_refresh_token,
    ))
}

pub async fn logout(
    state: &AppState,
    payload: &LogoutRequest,
    ctx: &AuthRequestContext,
) -> Result<Option<Session>, AuthError> {
    let session_repo = SessionRepo::new(&state.db);
    let token_hash = hash_token(&payload.refresh_token, &state.token_pepper);

    let session = session_repo
        .get_by_refresh_token_hash(&token_hash)
        .await
        .ok()
        .flatten();

    if let Err(err) = session_repo.delete_by_refresh_token_hash(&token_hash).await {
        tracing::error!(
            event = "auth_logout_failed",
            reason = "db_error",
            error = %err,
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Logout failed"
        );
        return Err(AuthError::DbError);
    }

    if let Some(session) = &session {
        tracing::info!(
            event = "auth_logout_ok",
            user_id = "redacted",
            device_id = %session.device_id,
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Logout succeeded"
        );
    } else {
        tracing::info!(
            event = "auth_logout_ok",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Logout succeeded"
        );
    }
    Ok(session)
}
