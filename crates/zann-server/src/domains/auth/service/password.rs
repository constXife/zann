use super::*;

pub async fn prelogin(
    state: &AppState,
    email: &str,
    ctx: &AuthRequestContext,
) -> Result<PreloginResponse, AuthError> {
    let repo = UserRepo::new(&state.db);
    let user = match repo.get_by_email(email).await {
        Ok(Some(user)) => Some(user),
        Ok(None) => None,
        Err(_) => {
            tracing::error!(
                event = "auth_prelogin_failed",
                reason = "db_error",
                email = "redacted",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Prelogin failed"
            );
            return Err(AuthError::DbError);
        }
    };

    let params = if let Some(user) = &user {
        kdf_params_from_user(user)
    } else {
        KdfParams {
            algorithm: state.config.auth.kdf.algorithm.clone(),
            iterations: state.config.auth.kdf.iterations,
            memory_kb: state.config.auth.kdf.memory_kb,
            parallelism: state.config.auth.kdf.parallelism,
        }
    };
    let kdf_salt = user
        .as_ref()
        .map_or_else(random_kdf_salt, |user| user.kdf_salt.clone());
    let fingerprint = if let Ok(value) = kdf_fingerprint(&kdf_salt, &params) {
        value
    } else {
        tracing::error!(
            event = "auth_prelogin_failed",
            reason = "fingerprint_failed",
            email = "redacted",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Prelogin failed"
        );
        return Err(AuthError::Internal("kdf_failed"));
    };

    Ok(PreloginResponse {
        kdf_salt,
        kdf_params: zann_core::api::auth::KdfParams {
            algorithm: params.algorithm,
            iterations: params.iterations,
            memory_kb: params.memory_kb,
            parallelism: params.parallelism,
        },
        salt_fingerprint: fingerprint,
    })
}

pub async fn login_internal(
    state: &AppState,
    payload: &LoginRequest,
    ctx: &AuthRequestContext,
) -> Result<LoginResponse, AuthError> {
    if !state.config.auth.internal.enabled || matches!(state.config.auth.mode, AuthMode::Oidc) {
        metrics::auth_login("disabled", "internal");
        tracing::warn!(
            event = "auth_login_rejected",
            reason = "internal_disabled",
            email = "redacted",
            method = "internal",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login rejected"
        );
        return Err(AuthError::Forbidden("internal_disabled"));
    }

    let repo = UserRepo::new(&state.db);
    let user = match repo.get_by_email(&payload.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            metrics::auth_login("invalid", "internal");
            tracing::warn!(
                event = "auth_login_failed",
                reason = "user_not_found",
                email = "redacted",
                method = "internal",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Login failed"
            );
            return Err(AuthError::Unauthorized("invalid_credentials"));
        }
        Err(_) => {
            metrics::auth_login("db_error", "internal");
            tracing::error!(
                event = "auth_login_failed",
                reason = "db_error",
                email = "redacted",
                method = "internal",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Login failed"
            );
            return Err(AuthError::DbError);
        }
    };

    if user.status != UserStatus::Active {
        metrics::auth_login("disabled", "internal");
        tracing::warn!(
            event = "auth_login_rejected",
            reason = "user_disabled",
            user_id = "redacted",
            email = "redacted",
            method = "internal",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login rejected"
        );
        return Err(AuthError::Forbidden("user_disabled"));
    }

    let _permit = match metrics::acquire_kdf_permit(&state.argon2_semaphore, "auth_login").await {
        Ok(permit) => permit,
        Err(_) => {
            metrics::auth_login("db_error", "internal");
            tracing::error!(
                event = "auth_login_failed",
                reason = "kdf_error",
                user_id = "redacted",
                email = "redacted",
                method = "internal",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Login failed"
            );
            return Err(AuthError::Kdf);
        }
    };
    let Ok(valid) = verify_password(&user, &payload.password, &state.password_pepper) else {
        metrics::auth_login("db_error", "internal");
        tracing::error!(
            event = "auth_login_failed",
            reason = "kdf_error",
            user_id = "redacted",
            email = "redacted",
            method = "internal",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login failed"
        );
        return Err(AuthError::Kdf);
    };

    if !valid {
        metrics::auth_login("invalid", "internal");
        tracing::warn!(
            event = "auth_login_failed",
            reason = "invalid_password",
            user_id = "redacted",
            email = "redacted",
            method = "internal",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login failed"
        );
        return Err(AuthError::Unauthorized("invalid_credentials"));
    }

    let now = Utc::now();
    let device = build_device(
        user.id,
        payload.device_name.clone(),
        payload.device_platform.clone(),
        payload.device_fingerprint.clone(),
        payload.device_os.clone(),
        payload.device_os_version.clone(),
        payload.device_app_version.clone(),
        "default",
        "unknown",
        now,
    );

    let tokens = issuance::issue_login_session(state, &user, &device, now, ctx, "internal").await?;

    if let Err(err) = repo.update_last_login(user.id, user.row_version, now).await {
        tracing::warn!(
            event = "auth_login_update_last_login_failed",
            error = %err,
            user_id = "redacted",
            method = "internal",
            "Failed to update last login timestamp"
        );
    }
    metrics::auth_login("ok", "internal");
    metrics::auth_tokens_issued("access");
    metrics::auth_tokens_issued("refresh");
    tracing::info!(
        event = "auth_login_ok",
        user_id = "redacted",
        email = "redacted",
        method = "internal",
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
