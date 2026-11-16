use super::*;

pub async fn register(
    state: &AppState,
    payload: &RegisterRequest,
    ctx: &AuthRequestContext,
) -> Result<LoginResponse, AuthError> {
    if !state.config.auth.internal.enabled || matches!(state.config.auth.mode, AuthMode::Oidc) {
        metrics::auth_register("rejected");
        tracing::warn!(
            event = "auth_register_rejected",
            reason = "internal_disabled",
            email = "redacted",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Registration rejected"
        );
        return Err(AuthError::Forbidden("internal_disabled"));
    }

    match state.config.auth.internal.registration {
        InternalRegistration::Disabled => {
            metrics::auth_register("rejected");
            tracing::warn!(
                event = "auth_register_rejected",
                reason = "registration_disabled",
                email = "redacted",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Registration rejected"
            );
            return Err(AuthError::Forbidden("registration_disabled"));
        }
        InternalRegistration::Open => {}
    }

    let now = Utc::now();
    let params = KdfParams {
        algorithm: state.config.auth.kdf.algorithm.clone(),
        iterations: state.config.auth.kdf.iterations,
        memory_kb: state.config.auth.kdf.memory_kb,
        parallelism: state.config.auth.kdf.parallelism,
    };
    let kdf_salt = random_kdf_salt();
    let _permit = match metrics::acquire_kdf_permit(&state.argon2_semaphore, "auth_register").await
    {
        Ok(permit) => permit,
        Err(_) => {
            metrics::auth_register("kdf_error");
            tracing::error!(
                event = "auth_register_failed",
                reason = "kdf_error",
                email = "redacted",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Registration failed"
            );
            return Err(AuthError::Kdf);
        }
    };
    let auth_hash = if let Ok(value) = derive_auth_hash(&payload.password, &kdf_salt, &params) {
        value
    } else {
        metrics::auth_register("kdf_error");
        tracing::error!(
            event = "auth_register_failed",
            reason = "kdf_error",
            email = "redacted",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Registration failed"
        );
        return Err(AuthError::Kdf);
    };
    let password_hash =
        if let Ok(value) = hash_password(&auth_hash, &state.password_pepper, &params) {
            value
        } else {
            metrics::auth_register("kdf_error");
            tracing::error!(
                event = "auth_register_failed",
                reason = "kdf_error",
                email = "redacted",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Registration failed"
            );
            return Err(AuthError::Kdf);
        };

    let user = User {
        id: Uuid::now_v7(),
        email: payload.email.clone(),
        full_name: payload
            .full_name
            .as_ref()
            .map(|value| value.trim().to_string()),
        password_hash: Some(password_hash),
        recovery_key_hash: None,
        auth_epoch: 1,
        active_recovery_id: None,
        kdf_algorithm: params.algorithm,
        kdf_iterations: params.iterations as i64,
        kdf_memory_kb: params.memory_kb as i64,
        kdf_parallelism: params.parallelism as i64,
        kdf_salt,
        status: UserStatus::Active,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: now,
        updated_at: now,
        last_login_at: None,
    };

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
    let tokens = create_session_for_user(state, user.id, device.id, user.auth_epoch, now);
    let session = tokens.session;

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            metrics::auth_register("db_error");
            tracing::error!(
                event = "auth_register_failed",
                reason = "db_error",
                error = %err,
                email = "redacted",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Registration failed"
            );
            return Err(AuthError::DbError);
        }
    };
    if let Err(err) = apply_tx_isolation(&mut tx, state.db_tx_isolation).await {
        metrics::auth_register("db_error");
        tracing::error!(
            event = "auth_register_failed",
            reason = "db_error",
            error = %err,
            email = "redacted",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Registration failed"
        );
        return Err(AuthError::DbError);
    }

    let existing = query::<Postgres>(
        r#"
        SELECT 1
        FROM users
        WHERE email = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(&payload.email)
    .fetch_optional(&mut *tx)
    .await;
    match existing {
        Ok(Some(_)) => {
            if let Err(err) = tx.rollback().await {
                tracing::error!(
                    event = "auth_register_failed",
                    error = %err,
                    "DB rollback failed"
                );
                metrics::auth_register("db_error");
                return Err(AuthError::DbError);
            }
            metrics::auth_register("rejected");
            tracing::warn!(
                event = "auth_register_rejected",
                reason = "email_taken",
                email = "redacted",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Registration rejected"
            );
            return Err(AuthError::Conflict("email_taken"));
        }
        Ok(None) => {}
        Err(err) => {
            if let Err(err) = tx.rollback().await {
                tracing::error!(
                    event = "auth_register_failed",
                    error = %err,
                    "DB rollback failed"
                );
                metrics::auth_register("db_error");
                return Err(AuthError::DbError);
            }
            metrics::auth_register("db_error");
            tracing::error!(
                event = "auth_register_failed",
                reason = "db_error",
                error = %err,
                email = "redacted",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Registration failed"
            );
            return Err(AuthError::DbError);
        }
    }

    if let Err(err) = query::<Postgres>(
        r#"
        INSERT INTO users (
            id,
            email,
            full_name,
            password_hash,
            kdf_salt,
            kdf_algorithm,
            kdf_iterations,
            kdf_memory_kb,
            kdf_parallelism,
            recovery_key_hash,
            status,
            deleted_at,
            deleted_by_user_id,
            deleted_by_device_id,
            row_version,
            created_at,
            updated_at,
            last_login_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
        )
        "#,
    )
    .bind(user.id)
    .bind(user.email.as_str())
    .bind(user.full_name.as_deref())
    .bind(user.password_hash.as_deref())
    .bind(user.kdf_salt.as_str())
    .bind(user.kdf_algorithm.as_str())
    .bind(user.kdf_iterations)
    .bind(user.kdf_memory_kb)
    .bind(user.kdf_parallelism)
    .bind(user.recovery_key_hash.as_deref())
    .bind(user.status.as_i32())
    .bind(user.deleted_at)
    .bind(user.deleted_by_user_id)
    .bind(user.deleted_by_device_id)
    .bind(user.row_version)
    .bind(user.created_at)
    .bind(user.updated_at)
    .bind(user.last_login_at)
    .execute(&mut *tx)
    .await
    {
        if let Err(rollback_err) = tx.rollback().await {
            tracing::error!(
                event = "auth_register_failed",
                error = %rollback_err,
                "DB rollback failed"
            );
            metrics::auth_register("db_error");
            return Err(AuthError::DbError);
        }
        metrics::auth_register("db_error");
        tracing::error!(
            event = "auth_register_failed",
            reason = "db_error",
            error = %err,
            email = "redacted",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Registration failed"
        );
        return Err(AuthError::DbError);
    }

    if let Err(err) = DeviceRepo::create_in(&mut tx, &device).await {
        if let Err(rollback_err) = tx.rollback().await {
            tracing::error!(
                event = "auth_register_failed",
                error = %rollback_err,
                "DB rollback failed"
            );
            metrics::auth_register("db_error");
            return Err(AuthError::DbError);
        }
        metrics::auth_register("db_error");
        tracing::error!(
            event = "auth_register_failed",
            reason = "db_error",
            error = %err,
            email = "redacted",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Registration failed"
        );
        return Err(AuthError::DbError);
    }

    if let Err(err) = SessionRepo::create_in(&mut tx, &session).await {
        if let Err(rollback_err) = tx.rollback().await {
            tracing::error!(
                event = "auth_register_failed",
                error = %rollback_err,
                "DB rollback failed"
            );
            metrics::auth_register("db_error");
            return Err(AuthError::DbError);
        }
        metrics::auth_register("db_error");
        tracing::error!(
            event = "auth_register_failed",
            reason = "db_error",
            error = %err,
            email = "redacted",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Registration failed"
        );
        return Err(AuthError::DbError);
    }

    if let Err(err) = ensure_personal_vault_tx(state, &mut tx, user.id, now).await {
        if let Err(rollback_err) = tx.rollback().await {
            tracing::error!(
                event = "auth_register_failed",
                error = %rollback_err,
                "DB rollback failed"
            );
            metrics::auth_register("db_error");
            return Err(AuthError::DbError);
        }
        tracing::error!(
            event = "personal_vault_create_failed",
            error = %err,
            user_id = "redacted",
            "Failed to ensure personal vault"
        );
        return Err(AuthError::Internal("personal_vault_create_failed"));
    }

    if let Err(err) = tx.commit().await {
        metrics::auth_register("db_error");
        tracing::error!(
            event = "auth_register_failed",
            reason = "db_error",
            error = %err,
            email = "redacted",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Registration failed"
        );
        return Err(AuthError::DbError);
    }

    metrics::auth_register("ok");
    metrics::auth_tokens_issued("access");
    metrics::auth_tokens_issued("refresh");
    tracing::info!(
        event = "auth_register_ok",
        user_id = "redacted",
        email = "redacted",
        ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
        request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
        "Registration succeeded"
    );

    Ok(build_login_response(
        state,
        tokens.access_token,
        tokens.refresh_token,
    ))
}
