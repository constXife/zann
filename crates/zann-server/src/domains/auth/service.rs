use base64::Engine;
use chrono::Utc;
use sqlx_core::query::query;
use sqlx_postgres::Postgres;
use std::collections::HashSet;
use uuid::Uuid;
use zann_core::api::auth::{
    LoginRequest, LoginResponse, LogoutRequest, OidcLoginRequest, PreloginResponse, RefreshRequest,
    RegisterRequest,
};
use zann_core::{Session, User, UserStatus, VaultEncryptionType, VaultKind};
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{
    DeviceRepo, ServiceAccountRepo, ServiceAccountSessionRepo, SessionRepo, UserRepo, VaultRepo,
};

use crate::app::AppState;
use crate::config::{AuthMode, InternalRegistration};
use crate::domains::access_control::http::scopes_allow_vault;
use crate::domains::auth::core::identity::identity_from_oidc;
use crate::domains::auth::core::oidc::validate_oidc_jwt;
use crate::domains::auth::core::passwords::{
    derive_auth_hash, hash_password, hash_service_token, kdf_fingerprint, kdf_params_from_user,
    random_kdf_salt, verify_password, KdfParams,
};
use crate::domains::auth::core::tokens::hash_token;
use crate::domains::auth::helpers::{
    build_device, build_login_response, create_session_for_user, ensure_personal_vault,
    ensure_personal_vault_tx, ttl_seconds_u64,
};
use crate::domains::errors::ServiceError;
use crate::infra::db::apply_tx_isolation;
use crate::infra::metrics;

use super::http::v1::types::{
    ServiceAccountLoginRequest, ServiceAccountLoginResponse, ServiceAccountVaultKey,
};

const SERVICE_ACCOUNT_PREFIX: &str = "zann_sa_";
const SERVICE_ACCOUNT_PREFIX_LEN: usize = 12;

pub struct AuthRequestContext {
    pub client_ip: Option<String>,
    pub request_id: Option<String>,
    pub user_agent: Option<String>,
}

pub type AuthError = ServiceError;

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
    let tokens = create_session_for_user(state, user.id, device.id, now);
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

    if let Err(err) = query::<Postgres>(
        r#"
        INSERT INTO devices (
            id, user_id, name, fingerprint, os, os_version, app_version,
            last_seen_at, last_ip, revoked_at, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(device.id)
    .bind(device.user_id)
    .bind(device.name.as_str())
    .bind(device.fingerprint.as_str())
    .bind(device.os.as_deref())
    .bind(device.os_version.as_deref())
    .bind(device.app_version.as_deref())
    .bind(device.last_seen_at)
    .bind(device.last_ip.as_deref())
    .bind(device.revoked_at)
    .bind(device.created_at)
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

    if let Err(err) = query::<Postgres>(
        r#"
        INSERT INTO sessions (
            id, user_id, device_id, access_token_hash, access_expires_at,
            refresh_token_hash, expires_at, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(session.id)
    .bind(session.user_id)
    .bind(session.device_id)
    .bind(session.access_token_hash.as_str())
    .bind(session.access_expires_at)
    .bind(session.refresh_token_hash.as_str())
    .bind(session.expires_at)
    .bind(session.created_at)
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

    let device_repo = DeviceRepo::new(&state.db);
    if let Err(err) = device_repo.create(&device).await {
        metrics::auth_login("db_error", "internal");
        tracing::error!(
            event = "auth_login_failed",
            reason = "db_error",
            error = %err,
            user_id = "redacted",
            email = "redacted",
            method = "internal",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login failed"
        );
        return Err(AuthError::DbError);
    }

    let tokens = create_session_for_user(state, user.id, device.id, now);
    let session = tokens.session;

    let session_repo = SessionRepo::new(&state.db);
    if let Err(err) = session_repo.create(&session).await {
        metrics::auth_login("db_error", "internal");
        tracing::error!(
            event = "auth_login_failed",
            reason = "db_error",
            error = %err,
            user_id = "redacted",
            email = "redacted",
            method = "internal",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            "Login failed"
        );
        return Err(AuthError::DbError);
    }

    if let Err(err) = ensure_personal_vault(state, user.id, now).await {
        tracing::error!(
            event = "personal_vault_create_failed",
            error = %err,
            user_id = "redacted",
            "Failed to ensure personal vault"
        );
        return Err(AuthError::Internal("personal_vault_create_failed"));
    }

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

    let oidc_token = zann_core::OidcToken {
        issuer: claims.iss.clone(),
        subject: claims.sub.clone(),
        email: {
            let email = claims.email.clone();
            if email.is_some() {
                email
            } else {
                state
                    .oidc_jwks_cache
                    .fetch_userinfo_email(&payload.token, &state.config.auth.oidc)
                    .await
                    .ok()
                    .flatten()
            }
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

    let device_repo = DeviceRepo::new(&state.db);
    if let Err(err) = device_repo.create(&device).await {
        metrics::auth_login("db_error", "oidc");
        tracing::error!(
            event = "auth_login_failed",
            reason = "db_error",
            error = %err,
            user_id = "redacted",
            method = "oidc",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login failed"
        );
        return Err(AuthError::DbError);
    }

    let tokens = create_session_for_user(state, identity.user_id, device.id, now);
    let session = tokens.session;

    let session_repo = SessionRepo::new(&state.db);
    if let Err(err) = session_repo.create(&session).await {
        metrics::auth_login("db_error", "oidc");
        tracing::error!(
            event = "auth_login_failed",
            reason = "db_error",
            error = %err,
            user_id = "redacted",
            method = "oidc",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login failed"
        );
        return Err(AuthError::DbError);
    }

    if let Err(err) = ensure_personal_vault(state, identity.user_id, now).await {
        tracing::error!(
            event = "personal_vault_create_failed",
            error = %err,
            user_id = "redacted",
            "Failed to ensure personal vault"
        );
        return Err(AuthError::Internal("personal_vault_create_failed"));
    }

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
        Err(_) => {
            tracing::error!(
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
            session.id,
            &new_access_hash,
            new_access_expires_at,
            &new_refresh_hash,
            new_expires_at,
        )
        .await
    {
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

pub(crate) async fn login_service_account(
    state: &AppState,
    payload: &ServiceAccountLoginRequest,
    ctx: &AuthRequestContext,
) -> Result<ServiceAccountLoginResponse, AuthError> {
    if !payload.token.starts_with(SERVICE_ACCOUNT_PREFIX) {
        metrics::auth_login("invalid", "service_account");
        tracing::warn!(
            event = "auth_login_failed",
            reason = "invalid_token_format",
            method = "service_account",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login failed"
        );
        return Err(AuthError::Unauthorized("invalid_token"));
    }

    let token_prefix = service_account_prefix(&payload.token);
    let repo = ServiceAccountRepo::new(&state.db);
    let accounts = if let Ok(accounts) = repo.list_by_prefix(&token_prefix).await {
        accounts
    } else {
        metrics::auth_login("db_error", "service_account");
        tracing::error!(
            event = "auth_login_failed",
            reason = "db_error",
            method = "service_account",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login failed"
        );
        return Err(AuthError::DbError);
    };

    let params = KdfParams {
        algorithm: state.config.auth.kdf.algorithm.clone(),
        iterations: state.config.auth.kdf.iterations,
        memory_kb: state.config.auth.kdf.memory_kb,
        parallelism: state.config.auth.kdf.parallelism,
    };
    let _permit =
        match metrics::acquire_kdf_permit(&state.argon2_semaphore, "service_account_login").await {
            Ok(permit) => permit,
            Err(_) => {
                metrics::auth_login("kdf_error", "service_account");
                tracing::error!(
                    event = "auth_login_failed",
                    reason = "kdf_error",
                    method = "service_account",
                    ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                    request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                    "Login failed"
                );
                return Err(AuthError::Kdf);
            }
        };
    let token_hash =
        if let Ok(value) = hash_service_token(&payload.token, &state.token_pepper, &params) {
            value
        } else {
            metrics::auth_login("kdf_error", "service_account");
            tracing::error!(
                event = "auth_login_failed",
                reason = "kdf_error",
                method = "service_account",
                ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
                request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
                "Login failed"
            );
            return Err(AuthError::Kdf);
        };

    let account = if let Some(account) = accounts.into_iter().find(|sa| sa.token_hash == token_hash)
    {
        account
    } else {
        metrics::auth_login("invalid", "service_account");
        tracing::warn!(
            event = "auth_login_failed",
            reason = "invalid_token",
            method = "service_account",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login failed"
        );
        return Err(AuthError::Unauthorized("invalid_token"));
    };

    if account.revoked_at.is_some() {
        metrics::auth_login("revoked", "service_account");
        return Err(AuthError::Unauthorized("token_revoked"));
    }
    if account
        .expires_at
        .is_some_and(|expires_at| expires_at < Utc::now())
    {
        metrics::auth_login("expired", "service_account");
        return Err(AuthError::Unauthorized("token_expired"));
    }

    if let Some(allowed_ips) = account.allowed_ips.as_ref() {
        let Some(client_ip) = ctx.client_ip.as_deref() else {
            metrics::auth_login("ip_denied", "service_account");
            return Err(AuthError::Forbidden("ip_not_allowed"));
        };
        if !allowed_ips.0.iter().any(|ip| ip == client_ip) {
            metrics::auth_login("ip_denied", "service_account");
            return Err(AuthError::Forbidden("ip_not_allowed"));
        }
    }

    let now = Utc::now();
    let access_token = Uuid::now_v7().to_string();
    let access_token_hash = hash_token(&access_token, &state.token_pepper);
    let access_expires_at = now + chrono::Duration::seconds(state.access_token_ttl_seconds);

    let session = zann_core::ServiceAccountSession {
        id: Uuid::now_v7(),
        service_account_id: account.id,
        access_token_hash,
        expires_at: access_expires_at,
        created_at: now,
    };
    let sa_session_repo = ServiceAccountSessionRepo::new(&state.db);
    if let Err(err) = sa_session_repo.create(&session).await {
        metrics::auth_login("db_error", "service_account");
        tracing::error!(
            event = "auth_login_failed",
            reason = "db_error",
            error = %err,
            method = "service_account",
            ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
            request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
            "Login failed"
        );
        return Err(AuthError::DbError);
    }

    if let Err(err) = repo
        .update_usage(
            account.id,
            now,
            ctx.client_ip.as_deref(),
            ctx.user_agent.as_deref(),
            1,
        )
        .await
    {
        tracing::warn!(
            event = "service_account_usage_update_failed",
            error = %err,
            service_account_id = %account.id,
            "Failed to update service account usage"
        );
    }

    metrics::auth_login("ok", "service_account");
    metrics::auth_tokens_issued("access");
    tracing::info!(
        event = "service_account_used",
        service_account_id = %account.id,
        owner_user_id = "redacted",
        ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
        "Service account used"
    );
    tracing::info!(
        event = "auth_login_ok",
        service_account_id = %account.id,
        method = "service_account",
        ip = %ctx.client_ip.as_deref().unwrap_or("unknown"),
        request_id = %ctx.request_id.as_deref().unwrap_or("unknown"),
        "Login succeeded"
    );

    let vault_keys = service_account_vault_keys(state, &account)
        .await
        .map_err(|err| {
            tracing::error!(
                event = "service_account_vault_keys_failed",
                reason = %err,
                service_account_id = %account.id,
                "Failed to load vault keys"
            );
            AuthError::Internal("vault_keys_failed")
        })?;

    Ok(ServiceAccountLoginResponse {
        service_account_id: account.id.to_string(),
        owner_user_id: account.owner_user_id.to_string(),
        access_token,
        expires_in: ttl_seconds_u64(state.access_token_ttl_seconds),
        vault_keys,
    })
}

async fn service_account_vault_keys(
    state: &AppState,
    account: &zann_core::ServiceAccount,
) -> Result<Vec<ServiceAccountVaultKey>, &'static str> {
    let Some(smk) = state.server_master_key.as_ref() else {
        return Err("smk_missing");
    };
    let vault_repo = VaultRepo::new(&state.db);
    let mut keys = Vec::new();
    let mut seen = HashSet::new();

    let vaults = vault_repo.list_all().await.map_err(|_| "db_error")?;
    for vault in vaults {
        if vault.kind != VaultKind::Shared {
            continue;
        }
        if vault.encryption_type != VaultEncryptionType::Server {
            continue;
        }
        if !scopes_allow_vault(&account.scopes.0, &vault) {
            continue;
        }
        if !seen.insert(vault.id) {
            continue;
        }

        let key = core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)
            .map_err(|err| err.as_code())?;
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key.as_bytes());
        keys.push(ServiceAccountVaultKey {
            vault_id: vault.id.to_string(),
            vault_key: key_b64,
        });
    }

    Ok(keys)
}

fn service_account_prefix(token: &str) -> String {
    token.chars().take(SERVICE_ACCOUNT_PREFIX_LEN).collect()
}
