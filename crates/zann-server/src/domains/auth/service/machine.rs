use super::*;

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
        if !allowed_ips.iter().any(|ip| ip == client_ip) {
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
    let filter = crate::domains::vaults::service::service_account_catalog_filter(&account.scopes);
    let vaults = vault_repo
        .list_service_account_key_material(&filter, SERVICE_ACCOUNT_VAULT_KEY_LOOKAHEAD)
        .await
        .map_err(|_| "db_error")?;
    if vaults.len() > MAX_SERVICE_ACCOUNT_VAULT_KEYS {
        return Err("catalog_too_large");
    }
    let mut keys = Vec::with_capacity(vaults.len());
    for vault in vaults {
        let vault_key_enc = vault.vault_key_enc.ok_or("invalid_vault_key")?;
        let key = core_crypto::decrypt_vault_key(smk, vault.id, &vault_key_enc)
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
