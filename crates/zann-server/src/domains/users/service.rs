use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use zann_core::{AuthSource, Identity, User};
use zann_db::repo::UserRepo;

use crate::app::AppState;
use crate::config::AuthMode;
use crate::domains::auth::core::passwords::{
    derive_auth_hash, hash_password, kdf_params_from_user, verify_password,
};
use crate::domains::errors::ServiceError;
use crate::infra::metrics;

pub struct UpdateMeCommand {
    pub full_name: Option<String>,
}

pub struct ChangePasswordCommand {
    pub current_password: String,
    pub new_password: String,
}

pub struct RecoveryKitResult {
    pub recovery_key: String,
}

pub type MeError = ServiceError;

pub async fn get_me(state: &AppState, identity: &Identity) -> Result<Identity, MeError> {
    let policies = state.policy_store.get();
    if !policies.is_allowed(identity, "read", "users/me") {
        metrics::forbidden_access("users/me");
        tracing::warn!(
            event = "forbidden",
            action = "read",
            resource = "users/me",
            "Access denied"
        );
        return Err(MeError::ForbiddenNoBody);
    }

    tracing::info!(event = "users_me", "User profile returned");
    Ok(identity.clone())
}

pub async fn update_me(
    state: &AppState,
    identity: &Identity,
    cmd: UpdateMeCommand,
) -> Result<User, MeError> {
    let resource = "users/me";
    if matches!(
        identity.source,
        AuthSource::Device | AuthSource::ServiceAccount
    ) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = resource,
            reason = "device_token",
            "Access denied"
        );
        return Err(MeError::ForbiddenNoBody);
    }

    let policies = state.policy_store.get();
    if !policies.is_allowed(identity, "write", resource) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = resource,
            "Access denied"
        );
        return Err(MeError::ForbiddenNoBody);
    }

    let repo = UserRepo::new(&state.db);
    let mut user = match repo.get_by_id(identity.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(MeError::NotFound),
        Err(_) => {
            tracing::error!(event = "users_me_update_failed", "DB error");
            return Err(MeError::DbError);
        }
    };

    let mut updated = false;
    if let Some(full_name) = cmd.full_name {
        let trimmed = full_name.trim();
        let next = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        if user.full_name != next {
            user.full_name = next;
            updated = true;
        }
    }

    if !updated {
        return Err(MeError::NoChanges);
    }

    let Ok(affected) = repo
        .update_full_name(
            identity.user_id,
            user.row_version,
            user.full_name.as_deref(),
        )
        .await
    else {
        tracing::error!(event = "users_me_update_failed", "DB error");
        return Err(MeError::DbError);
    };
    if affected == 0 {
        return Err(MeError::NotFound);
    }

    tracing::info!(event = "users_me_updated", "User profile updated");
    Ok(user)
}

pub async fn change_password(
    state: &AppState,
    identity: &Identity,
    cmd: ChangePasswordCommand,
) -> Result<(), MeError> {
    let resource = "users/me/password";
    if !matches!(identity.source, AuthSource::Internal) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = resource,
            reason = "internal_only",
            "Access denied"
        );
        return Err(MeError::ForbiddenNoBody);
    }

    let policies = state.policy_store.get();
    if !policies.is_allowed(identity, "write", resource) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = resource,
            "Access denied"
        );
        return Err(MeError::ForbiddenNoBody);
    }

    if !state.config.auth.internal.enabled || matches!(state.config.auth.mode, AuthMode::Oidc) {
        return Err(MeError::Forbidden("internal_disabled"));
    }

    if cmd.current_password.is_empty() || cmd.new_password.is_empty() {
        return Err(MeError::InvalidPassword);
    }

    let user_repo = UserRepo::new(&state.db);
    let user = match user_repo.get_by_id(identity.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(MeError::Forbidden("internal_only")),
        Err(_) => {
            tracing::error!(event = "users_me_password_failed", "DB error");
            return Err(MeError::DbError);
        }
    };

    let _permit =
        match metrics::acquire_kdf_permit(&state.argon2_semaphore, "users_change_password").await {
            Ok(permit) => permit,
            Err(_) => {
                tracing::error!(event = "users_me_password_failed", "Argon2 limiter closed");
                return Err(MeError::Kdf);
            }
        };
    let Ok(valid) = verify_password(&user, &cmd.current_password, &state.password_pepper) else {
        tracing::error!(event = "users_me_password_failed", "KDF error");
        return Err(MeError::Kdf);
    };

    if !valid {
        return Err(MeError::InvalidCredentials);
    }

    let params = kdf_params_from_user(&user);
    let _permit =
        match metrics::acquire_kdf_permit(&state.argon2_semaphore, "users_change_password").await {
            Ok(permit) => permit,
            Err(_) => {
                tracing::error!(event = "users_me_password_failed", "Argon2 limiter closed");
                return Err(MeError::Kdf);
            }
        };
    let auth_hash = if let Ok(value) = derive_auth_hash(&cmd.new_password, &user.kdf_salt, &params)
    {
        value
    } else {
        tracing::error!(event = "users_me_password_failed", "KDF error");
        return Err(MeError::Kdf);
    };
    let password_hash =
        if let Ok(value) = hash_password(&auth_hash, &state.password_pepper, &params) {
            value
        } else {
            tracing::error!(event = "users_me_password_failed", "KDF error");
            return Err(MeError::Kdf);
        };
    let Ok(affected) = user_repo
        .update_password_hash(identity.user_id, user.row_version, Some(&password_hash))
        .await
    else {
        tracing::error!(event = "users_me_password_failed", "DB error");
        return Err(MeError::DbError);
    };
    if affected == 0 {
        return Err(MeError::NotFound);
    }

    tracing::info!(event = "users_me_password_changed", "Password changed");
    Ok(())
}

pub async fn create_recovery_kit(
    state: &AppState,
    identity: &Identity,
) -> Result<RecoveryKitResult, MeError> {
    let resource = "users/me/recovery-kit";
    if !matches!(identity.source, AuthSource::Internal) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = resource,
            reason = "internal_only",
            "Access denied"
        );
        return Err(MeError::ForbiddenNoBody);
    }

    let policies = state.policy_store.get();
    if !policies.is_allowed(identity, "write", resource) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = resource,
            "Access denied"
        );
        return Err(MeError::ForbiddenNoBody);
    }

    if !state.config.auth.internal.enabled || matches!(state.config.auth.mode, AuthMode::Oidc) {
        return Err(MeError::Forbidden("internal_disabled"));
    }

    let user_repo = UserRepo::new(&state.db);
    let user = match user_repo.get_by_id(identity.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(MeError::Forbidden("internal_only")),
        Err(_) => {
            tracing::error!(event = "users_me_recovery_failed", "DB error");
            return Err(MeError::DbError);
        }
    };
    if user.password_hash.is_none() {
        return Err(MeError::Forbidden("internal_only"));
    }

    let recovery_key: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();
    let params = kdf_params_from_user(&user);
    let _permit =
        match metrics::acquire_kdf_permit(&state.argon2_semaphore, "users_recovery_kit").await {
            Ok(permit) => permit,
            Err(_) => {
                tracing::error!(event = "users_me_recovery_failed", "Argon2 limiter closed");
                return Err(MeError::Kdf);
            }
        };
    let auth_hash = if let Ok(value) = derive_auth_hash(&recovery_key, &user.kdf_salt, &params) {
        value
    } else {
        tracing::error!(event = "users_me_recovery_failed", "KDF error");
        return Err(MeError::Kdf);
    };
    let recovery_key_hash =
        if let Ok(value) = hash_password(&auth_hash, &state.password_pepper, &params) {
            value
        } else {
            tracing::error!(event = "users_me_recovery_failed", "KDF error");
            return Err(MeError::Kdf);
        };

    let Ok(affected) = user_repo
        .update_recovery_key_hash(identity.user_id, user.row_version, &recovery_key_hash)
        .await
    else {
        tracing::error!(event = "users_me_recovery_failed", "DB error");
        return Err(MeError::DbError);
    };
    if affected == 0 {
        return Err(MeError::NotFound);
    }

    tracing::info!(event = "users_me_recovery_created", "Recovery kit created");
    Ok(RecoveryKitResult { recovery_key })
}
