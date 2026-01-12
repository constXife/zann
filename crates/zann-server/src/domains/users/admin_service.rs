use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use uuid::Uuid;
use zann_core::{AuthSource, Identity, User, UserStatus};
use zann_db::repo::UserRepo;

use crate::app::AppState;
use crate::config::AuthMode;
use crate::domains::auth::core::passwords::{
    derive_auth_hash, hash_password, random_kdf_salt, KdfParams,
};
use crate::infra::metrics;

pub struct ListUsersCommand {
    pub status: Option<i32>,
    pub sort: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub struct CreateUserCommand {
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
}

pub struct ResetPasswordCommand {
    pub user_id: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum AdminUserError {
    ForbiddenNoBody,
    Forbidden(&'static str),
    BadRequest(&'static str),
    NotFound,
    Db,
    Kdf,
}

pub struct ListUsersResult {
    pub users: Vec<User>,
}

pub struct ResetPasswordResult {
    pub password: String,
    #[allow(dead_code)]
    pub user: User,
}

fn ensure_internal(
    identity: &Identity,
    resource: &str,
    action: &str,
) -> Result<(), AdminUserError> {
    if !matches!(identity.source, AuthSource::Internal) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = action,
            resource = resource,
            reason = "internal_only",
            "Access denied"
        );
        return Err(AdminUserError::ForbiddenNoBody);
    }
    Ok(())
}

fn ensure_policy(
    state: &AppState,
    identity: &Identity,
    resource: &str,
    action: &str,
) -> Result<(), AdminUserError> {
    let policies = state.policy_store.get();
    if !policies.is_allowed(identity, action, resource) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = action,
            resource = resource,
            "Access denied"
        );
        return Err(AdminUserError::ForbiddenNoBody);
    }
    Ok(())
}

pub async fn list_users(
    state: &AppState,
    identity: &Identity,
    cmd: ListUsersCommand,
) -> Result<ListUsersResult, AdminUserError> {
    let resource = "users";
    ensure_internal(identity, resource, "list")?;
    ensure_policy(state, identity, resource, "list")?;

    let status = if let Some(query_status) = cmd.status {
        Some(
            UserStatus::try_from(query_status)
                .map_err(|_| AdminUserError::BadRequest("invalid_query"))?,
        )
    } else {
        None
    };

    let sort = match cmd.sort.as_deref() {
        Some("asc") => "asc",
        Some("desc") => "desc",
        Some(_) => return Err(AdminUserError::BadRequest("invalid_query")),
        None => "desc",
    };
    let limit = cmd.limit.unwrap_or(100).clamp(1, 500);
    let offset = cmd.offset.unwrap_or(0).max(0);

    let repo = UserRepo::new(&state.db);
    let users = match repo.list(limit, offset, sort, status).await {
        Ok(users) => users,
        Err(_) => {
            tracing::error!(event = "users_list_failed", "DB error");
            return Err(AdminUserError::Db);
        }
    };

    tracing::info!(event = "users_list", count = users.len(), "Users listed");
    Ok(ListUsersResult { users })
}

pub async fn create_user(
    state: &AppState,
    identity: &Identity,
    cmd: CreateUserCommand,
) -> Result<User, AdminUserError> {
    let resource = "users";
    ensure_internal(identity, resource, "write")?;
    ensure_policy(state, identity, resource, "write")?;

    if !state.config.auth.internal.enabled || matches!(state.config.auth.mode, AuthMode::Oidc) {
        return Err(AdminUserError::Forbidden("internal_disabled"));
    }

    if cmd.email.trim().is_empty() || cmd.password.trim().is_empty() {
        return Err(AdminUserError::BadRequest("invalid_payload"));
    }

    let params = KdfParams {
        algorithm: state.config.auth.kdf.algorithm.clone(),
        iterations: state.config.auth.kdf.iterations,
        memory_kb: state.config.auth.kdf.memory_kb,
        parallelism: state.config.auth.kdf.parallelism,
    };
    let kdf_salt = random_kdf_salt();

    let mut user = User {
        id: Uuid::now_v7(),
        email: cmd.email.trim().to_string(),
        full_name: cmd
            .full_name
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        password_hash: None,
        recovery_key_hash: None,
        kdf_salt: kdf_salt.clone(),
        kdf_algorithm: params.algorithm.to_string(),
        kdf_iterations: i64::from(params.iterations),
        kdf_memory_kb: i64::from(params.memory_kb),
        kdf_parallelism: i64::from(params.parallelism),
        status: UserStatus::Active,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_login_at: None,
    };
    let _permit = match metrics::acquire_kdf_permit(&state.argon2_semaphore, "users_create").await {
        Ok(permit) => permit,
        Err(_) => {
            tracing::error!(event = "users_create_failed", "Argon2 limiter closed");
            return Err(AdminUserError::Kdf);
        }
    };
    let auth_hash = if let Ok(value) = derive_auth_hash(&cmd.password, &kdf_salt, &params) {
        value
    } else {
        tracing::error!(event = "users_create_failed", "KDF error");
        return Err(AdminUserError::Kdf);
    };
    let password_hash =
        if let Ok(value) = hash_password(&auth_hash, &state.password_pepper, &params) {
            value
        } else {
            tracing::error!(event = "users_create_failed", "KDF error");
            return Err(AdminUserError::Kdf);
        };
    user.password_hash = Some(password_hash);
    let repo = UserRepo::new(&state.db);
    if let Ok(Some(_)) = repo.get_by_email(&user.email).await {
        return Err(AdminUserError::BadRequest("email_exists"));
    }

    let Ok(()) = repo.create(&user).await else {
        tracing::error!(event = "users_create_failed", "DB error");
        return Err(AdminUserError::Db);
    };
    tracing::info!(event = "users_create", user_id = "redacted", "User created");
    Ok(user)
}

pub async fn get_user(
    state: &AppState,
    identity: &Identity,
    user_id: &str,
) -> Result<User, AdminUserError> {
    let resource = "users";
    ensure_internal(identity, resource, "read")?;
    ensure_policy(state, identity, resource, "read")?;

    let Ok(id) = Uuid::parse_str(user_id) else {
        return Err(AdminUserError::BadRequest("invalid_user_id"));
    };

    let repo = UserRepo::new(&state.db);
    let user = match repo.get_by_id(id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(AdminUserError::NotFound),
        Err(_) => {
            tracing::error!(event = "users_get_failed", "DB error");
            return Err(AdminUserError::Db);
        }
    };

    tracing::info!(event = "users_get", user_id = "redacted", "User retrieved");
    Ok(user)
}

pub async fn delete_user(
    state: &AppState,
    identity: &Identity,
    user_id: &str,
    device_id: Option<Uuid>,
) -> Result<(), AdminUserError> {
    let resource = "users";
    ensure_internal(identity, resource, "delete")?;
    ensure_policy(state, identity, resource, "delete")?;

    let Ok(id) = Uuid::parse_str(user_id) else {
        return Err(AdminUserError::BadRequest("invalid_user_id"));
    };

    let repo = UserRepo::new(&state.db);
    let user = match repo.get_by_id(id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(AdminUserError::NotFound),
        Err(_) => {
            tracing::error!(event = "users_delete_failed", "DB error");
            return Err(AdminUserError::Db);
        }
    };

    let deleted_at = chrono::Utc::now();
    let Ok(affected) = repo
        .delete_by_id(
            user.id,
            user.row_version,
            deleted_at,
            identity.user_id,
            device_id,
        )
        .await
    else {
        tracing::error!(event = "users_delete_failed", "DB error");
        return Err(AdminUserError::Db);
    };
    if affected == 0 {
        return Err(AdminUserError::NotFound);
    }

    tracing::info!(event = "users_delete", user_id = "redacted", "User deleted");
    Ok(())
}

pub async fn block_user(
    state: &AppState,
    identity: &Identity,
    user_id: &str,
) -> Result<User, AdminUserError> {
    let resource = "users";
    ensure_internal(identity, resource, "write")?;
    ensure_policy(state, identity, resource, "write")?;

    let Ok(id) = Uuid::parse_str(user_id) else {
        return Err(AdminUserError::BadRequest("invalid_user_id"));
    };

    let repo = UserRepo::new(&state.db);
    let user = match repo.get_by_id(id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(AdminUserError::NotFound),
        Err(_) => {
            tracing::error!(event = "users_block_failed", "DB error");
            return Err(AdminUserError::Db);
        }
    };
    let Ok(affected) = repo
        .update_status(user.id, user.row_version, UserStatus::Disabled)
        .await
    else {
        tracing::error!(event = "users_block_failed", "DB error");
        return Err(AdminUserError::Db);
    };
    if affected == 0 {
        return Err(AdminUserError::NotFound);
    }

    tracing::info!(event = "users_block", user_id = "redacted", "User blocked");
    Ok(user)
}

pub async fn unblock_user(
    state: &AppState,
    identity: &Identity,
    user_id: &str,
) -> Result<User, AdminUserError> {
    let resource = "users";
    ensure_internal(identity, resource, "write")?;
    ensure_policy(state, identity, resource, "write")?;

    let Ok(id) = Uuid::parse_str(user_id) else {
        return Err(AdminUserError::BadRequest("invalid_user_id"));
    };

    let repo = UserRepo::new(&state.db);
    let user = match repo.get_by_id(id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(AdminUserError::NotFound),
        Err(_) => {
            tracing::error!(event = "users_unblock_failed", "DB error");
            return Err(AdminUserError::Db);
        }
    };
    let Ok(affected) = repo
        .update_status(user.id, user.row_version, UserStatus::Active)
        .await
    else {
        tracing::error!(event = "users_unblock_failed", "DB error");
        return Err(AdminUserError::Db);
    };
    if affected == 0 {
        return Err(AdminUserError::NotFound);
    }

    tracing::info!(
        event = "users_unblock",
        user_id = "redacted",
        "User unblocked"
    );
    Ok(user)
}

pub async fn reset_password(
    state: &AppState,
    identity: &Identity,
    cmd: ResetPasswordCommand,
) -> Result<ResetPasswordResult, AdminUserError> {
    let resource = "users";
    ensure_internal(identity, resource, "write")?;
    ensure_policy(state, identity, resource, "write")?;

    if !state.config.auth.internal.enabled || matches!(state.config.auth.mode, AuthMode::Oidc) {
        return Err(AdminUserError::Forbidden("internal_disabled"));
    }

    let Ok(id) = Uuid::parse_str(&cmd.user_id) else {
        return Err(AdminUserError::BadRequest("invalid_user_id"));
    };

    let repo = UserRepo::new(&state.db);
    let user = match repo.get_by_id(id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(AdminUserError::NotFound),
        Err(_) => {
            tracing::error!(event = "users_reset_password_failed", "DB error");
            return Err(AdminUserError::Db);
        }
    };
    if user.status == UserStatus::Disabled {
        return Err(AdminUserError::Forbidden("user_blocked"));
    }

    let password = cmd.password.unwrap_or_else(|| {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(18)
            .map(char::from)
            .collect()
    });

    let params = KdfParams {
        algorithm: user.kdf_algorithm.clone(),
        iterations: u32::try_from(user.kdf_iterations).unwrap_or(0),
        memory_kb: u32::try_from(user.kdf_memory_kb).unwrap_or(0),
        parallelism: u32::try_from(user.kdf_parallelism).unwrap_or(0),
    };
    let _permit =
        match metrics::acquire_kdf_permit(&state.argon2_semaphore, "users_reset_password").await {
            Ok(permit) => permit,
            Err(_) => {
                tracing::error!(
                    event = "users_reset_password_failed",
                    "Argon2 limiter closed"
                );
                return Err(AdminUserError::Kdf);
            }
        };
    let auth_hash = if let Ok(value) = derive_auth_hash(&password, &user.kdf_salt, &params) {
        value
    } else {
        tracing::error!(event = "users_reset_password_failed", "KDF error");
        return Err(AdminUserError::Kdf);
    };
    let password_hash =
        if let Ok(value) = hash_password(&auth_hash, &state.password_pepper, &params) {
            value
        } else {
            tracing::error!(event = "users_reset_password_failed", "KDF error");
            return Err(AdminUserError::Kdf);
        };
    let Ok(affected) = repo
        .update_password_hash(user.id, user.row_version, Some(&password_hash))
        .await
    else {
        tracing::error!(event = "users_reset_password_failed", "DB error");
        return Err(AdminUserError::Db);
    };
    if affected == 0 {
        return Err(AdminUserError::NotFound);
    }

    tracing::info!(
        event = "users_reset_password",
        user_id = "redacted",
        "Password reset"
    );
    Ok(ResetPasswordResult { password, user })
}
