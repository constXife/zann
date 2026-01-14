use chrono::Utc;
use zann_core::{extract_groups, AuthSource, Identity, OidcToken, User, UserStatus};
use zann_db::repo::{
    GroupMemberRepo, GroupRepo, OidcGroupMappingRepo, OidcIdentityRepo, ServiceAccountRepo,
    ServiceAccountSessionRepo, SessionRepo, UserRepo,
};

use crate::app::AppState;
use crate::domains::auth::core::passwords::{hash_service_token, random_kdf_salt, KdfParams};
use crate::infra::user_display::{avatar_initials_for_user, display_name_for_user};

const SERVICE_ACCOUNT_PREFIX: &str = "zann_sa_";
const SERVICE_ACCOUNT_PREFIX_LEN: usize = 12;

pub async fn identity_from_oidc(
    state: &AppState,
    oidc_token: OidcToken,
) -> Result<Identity, &'static str> {
    let oidc_repo = OidcIdentityRepo::new(&state.db);
    let user_repo = UserRepo::new(&state.db);
    let group_repo = GroupRepo::new(&state.db);
    let group_member_repo = GroupMemberRepo::new(&state.db);
    let mapping_repo = OidcGroupMappingRepo::new(&state.db);

    let user = if let Some(identity) = oidc_repo
        .get_by_issuer_subject(&oidc_token.issuer, &oidc_token.subject)
        .await
        .map_err(|err| {
            tracing::error!(
                event = "auth_oidc_identity_lookup_failed",
                error = %err,
                "Failed to load OIDC identity"
            );
            "db_error"
        })? {
        user_repo
            .get_by_id(identity.user_id)
            .await
            .map_err(|err| {
                tracing::error!(
                    event = "auth_user_lookup_failed",
                    error = %err,
                    "Failed to load user"
                );
                "db_error"
            })?
            .ok_or("user_not_found")?
    } else {
        let email = oidc_token.email.clone().ok_or("email_missing")?;
        let params = KdfParams {
            algorithm: state.config.auth.kdf.algorithm.clone(),
            iterations: state.config.auth.kdf.iterations,
            memory_kb: state.config.auth.kdf.memory_kb,
            parallelism: state.config.auth.kdf.parallelism,
        };
        let user = User {
            id: uuid::Uuid::now_v7(),
            email,
            full_name: None,
            password_hash: None,
            kdf_salt: random_kdf_salt(),
            kdf_algorithm: params.algorithm.clone(),
            kdf_iterations: i64::from(params.iterations),
            kdf_memory_kb: i64::from(params.memory_kb),
            kdf_parallelism: i64::from(params.parallelism),
            recovery_key_hash: None,
            status: UserStatus::Active,
            deleted_at: None,
            deleted_by_user_id: None,
            deleted_by_device_id: None,
            row_version: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login_at: None,
        };

        user_repo.create(&user).await.map_err(|err| {
            tracing::error!(
                event = "auth_oidc_user_create_failed",
                error = %err,
                "Failed to create OIDC user"
            );
            "db_error"
        })?;

        let identity = zann_core::OidcIdentity {
            id: uuid::Uuid::now_v7(),
            user_id: user.id,
            issuer: oidc_token.issuer.clone(),
            subject: oidc_token.subject.clone(),
            created_at: Utc::now(),
        };
        oidc_repo.create(&identity).await.map_err(|err| {
            tracing::error!(
                event = "auth_oidc_identity_create_failed",
                error = %err,
                "Failed to create OIDC identity"
            );
            "db_error"
        })?;

        user
    };

    if !matches!(user.status, UserStatus::Active) {
        return Err("user_disabled");
    }

    let groups_claim = state
        .config
        .auth
        .oidc
        .groups_claim
        .clone()
        .unwrap_or_else(|| "groups".to_string());
    let oidc_groups = extract_groups(&oidc_token, &groups_claim);
    let mut groups = Vec::new();

    for oidc_group in &oidc_groups {
        if let Some(mapped) = state.config.auth.oidc.group_mappings.get(oidc_group) {
            groups.push(mapped.clone());
        }
        if let Some(mapping) = mapping_repo
            .get_by_issuer_group(&oidc_token.issuer, oidc_group)
            .await
            .map_err(|err| {
                tracing::error!(
                    event = "auth_oidc_group_mapping_lookup_failed",
                    error = %err,
                    "Failed to load OIDC group mapping"
                );
                "db_error"
            })?
        {
            if let Some(group) = group_repo
                .get_by_id(mapping.internal_group_id)
                .await
                .map_err(|err| {
                    tracing::error!(
                        event = "auth_group_lookup_failed",
                        error = %err,
                        "Failed to load group"
                    );
                    "db_error"
                })?
            {
                groups.push(group.slug);
            }
        }
    }

    if let Some(admin_group) = state.config.auth.oidc.admin_group.as_ref() {
        if oidc_groups.iter().any(|g| g == admin_group) {
            groups.push("admins".to_string());
        }
    }

    for member in group_member_repo
        .list_by_user(user.id)
        .await
        .map_err(|err| {
            tracing::error!(
                event = "auth_group_membership_lookup_failed",
                error = %err,
                "Failed to load group memberships"
            );
            "db_error"
        })?
    {
        if let Some(group) = group_repo.get_by_id(member.group_id).await.map_err(|err| {
            tracing::error!(
                event = "auth_group_lookup_failed",
                error = %err,
                "Failed to load group"
            );
            "db_error"
        })? {
            groups.push(group.slug);
        }
    }

    groups.sort();
    groups.dedup();

    let email = user.email.clone();
    let display_name = display_name_for_user(user.full_name.as_deref(), &email);
    let avatar_initials = avatar_initials_for_user(user.full_name.as_deref(), &email);

    Ok(Identity {
        user_id: user.id,
        email,
        display_name,
        avatar_url: None,
        avatar_initials,
        groups,
        source: AuthSource::Oidc {
            issuer: oidc_token.issuer,
            subject: oidc_token.subject,
        },
        device_id: None,
        service_account_id: None,
    })
}

pub async fn identity_from_service_account_token(
    state: &AppState,
    token: &str,
    client_ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<Identity, &'static str> {
    if !token.starts_with(SERVICE_ACCOUNT_PREFIX) {
        return Err("invalid_token");
    }

    let token_prefix: String = token.chars().take(SERVICE_ACCOUNT_PREFIX_LEN).collect();
    let repo = ServiceAccountRepo::new(&state.db);
    let accounts = repo.list_by_prefix(&token_prefix).await.map_err(|err| {
        tracing::error!(
            event = "auth_sa_list_failed",
            error = %err,
            "Failed to list service accounts"
        );
        "db_error"
    })?;

    let params = KdfParams {
        algorithm: state.config.auth.kdf.algorithm.clone(),
        iterations: state.config.auth.kdf.iterations,
        memory_kb: state.config.auth.kdf.memory_kb,
        parallelism: state.config.auth.kdf.parallelism,
    };
    let token_hash = hash_service_token(token, &state.token_pepper, &params)?;
    let account = accounts
        .into_iter()
        .find(|account| account.token_hash == token_hash)
        .ok_or("invalid_token")?;

    if account.revoked_at.is_some() {
        return Err("token_revoked");
    }
    if account
        .expires_at
        .is_some_and(|expires_at| expires_at < Utc::now())
    {
        return Err("token_expired");
    }
    if let Some(allowed_ips) = account.allowed_ips.as_ref() {
        let Some(client_ip) = client_ip else {
            return Err("ip_not_allowed");
        };
        if !allowed_ips.0.iter().any(|ip| ip == client_ip) {
            return Err("ip_not_allowed");
        }
    }

    if let Err(err) = repo
        .update_usage(account.id, Utc::now(), client_ip, user_agent, 1)
        .await
    {
        tracing::warn!(event = "auth_sa_usage_update_failed", error = %err);
    }

    identity_from_user(
        state,
        account.owner_user_id,
        AuthSource::ServiceAccount,
        None,
        Some(account.id),
    )
    .await
}

pub async fn identity_from_session_token(
    state: &AppState,
    token: &str,
) -> Result<Identity, &'static str> {
    let token_hash = crate::domains::auth::core::tokens::hash_token(token, &state.token_pepper);
    let session_repo = SessionRepo::new(&state.db);
    let service_account_session_repo = ServiceAccountSessionRepo::new(&state.db);
    let service_account_repo = ServiceAccountRepo::new(&state.db);

    let (user_id, device_id, service_account_id, source) = if let Some(session) = session_repo
        .get_by_access_token_hash(&token_hash)
        .await
        .map_err(|err| {
            tracing::error!(
                event = "auth_session_lookup_failed",
                error = %err,
                "Failed to load session by access token"
            );
            "db_error"
        })? {
        if session.access_expires_at < Utc::now() {
            return Err("token_expired");
        }
        (
            session.user_id,
            Some(session.device_id),
            None,
            AuthSource::Internal,
        )
    } else if let Some(session) = service_account_session_repo
        .get_by_access_token_hash(&token_hash)
        .await
        .map_err(|err| {
            tracing::error!(
                event = "auth_sa_session_lookup_failed",
                error = %err,
                "Failed to load service account session by access token"
            );
            "db_error"
        })?
    {
        if session.expires_at < Utc::now() {
            return Err("token_expired");
        }
        let account = service_account_repo
            .get_by_id(session.service_account_id)
            .await
            .map_err(|err| {
                tracing::error!(
                    event = "auth_sa_lookup_failed",
                    error = %err,
                    "Failed to load service account"
                );
                "db_error"
            })?
            .ok_or("invalid_token")?;
        if account.revoked_at.is_some() {
            return Err("token_revoked");
        }
        if account
            .expires_at
            .is_some_and(|expires_at| expires_at < Utc::now())
        {
            return Err("token_expired");
        }

        (
            account.owner_user_id,
            None,
            Some(account.id),
            AuthSource::ServiceAccount,
        )
    } else {
        return Err("invalid_token");
    };
    identity_from_user(state, user_id, source, device_id, service_account_id).await
}

async fn identity_from_user(
    state: &AppState,
    user_id: uuid::Uuid,
    source: AuthSource,
    device_id: Option<uuid::Uuid>,
    service_account_id: Option<uuid::Uuid>,
) -> Result<Identity, &'static str> {
    let user_repo = UserRepo::new(&state.db);
    let group_repo = GroupRepo::new(&state.db);
    let group_member_repo = GroupMemberRepo::new(&state.db);
    let user = user_repo
        .get_by_id(user_id)
        .await
        .map_err(|err| {
            tracing::error!(
                event = "auth_user_lookup_failed",
                error = %err,
                "Failed to load user"
            );
            "db_error"
        })?
        .ok_or("user_not_found")?;

    let status_allowed = matches!(user.status, UserStatus::Active)
        || (matches!(user.status, UserStatus::System)
            && matches!(source, AuthSource::ServiceAccount));
    if !status_allowed {
        return Err("user_disabled");
    }

    let mut groups = Vec::new();
    for member in group_member_repo
        .list_by_user(user.id)
        .await
        .map_err(|err| {
            tracing::error!(
                event = "auth_group_membership_lookup_failed",
                error = %err,
                "Failed to load group memberships"
            );
            "db_error"
        })?
    {
        if let Some(group) = group_repo.get_by_id(member.group_id).await.map_err(|err| {
            tracing::error!(
                event = "auth_group_lookup_failed",
                error = %err,
                "Failed to load group"
            );
            "db_error"
        })? {
            groups.push(group.slug);
        }
    }

    groups.sort();
    groups.dedup();

    let email = user.email.clone();
    let display_name = display_name_for_user(user.full_name.as_deref(), &email);
    let avatar_initials = avatar_initials_for_user(user.full_name.as_deref(), &email);

    Ok(Identity {
        user_id: user.id,
        email,
        display_name,
        avatar_url: None,
        avatar_initials,
        groups,
        source,
        device_id,
        service_account_id,
    })
}
