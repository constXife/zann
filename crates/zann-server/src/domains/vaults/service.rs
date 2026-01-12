use chrono::Utc;
use sqlx_core::types::Json as SqlxJson;
use uuid::Uuid;
use zann_core::api::vaults::VaultSummary;
use zann_core::{CachePolicy, Identity, Vault, VaultEncryptionType, VaultKind};
use zann_crypto::crypto::SecretKey;
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{VaultMemberRepo, VaultRepo};

use crate::app::AppState;
use crate::domains::access_control::http::{find_vault, vault_role_allows, VaultScope};
use crate::domains::access_control::policies::PolicyDecision;
use crate::infra::metrics;
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy)]
pub enum VaultServiceError {
    #[error("forbidden_no_body")]
    ForbiddenNoBody,
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    #[error("not_found")]
    NotFound,
    #[error("bad_request: {0}")]
    BadRequest(&'static str),
    #[error("db_error")]
    DbError,
    #[error("internal: {0}")]
    Internal(&'static str),
}

pub struct ListVaultsCommand {
    pub sort: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub struct CreateVaultCommand {
    pub id: Option<String>,
    pub slug: String,
    pub name: String,
    pub kind: VaultKind,
    pub cache_policy: CachePolicy,
    pub vault_key_enc: Option<Vec<u8>>,
    pub tags: Option<Vec<String>>,
}

pub struct UpdateVaultKeyCommand {
    pub vault_id: String,
    pub vault_key_enc: Vec<u8>,
}

pub async fn list_vault_summaries(
    state: &AppState,
    identity: &Identity,
    cmd: ListVaultsCommand,
) -> Result<Vec<VaultSummary>, VaultServiceError> {
    let policies = state.policy_store.get();
    let resource = "vaults/*";
    if !policies.is_allowed(identity, "list", resource) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = "list",
            resource = %resource,
            "Access denied"
        );
        return Err(VaultServiceError::ForbiddenNoBody);
    }

    let limit = cmd.limit.unwrap_or(50).clamp(1, 200);
    let offset = cmd.offset.unwrap_or(0).max(0);
    let sort = cmd.sort.as_deref().unwrap_or("desc");

    let repo = VaultRepo::new(&state.db);
    let vaults = repo
        .list_by_user(identity.user_id, limit, offset, sort)
        .await
        .map_err(|_| VaultServiceError::DbError)?;

    Ok(vaults
        .into_iter()
        .map(|vault| VaultSummary {
            id: vault.id,
            slug: vault.slug,
            name: vault.name,
            kind: vault.kind,
            cache_policy: vault.cache_policy,
            tags: vault.tags.map(|tags| tags.0),
        })
        .collect())
}

pub async fn create_vault(
    state: &AppState,
    identity: &Identity,
    cmd: CreateVaultCommand,
) -> Result<Vault, VaultServiceError> {
    if identity.service_account_id.is_some() {
        return Err(VaultServiceError::ForbiddenNoBody);
    }
    let resource = "vaults";
    let policies = state.policy_store.get();
    if !policies.is_allowed(identity, "write", resource) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = resource,
            "Access denied"
        );
        return Err(VaultServiceError::ForbiddenNoBody);
    }

    let slug = cmd.slug.trim();
    let name = cmd.name.trim();
    if slug.is_empty() {
        return Err(VaultServiceError::BadRequest("invalid_slug"));
    }
    if name.is_empty() {
        return Err(VaultServiceError::BadRequest("invalid_name"));
    }

    let kind = cmd.kind;
    let cache_policy = cmd.cache_policy;

    let repo = VaultRepo::new(&state.db);
    if kind == VaultKind::Personal {
        if !state.config.server.personal_vaults_enabled {
            return Err(VaultServiceError::Forbidden("personal_disabled"));
        }
        return Err(VaultServiceError::Forbidden("personal_managed"));
    }

    match repo.get_by_slug(slug).await {
        Ok(Some(_)) => {
            return Err(VaultServiceError::BadRequest("slug_taken"));
        }
        Ok(None) => {}
        Err(_) => {
            tracing::error!(event = "vault_create_failed", "DB error");
            return Err(VaultServiceError::DbError);
        }
    }

    let now = Utc::now();
    let vault_id = if let Some(id) = cmd.id.as_deref() {
        let parsed =
            Uuid::parse_str(id).map_err(|_| VaultServiceError::BadRequest("invalid_id"))?;
        match repo.get_by_id(parsed).await {
            Ok(Some(_)) => {
                return Err(VaultServiceError::BadRequest("id_taken"));
            }
            Ok(None) => parsed,
            Err(_) => {
                tracing::error!(event = "vault_create_failed", "DB error");
                return Err(VaultServiceError::DbError);
            }
        }
    } else {
        Uuid::now_v7()
    };
    let tags = cmd
        .tags
        .map(|tags| {
            tags.into_iter()
                .map(|tag| tag.trim().to_string())
                .filter(|tag| !tag.is_empty())
                .collect::<Vec<String>>()
        })
        .filter(|tags| !tags.is_empty())
        .map(SqlxJson);

    let (encryption_type, vault_key_enc) = match kind {
        VaultKind::Shared => {
            let Some(smk) = state.server_master_key.as_ref() else {
                return Err(VaultServiceError::Internal("smk_missing"));
            };
            let vault_key = SecretKey::generate();
            let vault_key_enc = core_crypto::encrypt_vault_key(smk, vault_id, &vault_key)
                .map_err(|_| VaultServiceError::Internal("vault_key_encrypt_failed"))?;
            (VaultEncryptionType::Server, vault_key_enc)
        }
        VaultKind::Personal => {
            let Some(vault_key_enc) = cmd.vault_key_enc else {
                return Err(VaultServiceError::BadRequest("vault_key_missing"));
            };
            (VaultEncryptionType::Client, vault_key_enc)
        }
    };

    let vault = Vault {
        id: vault_id,
        slug: slug.to_string(),
        name: name.to_string(),
        kind,
        encryption_type,
        vault_key_enc,
        cache_policy,
        tags,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: now,
    };

    if repo.create(&vault).await.is_err() {
        tracing::error!(event = "vault_create_failed", "DB error");
        return Err(VaultServiceError::DbError);
    }

    let member_repo = VaultMemberRepo::new(&state.db);
    let member = zann_core::VaultMember {
        vault_id: vault.id,
        user_id: identity.user_id,
        role: zann_core::VaultMemberRole::Admin,
        created_at: now,
    };
    if member_repo.create(&member).await.is_err() {
        tracing::error!(event = "vault_member_create_failed", "DB error");
        return Err(VaultServiceError::DbError);
    }

    tracing::info!(event = "vault_created", vault_id = %vault.id, "Vault created");
    Ok(vault)
}

pub async fn get_vault(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
) -> Result<Vault, VaultServiceError> {
    let resource = format!("vaults/{vault_id}");
    let policies = state.policy_store.get();

    let repo = VaultRepo::new(&state.db);
    let vault = match find_vault(&repo, vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return Err(VaultServiceError::NotFound),
        Err(_) => {
            tracing::error!(event = "vault_get_failed", "DB error");
            return Err(VaultServiceError::DbError);
        }
    };

    match policies.evaluate(identity, "read", &resource) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny => {
            metrics::forbidden_access(&resource);
            tracing::warn!(
                event = "forbidden",
                action = "read",
                resource = %resource,
                "Access denied"
            );
            return Err(VaultServiceError::ForbiddenNoBody);
        }
        PolicyDecision::NoMatch => {
            match vault_role_allows(state, identity, vault.id, "read", VaultScope::Vault).await {
                Ok(true) => {}
                Ok(false) => {
                    metrics::forbidden_access(&resource);
                    tracing::warn!(
                        event = "forbidden",
                        action = "read",
                        resource = %resource,
                        "Access denied"
                    );
                    return Err(VaultServiceError::ForbiddenNoBody);
                }
                Err(_) => {
                    tracing::error!(event = "vault_access_failed", "DB error");
                    return Err(VaultServiceError::DbError);
                }
            }
        }
    }

    tracing::info!(event = "vault_fetched", "Vault fetched");
    Ok(vault)
}

pub async fn update_vault_key(
    state: &AppState,
    identity: &Identity,
    cmd: UpdateVaultKeyCommand,
) -> Result<(), VaultServiceError> {
    if identity.service_account_id.is_some() {
        return Err(VaultServiceError::ForbiddenNoBody);
    }
    let resource = format!("vaults/{}", cmd.vault_id);
    let policies = state.policy_store.get();

    let repo = VaultRepo::new(&state.db);
    let vault = match find_vault(&repo, &cmd.vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return Err(VaultServiceError::NotFound),
        Err(_) => {
            tracing::error!(event = "vault_get_failed", "DB error");
            return Err(VaultServiceError::DbError);
        }
    };

    match policies.evaluate(identity, "write", &resource) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny => {
            metrics::forbidden_access(&resource);
            tracing::warn!(
                event = "forbidden",
                action = "write",
                resource = %resource,
                "Access denied"
            );
            return Err(VaultServiceError::ForbiddenNoBody);
        }
        PolicyDecision::NoMatch => {
            match vault_role_allows(state, identity, vault.id, "write", VaultScope::Vault).await {
                Ok(true) => {}
                Ok(false) => {
                    metrics::forbidden_access(&resource);
                    tracing::warn!(
                        event = "forbidden",
                        action = "write",
                        resource = %resource,
                        "Access denied"
                    );
                    return Err(VaultServiceError::ForbiddenNoBody);
                }
                Err(_) => {
                    tracing::error!(event = "vault_access_failed", "DB error");
                    return Err(VaultServiceError::DbError);
                }
            }
        }
    }

    if vault.encryption_type != VaultEncryptionType::Client || vault.kind != VaultKind::Personal {
        return Err(VaultServiceError::BadRequest(
            "vault_key_update_not_allowed",
        ));
    }

    let key_checksum = blake3::hash(&cmd.vault_key_enc).to_hex().to_string();
    let Ok(affected) = repo.update_key_by_id(vault.id, &cmd.vault_key_enc).await else {
        tracing::error!(event = "vault_key_update_failed", "DB error");
        return Err(VaultServiceError::DbError);
    };
    if affected == 0 {
        return Err(VaultServiceError::NotFound);
    }

    tracing::info!(
        event = "vault_key_updated",
        vault_id = %vault.id,
        key_checksum = %key_checksum,
        "Vault key updated"
    );
    Ok(())
}

pub async fn delete_vault(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
) -> Result<(), VaultServiceError> {
    if identity.service_account_id.is_some() {
        return Err(VaultServiceError::ForbiddenNoBody);
    }
    let resource = format!("vaults/{vault_id}");
    let policies = state.policy_store.get();

    let repo = VaultRepo::new(&state.db);
    let vault = match find_vault(&repo, vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return Err(VaultServiceError::NotFound),
        Err(_) => {
            tracing::error!(event = "vault_get_failed", "DB error");
            return Err(VaultServiceError::DbError);
        }
    };

    match policies.evaluate(identity, "write", &resource) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny => {
            metrics::forbidden_access(&resource);
            tracing::warn!(
                event = "forbidden",
                action = "write",
                resource = %resource,
                "Access denied"
            );
            return Err(VaultServiceError::ForbiddenNoBody);
        }
        PolicyDecision::NoMatch => {
            match vault_role_allows(state, identity, vault.id, "write", VaultScope::Vault).await {
                Ok(true) => {}
                Ok(false) => {
                    metrics::forbidden_access(&resource);
                    tracing::warn!(
                        event = "forbidden",
                        action = "write",
                        resource = %resource,
                        "Access denied"
                    );
                    return Err(VaultServiceError::ForbiddenNoBody);
                }
                Err(_) => {
                    tracing::error!(event = "vault_access_failed", "DB error");
                    return Err(VaultServiceError::DbError);
                }
            }
        }
    }

    let Ok(affected) = repo
        .delete_by_id(
            vault.id,
            vault.row_version,
            Utc::now(),
            identity.user_id,
            identity.device_id,
        )
        .await
    else {
        tracing::error!(event = "vault_delete_failed", "DB error");
        return Err(VaultServiceError::DbError);
    };
    if affected == 0 {
        return Err(VaultServiceError::NotFound);
    }

    tracing::info!(event = "vault_deleted", vault_id = %vault.id, "Vault deleted");
    Ok(())
}
