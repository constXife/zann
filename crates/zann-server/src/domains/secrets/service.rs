use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use zann_core::{Change, ChangeOp, ChangeType, Identity, Item, ItemHistory, SyncStatus, Vault};
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{ChangeRepo, DeviceRepo, ItemHistoryRepo, ItemRepo, UserRepo, VaultRepo};

use crate::app::AppState;
use crate::domains::access_control::http::{find_vault, vault_role_allows, VaultScope};
use crate::domains::access_control::policies::PolicyDecision;
use crate::domains::items::service::basename_from_path;
use crate::domains::secrets::policies::{generate_secret, PasswordPolicy};
use crate::infra::metrics;

#[derive(Debug, Clone)]
pub enum SecretError {
    ForbiddenNoBody,
    Forbidden(&'static str),
    NotFound,
    BadRequest(&'static str),
    Conflict(&'static str),
    PolicyMismatch { existing: String, requested: String },
    Db,
    Internal(&'static str),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPayload {
    pub value: String,
    pub policy: String,
    #[serde(default)]
    pub meta: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct SecretRecord {
    pub path: String,
    pub vault_id: String,
    pub value: String,
    pub policy: String,
    pub meta: Option<HashMap<String, String>>,
    pub version: i64,
}

struct ActorSnapshot {
    email: String,
    name: Option<String>,
    device_name: Option<String>,
}

pub async fn get_secret(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    path: &str,
) -> Result<SecretRecord, SecretError> {
    let normalized_path = normalize_secret_path(path)?;
    let resource = format!("vaults/{vault_id}/secrets/{normalized_path}");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "read",
        &resource,
        VaultScope::Items,
    )
    .await?;

    ensure_server_encryption(state, &vault)?;

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo
        .get_by_vault_path(vault.id, &normalized_path)
        .await
    {
        Ok(Some(item)) => item,
        Ok(None) => return Err(SecretError::NotFound),
        Err(_) => {
            tracing::error!(event = "secret_get_failed", "DB error");
            return Err(SecretError::Db);
        }
    };

    if item.type_id != "secret" || item.sync_status != SyncStatus::Active {
        return Err(SecretError::NotFound);
    }

    let payload = decrypt_secret_payload(state, &vault, &item)?;

    let usage_tracker = state.usage_tracker.clone();
    let user_id = identity.user_id;
    let device_id = identity.device_id;
    let item_id = item.id;
    tokio::spawn(async move {
        usage_tracker.record_read(item_id, user_id, device_id).await;
    });
    Ok(SecretRecord {
        path: item.path,
        vault_id: vault.id.to_string(),
        value: payload.value,
        policy: payload.policy,
        meta: payload.meta,
        version: item.version,
    })
}

pub async fn ensure_secret(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    path: &str,
    policy_name: Option<&str>,
    meta: Option<HashMap<String, String>>,
) -> Result<(SecretRecord, bool), SecretError> {
    let device_id = identity
        .device_id
        .ok_or(SecretError::Forbidden("device_required"))?;
    let normalized_path = normalize_secret_path(path)?;
    let resource = format!("vaults/{vault_id}/secrets/{normalized_path}");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "write",
        &resource,
        VaultScope::Items,
    )
    .await?;

    ensure_server_encryption(state, &vault)?;

    let item_repo = ItemRepo::new(&state.db);
    if let Ok(Some(item)) = item_repo
        .get_by_vault_path(vault.id, &normalized_path)
        .await
    {
        if item.type_id != "secret" || item.sync_status != SyncStatus::Active {
            return Err(SecretError::Conflict("path_in_use"));
        }
        let payload = decrypt_secret_payload(state, &vault, &item)?;
        let requested_policy = resolve_policy_name(state, policy_name);
        if payload.policy != requested_policy {
            return Err(SecretError::PolicyMismatch {
                existing: payload.policy,
                requested: requested_policy,
            });
        }
        let record = SecretRecord {
            path: item.path,
            vault_id: vault.id.to_string(),
            value: payload.value,
            policy: payload.policy,
            meta: payload.meta,
            version: item.version,
        };
        return Ok((record, false));
    }

    let (policy_name, policy) = resolve_policy(state, policy_name)?;
    let value = generate_secret(&policy).map_err(SecretError::Internal)?;
    let normalized_meta = normalize_meta(meta);
    let payload = SecretPayload {
        value: value.clone(),
        policy: policy_name.clone(),
        meta: normalized_meta.clone(),
    };

    let item_id = Uuid::now_v7();
    let (payload_enc, checksum) = encrypt_secret_payload(state, &vault, item_id, &payload)?;

    let now = Utc::now();
    let item = Item {
        id: item_id,
        vault_id: vault.id,
        path: normalized_path.clone(),
        name: basename_from_path(&normalized_path),
        type_id: "secret".to_string(),
        tags: None,
        favorite: false,
        payload_enc,
        checksum,
        version: 1,
        row_version: 1,
        device_id,
        sync_status: SyncStatus::Active,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        created_at: now,
        updated_at: now,
    };

    let created = match item_repo.create(&item).await {
        Ok(()) => true,
        Err(err) => {
            tracing::warn!(event = "secret_create_conflict", error = %err);
            let existing = item_repo
                .get_by_vault_path(vault.id, &normalized_path)
                .await
                .map_err(|_| SecretError::Db)?;
            if let Some(existing) = existing {
                if existing.type_id != "secret" || existing.sync_status != SyncStatus::Active {
                    return Err(SecretError::Conflict("path_in_use"));
                }
                let payload = decrypt_secret_payload(state, &vault, &existing)?;
                let requested_policy = resolve_policy_name(state, Some(policy_name.as_str()));
                if payload.policy != requested_policy {
                    return Err(SecretError::PolicyMismatch {
                        existing: payload.policy,
                        requested: requested_policy,
                    });
                }
                let record = SecretRecord {
                    path: existing.path,
                    vault_id: vault.id.to_string(),
                    value: payload.value,
                    policy: payload.policy,
                    meta: payload.meta,
                    version: existing.version,
                };
                return Ok((record, false));
            }
            return Err(SecretError::Db);
        }
    };

    let history_repo = ItemHistoryRepo::new(&state.db);
    let actor = actor_snapshot(state, identity, Some(device_id)).await;
    let history = ItemHistory {
        id: Uuid::now_v7(),
        item_id: item.id,
        payload_enc: item.payload_enc.clone(),
        checksum: item.checksum.clone(),
        version: item.version,
        change_type: ChangeType::Create,
        fields_changed: None,
        changed_by_user_id: identity.user_id,
        changed_by_email: actor.email,
        changed_by_name: actor.name,
        changed_by_device_id: Some(device_id),
        changed_by_device_name: actor.device_name,
        created_at: now,
    };
    let _ = history_repo.create(&history).await;

    let change_repo = ChangeRepo::new(&state.db);
    let change = Change {
        seq: 0,
        vault_id: vault.id,
        item_id: item.id,
        op: ChangeOp::Create,
        version: item.version,
        device_id,
        created_at: now,
    };
    let _ = change_repo.create(&change).await;

    let record = SecretRecord {
        path: item.path,
        vault_id: vault.id.to_string(),
        value,
        policy: policy_name,
        meta: normalized_meta,
        version: item.version,
    };
    Ok((record, created))
}

pub async fn rotate_secret(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    path: &str,
    policy_name: Option<&str>,
    meta: Option<HashMap<String, String>>,
) -> Result<(SecretRecord, i64), SecretError> {
    let device_id = identity
        .device_id
        .ok_or(SecretError::Forbidden("device_required"))?;
    let normalized_path = normalize_secret_path(path)?;
    let resource = format!("vaults/{vault_id}/secrets/{normalized_path}");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "write",
        &resource,
        VaultScope::Items,
    )
    .await?;

    ensure_server_encryption(state, &vault)?;

    let item_repo = ItemRepo::new(&state.db);
    let mut item = match item_repo
        .get_by_vault_path(vault.id, &normalized_path)
        .await
    {
        Ok(Some(item)) => item,
        Ok(None) => return Err(SecretError::NotFound),
        Err(_) => {
            tracing::error!(event = "secret_rotate_failed", "DB error");
            return Err(SecretError::Db);
        }
    };

    if item.type_id != "secret" || item.sync_status != SyncStatus::Active {
        return Err(SecretError::NotFound);
    }

    let (policy_name, policy) = resolve_policy(state, policy_name)?;
    let value = generate_secret(&policy).map_err(SecretError::Internal)?;
    let normalized_meta = normalize_meta(meta);
    let payload = SecretPayload {
        value: value.clone(),
        policy: policy_name.clone(),
        meta: normalized_meta.clone(),
    };

    let (payload_enc, checksum) = encrypt_secret_payload(state, &vault, item.id, &payload)?;
    let previous_version = item.version;

    let history_repo = ItemHistoryRepo::new(&state.db);
    let actor = actor_snapshot(state, identity, Some(device_id)).await;
    let history = ItemHistory {
        id: Uuid::now_v7(),
        item_id: item.id,
        payload_enc: item.payload_enc.clone(),
        checksum: item.checksum.clone(),
        version: item.version,
        change_type: ChangeType::Update,
        fields_changed: None,
        changed_by_user_id: identity.user_id,
        changed_by_email: actor.email,
        changed_by_name: actor.name,
        changed_by_device_id: Some(device_id),
        changed_by_device_name: actor.device_name,
        created_at: Utc::now(),
    };
    let _ = history_repo.create(&history).await;

    item.payload_enc = payload_enc;
    item.checksum = checksum;
    item.version = item.version.saturating_add(1);
    item.device_id = device_id;
    item.updated_at = Utc::now();

    let Ok(affected) = item_repo.update(&item).await else {
        tracing::error!(event = "secret_rotate_failed", "DB error");
        return Err(SecretError::Db);
    };
    if affected == 0 {
        return Err(SecretError::Conflict("row_version_conflict"));
    }

    let change_repo = ChangeRepo::new(&state.db);
    let change = Change {
        seq: 0,
        vault_id: vault.id,
        item_id: item.id,
        op: ChangeOp::Update,
        version: item.version,
        device_id,
        created_at: item.updated_at,
    };
    let _ = change_repo.create(&change).await;

    let record = SecretRecord {
        path: item.path,
        vault_id: vault.id.to_string(),
        value,
        policy: policy_name,
        meta: normalized_meta,
        version: item.version,
    };
    Ok((record, previous_version))
}

fn normalize_secret_path(path: &str) -> Result<String, SecretError> {
    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Err(SecretError::BadRequest("invalid_path"));
    }
    Ok(format!("/{trimmed}"))
}

fn normalize_meta(meta: Option<HashMap<String, String>>) -> Option<HashMap<String, String>> {
    meta.and_then(|map| {
        let filtered: HashMap<String, String> = map
            .into_iter()
            .filter_map(|(k, v)| {
                let key = k.trim().to_string();
                if key.is_empty() {
                    return None;
                }
                Some((key, v))
            })
            .collect();
        if filtered.is_empty() {
            None
        } else {
            Some(filtered)
        }
    })
}

async fn actor_snapshot(
    state: &AppState,
    identity: &Identity,
    device_id: Option<Uuid>,
) -> ActorSnapshot {
    let user_repo = UserRepo::new(&state.db);
    let name = match user_repo.get_by_id(identity.user_id).await {
        Ok(Some(user)) => user.full_name,
        _ => None,
    };
    let device_name = match device_id {
        Some(device_id) => {
            let device_repo = DeviceRepo::new(&state.db);
            match device_repo.get_by_id(device_id).await {
                Ok(Some(device)) => Some(device.name),
                _ => None,
            }
        }
        None => None,
    };
    ActorSnapshot {
        email: identity.email.clone(),
        name,
        device_name,
    }
}

fn resolve_policy_name(state: &AppState, policy_name: Option<&str>) -> String {
    policy_name
        .map(str::to_string)
        .unwrap_or_else(|| state.secret_default_policy.clone())
}

fn resolve_policy(
    state: &AppState,
    policy_name: Option<&str>,
) -> Result<(String, PasswordPolicy), SecretError> {
    let name = resolve_policy_name(state, policy_name);
    let Some(policy) = state.secret_policies.get(&name).cloned() else {
        return Err(SecretError::BadRequest("unknown_policy"));
    };
    policy.validate().map_err(SecretError::BadRequest)?;
    Ok((name, policy))
}

fn ensure_server_encryption(state: &AppState, vault: &Vault) -> Result<(), SecretError> {
    if vault.encryption_type != zann_core::VaultEncryptionType::Server {
        return Err(SecretError::BadRequest("vault_not_server_encrypted"));
    }
    if state.server_master_key.is_none() {
        return Err(SecretError::Internal("smk_missing"));
    }
    Ok(())
}

fn decrypt_secret_payload(
    state: &AppState,
    vault: &Vault,
    item: &Item,
) -> Result<SecretPayload, SecretError> {
    let Some(smk) = state.server_master_key.as_ref() else {
        return Err(SecretError::Internal("smk_missing"));
    };
    let vault_key =
        core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc).map_err(|err| {
            tracing::error!(event = "secret_decrypt_failed", error = %err);
            SecretError::Internal("vault_key_decrypt_failed")
        })?;
    let bytes =
        core_crypto::decrypt_payload_bytes(&vault_key, vault.id, item.id, &item.payload_enc)
            .map_err(|err| {
                tracing::error!(event = "secret_decrypt_failed", error = %err);
                SecretError::Internal("payload_decrypt_failed")
            })?;
    let payload = {
        let _span = tracing::debug_span!(
            "serialize_json",
            op = "secret_payload_decode",
            bytes_len = bytes.len()
        )
        .entered();
        serde_json::from_slice::<SecretPayload>(&bytes)
            .map_err(|_| SecretError::Internal("decode_failed"))?
    };
    Ok(payload)
}

fn encrypt_secret_payload(
    state: &AppState,
    vault: &Vault,
    item_id: Uuid,
    payload: &SecretPayload,
) -> Result<(Vec<u8>, String), SecretError> {
    let Some(smk) = state.server_master_key.as_ref() else {
        return Err(SecretError::Internal("smk_missing"));
    };
    let vault_key =
        core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc).map_err(|err| {
            tracing::error!(event = "secret_encrypt_failed", error = %err);
            SecretError::Internal("vault_key_decrypt_failed")
        })?;
    let payload_bytes = {
        let _span = tracing::debug_span!("serialize_json", op = "secret_payload_encode").entered();
        serde_json::to_vec(payload).map_err(|_| SecretError::Internal("payload_encode_failed"))?
    };
    let payload_enc =
        core_crypto::encrypt_payload_bytes(&vault_key, vault.id, item_id, &payload_bytes).map_err(
            |err| {
                tracing::error!(event = "secret_encrypt_failed", error = %err);
                SecretError::Internal("payload_encrypt_failed")
            },
        )?;
    let checksum = core_crypto::payload_checksum(&payload_enc);
    Ok((payload_enc, checksum))
}

async fn authorize_vault_access(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    action: &str,
    resource: &str,
    scope: VaultScope,
) -> Result<Vault, SecretError> {
    let policies = state.policy_store.get();

    let vault_repo = VaultRepo::new(&state.db);
    let vault = match find_vault(&vault_repo, vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return Err(SecretError::NotFound),
        Err(_) => {
            tracing::error!(event = "vault_access_failed", "DB error");
            return Err(SecretError::Db);
        }
    };

    match policies.evaluate(identity, action, resource) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny => {
            metrics::forbidden_access(resource);
            tracing::warn!(
                event = "forbidden",
                action = action,
                resource = %resource,
                "Access denied"
            );
            return Err(SecretError::ForbiddenNoBody);
        }
        PolicyDecision::NoMatch => {
            match vault_role_allows(state, identity, vault.id, action, scope).await {
                Ok(true) => {}
                Ok(false) => {
                    metrics::forbidden_access(resource);
                    tracing::warn!(
                        event = "forbidden",
                        action = action,
                        resource = %resource,
                        "Access denied"
                    );
                    return Err(SecretError::ForbiddenNoBody);
                }
                Err(_) => {
                    tracing::error!(event = "vault_access_failed", "DB error");
                    return Err(SecretError::Db);
                }
            }
        }
    }

    Ok(vault)
}
