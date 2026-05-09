use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use zann_core::{Change, ChangeOp, ChangeType, Identity, Item, ItemHistory, SyncStatus, Vault};
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{
    ChangeRepo, DeviceRepo, ItemHistoryRepo, ItemRepo, ServiceAccountRepo, UserRepo, VaultRepo,
};

use crate::app::AppState;
use crate::domains::access_control::http::{
    find_vault, parse_scope, vault_role_allows, ScopeRule, ScopeTarget, VaultScope,
};
use crate::domains::access_control::policies::PolicyDecision;
use crate::domains::auth::helpers::build_device;
use crate::domains::errors::ServiceError;
use crate::domains::items::service::basename_from_path;
use crate::domains::secrets::policies::{generate_secret, PasswordPolicy};
use crate::infra::metrics;

pub type SecretError = ServiceError;

const SERVICE_ACCOUNT_DEVICE_NAME: &str = "Service Account";
const SERVICE_ACCOUNT_DEVICE_FINGERPRINT: &str = "service-account";

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
        &normalized_path,
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
            return Err(SecretError::DbError);
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
    let device_id = effective_device_id(state, identity).await?;
    let normalized_path = normalize_secret_path(path)?;
    let resource = format!("vaults/{vault_id}/secrets/{normalized_path}");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "write",
        &resource,
        &normalized_path,
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
                .map_err(|_| SecretError::DbError)?;
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
            return Err(SecretError::DbError);
        }
    };

    let history_repo = ItemHistoryRepo::new(&state.db);
    let actor = actor_snapshot(state, identity, identity.device_id).await;
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
        changed_by_device_id: identity.device_id,
        changed_by_device_name: actor.device_name,
        created_at: now,
    };
    if let Err(err) = history_repo.create(&history).await {
        tracing::warn!(event = "secret_history_create_failed", error = %err);
    }

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
    if let Err(err) = change_repo.create(&change).await {
        tracing::warn!(event = "secret_change_create_failed", error = %err);
    }

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

pub async fn set_secret(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    path: &str,
    value: &str,
    policy_name: Option<&str>,
    meta: Option<HashMap<String, String>>,
) -> Result<(SecretRecord, bool), SecretError> {
    let device_id = effective_device_id(state, identity).await?;
    let normalized_path = normalize_secret_path(path)?;
    let resource = format!("vaults/{vault_id}/secrets/{normalized_path}");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "write",
        &resource,
        &normalized_path,
        VaultScope::Items,
    )
    .await?;

    ensure_server_encryption(state, &vault)?;

    let item_repo = ItemRepo::new(&state.db);
    let existing = item_repo
        .get_by_vault_path(vault.id, &normalized_path)
        .await
        .map_err(|_| SecretError::DbError)?;

    if let Some(mut item) = existing {
        if item.type_id != "secret" || item.sync_status != SyncStatus::Active {
            return Err(SecretError::Conflict("path_in_use"));
        }

        let existing_payload = decrypt_secret_payload(state, &vault, &item)?;
        let policy = match policy_name {
            Some(name) => resolve_policy(state, Some(name))?.0,
            None => existing_payload.policy.clone(),
        };
        let normalized_meta = match meta {
            Some(map) => normalize_meta(Some(map)),
            None => existing_payload.meta.clone(),
        };
        let payload = SecretPayload {
            value: value.to_string(),
            policy: policy.clone(),
            meta: normalized_meta.clone(),
        };

        if payload.value == existing_payload.value
            && payload.policy == existing_payload.policy
            && payload.meta == existing_payload.meta
        {
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

        let history_repo = ItemHistoryRepo::new(&state.db);
        let actor = actor_snapshot(state, identity, identity.device_id).await;
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
            changed_by_device_id: identity.device_id,
            changed_by_device_name: actor.device_name,
            created_at: Utc::now(),
        };
        if let Err(err) = history_repo.create(&history).await {
            tracing::warn!(event = "secret_history_create_failed", error = %err);
        }

        let (payload_enc, checksum) = encrypt_secret_payload(state, &vault, item.id, &payload)?;
        item.payload_enc = payload_enc;
        item.checksum = checksum;
        item.version = item.version.saturating_add(1);
        item.device_id = device_id;
        item.updated_at = Utc::now();

        let Ok(affected) = item_repo.update(&item).await else {
            tracing::error!(event = "secret_set_failed", "DB error");
            return Err(SecretError::DbError);
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
        if let Err(err) = change_repo.create(&change).await {
            tracing::warn!(event = "secret_change_create_failed", error = %err);
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

    let (policy, _policy_config) = resolve_policy(state, policy_name)?;
    let normalized_meta = normalize_meta(meta);
    let payload = SecretPayload {
        value: value.to_string(),
        policy: policy.clone(),
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

    match item_repo.create(&item).await {
        Ok(()) => {}
        Err(err) => {
            tracing::warn!(event = "secret_set_conflict", error = %err);
            let existing = item_repo
                .get_by_vault_path(vault.id, &normalized_path)
                .await
                .map_err(|_| SecretError::DbError)?;
            if let Some(existing) = existing {
                if existing.type_id != "secret" || existing.sync_status != SyncStatus::Active {
                    return Err(SecretError::Conflict("path_in_use"));
                }
                let payload = decrypt_secret_payload(state, &vault, &existing)?;
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
            return Err(SecretError::DbError);
        }
    }

    let history_repo = ItemHistoryRepo::new(&state.db);
    let actor = actor_snapshot(state, identity, identity.device_id).await;
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
        changed_by_device_id: identity.device_id,
        changed_by_device_name: actor.device_name,
        created_at: now,
    };
    if let Err(err) = history_repo.create(&history).await {
        tracing::warn!(event = "secret_history_create_failed", error = %err);
    }

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
    if let Err(err) = change_repo.create(&change).await {
        tracing::warn!(event = "secret_change_create_failed", error = %err);
    }

    let record = SecretRecord {
        path: item.path,
        vault_id: vault.id.to_string(),
        value: value.to_string(),
        policy,
        meta: normalized_meta,
        version: item.version,
    };
    Ok((record, true))
}

pub async fn rotate_secret(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    path: &str,
    policy_name: Option<&str>,
    meta: Option<HashMap<String, String>>,
) -> Result<(SecretRecord, i64), SecretError> {
    let device_id = effective_device_id(state, identity).await?;
    let normalized_path = normalize_secret_path(path)?;
    let resource = format!("vaults/{vault_id}/secrets/{normalized_path}");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "write",
        &resource,
        &normalized_path,
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
            return Err(SecretError::DbError);
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
    let actor = actor_snapshot(state, identity, identity.device_id).await;
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
        changed_by_device_id: identity.device_id,
        changed_by_device_name: actor.device_name,
        created_at: Utc::now(),
    };
    if let Err(err) = history_repo.create(&history).await {
        tracing::warn!(event = "secret_history_create_failed", error = %err);
    }

    item.payload_enc = payload_enc;
    item.checksum = checksum;
    item.version = item.version.saturating_add(1);
    item.device_id = device_id;
    item.updated_at = Utc::now();

    let Ok(affected) = item_repo.update(&item).await else {
        tracing::error!(event = "secret_rotate_failed", "DB error");
        return Err(SecretError::DbError);
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
    if let Err(err) = change_repo.create(&change).await {
        tracing::warn!(event = "secret_change_create_failed", error = %err);
    }

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

async fn effective_device_id(state: &AppState, identity: &Identity) -> Result<Uuid, SecretError> {
    if let Some(device_id) = identity.device_id {
        return Ok(device_id);
    }

    if identity.service_account_id.is_none() {
        return Err(SecretError::DeviceRequired);
    }

    ensure_service_account_device(state, identity.user_id).await
}

async fn ensure_service_account_device(
    state: &AppState,
    user_id: Uuid,
) -> Result<Uuid, SecretError> {
    let repo = DeviceRepo::new(&state.db);
    let existing = repo
        .list_by_user(user_id, 1024, 0, "desc")
        .await
        .map_err(|_| SecretError::DbError)?
        .into_iter()
        .find(|device| {
            device.revoked_at.is_none() && device.fingerprint == SERVICE_ACCOUNT_DEVICE_FINGERPRINT
        });
    if let Some(device) = existing {
        return Ok(device.id);
    }

    let now = Utc::now();
    let device = build_device(
        user_id,
        Some(SERVICE_ACCOUNT_DEVICE_NAME.to_string()),
        Some("server".to_string()),
        Some(SERVICE_ACCOUNT_DEVICE_FINGERPRINT.to_string()),
        Some("server".to_string()),
        None,
        None,
        SERVICE_ACCOUNT_DEVICE_NAME,
        "server",
        now,
    );
    repo.create(&device).await.map_err(|err| {
        tracing::error!(event = "service_account_device_create_failed", error = %err);
        SecretError::DbError
    })?;
    Ok(device.id)
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
    path: &str,
    scope: VaultScope,
) -> Result<Vault, SecretError> {
    let policies = state.policy_store.get();

    let vault_repo = VaultRepo::new(&state.db);
    let vault = match find_vault(&vault_repo, vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return Err(SecretError::NotFound),
        Err(_) => {
            tracing::error!(event = "vault_access_failed", "DB error");
            return Err(SecretError::DbError);
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
            if let Some(service_account_id) = identity.service_account_id {
                if service_account_allows_path(state, service_account_id, &vault, action, path)
                    .await
                {
                    return Ok(vault);
                }
                metrics::forbidden_access(resource);
                tracing::warn!(
                    event = "forbidden",
                    action = action,
                    resource = %resource,
                    "Access denied"
                );
                return Err(SecretError::ForbiddenNoBody);
            }
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
                    return Err(SecretError::DbError);
                }
            }
        }
    }

    Ok(vault)
}

async fn service_account_scopes(state: &AppState, service_account_id: Uuid) -> Option<Vec<String>> {
    let repo = ServiceAccountRepo::new(&state.db);
    repo.get_by_id(service_account_id)
        .await
        .ok()
        .flatten()
        .map(|account| account.scopes.0)
}

async fn service_account_allows_path(
    state: &AppState,
    service_account_id: Uuid,
    vault: &Vault,
    action: &str,
    path: &str,
) -> bool {
    let Some(scopes) = service_account_scopes(state, service_account_id).await else {
        return false;
    };
    scopes.iter().any(|scope| {
        let Some(rule) = parse_scope(scope) else {
            return false;
        };
        scope_allows_action(&rule.permission, action) && scope_matches_path(&rule, vault, path)
    })
}

fn scope_allows_action(permission: &str, action: &str) -> bool {
    match action {
        "read" | "list" => permission == "read",
        _ => permission == action,
    }
}

fn scope_matches_path(rule: &ScopeRule, vault: &Vault, path: &str) -> bool {
    if !vault_matches_scope(vault, &rule.target) {
        return false;
    }
    if let Some(prefix) = rule.prefix.as_deref() {
        return prefix_matches_path(prefix, path);
    }
    true
}

fn vault_matches_scope(vault: &Vault, target: &ScopeTarget) -> bool {
    match target {
        ScopeTarget::Vault(scope) => vault.slug == *scope || vault.id.to_string() == *scope,
        ScopeTarget::Tag(tag) => vault
            .tags
            .as_ref()
            .is_some_and(|tags| tags.0.iter().any(|value| value == tag)),
        ScopeTarget::Pattern(pattern) => matches_pattern(pattern, &vault.slug),
    }
}

fn prefix_matches_path(prefix: &str, path: &str) -> bool {
    let prefix = prefix.trim_matches('/');
    let path = path.trim_matches('/');
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }

    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|part| !part.is_empty()).collect();

    if parts.is_empty() {
        return true;
    }

    let mut index = 0;
    for (i, part) in parts.iter().enumerate() {
        if let Some(pos) = value[index..].find(part) {
            if i == 0 && !starts_with_wildcard && pos != 0 {
                return false;
            }
            index += pos + part.len();
        } else {
            return false;
        }
    }

    if !ends_with_wildcard {
        if let Some(last) = parts.last() {
            return value.ends_with(last);
        }
    }

    true
}
