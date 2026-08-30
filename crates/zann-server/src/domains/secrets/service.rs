use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;
use zann_core::api::secrets::SecretVersionSelector;
use zann_core::{Change, ChangeOp, ChangeType, Identity, Item, ItemHistory, SyncStatus, Vault};
use zann_crypto::vault_crypto as core_crypto;
use zann_crypto::{EncryptedPayload, FieldKind, FieldValue};
use zann_db::repo::{
    ChangeRepo, DeviceRepo, ItemHistoryRepo, ItemRepo, ServiceAccountRepo, UserRepo, VaultRepo,
};
use zeroize::Zeroize;

use crate::app::AppState;
use crate::domains::access_control::http::{
    find_vault, scopes_allow_path, vault_role_allows, VaultScope,
};
use crate::domains::access_control::policies::PolicyDecision;
use crate::domains::auth::helpers::build_device;
use crate::domains::errors::ServiceError;
use crate::domains::items::contract::{
    canonical_create_location, next_item_version, validate_typed_payload, ItemContractError,
};
use crate::domains::items::service::{
    basename_from_path, fetch_item_list_page, parse_item_list_cursor, ItemListPage,
    ITEM_HISTORY_LIMIT, ITEM_LIST_DEFAULT_LIMIT, ITEM_LIST_MAX_LIMIT,
};
use crate::domains::secrets::policies::{generate_secret, PasswordPolicy};
use crate::infra::metrics;

pub type SecretError = ServiceError;

const SERVICE_ACCOUNT_DEVICE_NAME: &str = "Service Account";
const SERVICE_ACCOUNT_DEVICE_FINGERPRINT: &str = "service-account";

pub(crate) const SECRET_TYPE_ID: &str = "secret";
pub(crate) const SECRET_VALUE_FIELD: &str = "value";
pub(crate) const SECRET_POLICY_FIELD: &str = "policy";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPayload {
    pub value: String,
    pub policy: String,
    #[serde(default)]
    pub meta: Option<HashMap<String, String>>,
}

impl fmt::Debug for SecretPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretPayload")
            .field("value", &"<redacted>")
            .field("policy", &"<redacted>")
            .field(
                "meta_count",
                &self.meta.as_ref().map(HashMap::len).unwrap_or(0),
            )
            .finish()
    }
}

impl Drop for SecretPayload {
    fn drop(&mut self) {
        wipe_string(&mut self.value);
        wipe_string(&mut self.policy);
        wipe_string_map(&mut self.meta);
    }
}

impl SecretPayload {
    fn into_parts(mut self) -> (String, String, Option<HashMap<String, String>>) {
        (
            std::mem::take(&mut self.value),
            std::mem::take(&mut self.policy),
            self.meta.take(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretPayloadDecodeError {
    InvalidPayload,
    PayloadTooLarge,
}

impl SecretPayloadDecodeError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidPayload => "invalid_secret_payload",
            Self::PayloadTooLarge => "secret_payload_too_large",
        }
    }
}

fn wipe_string(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    bytes.zeroize();
}

fn wipe_string_map(value: &mut Option<HashMap<String, String>>) {
    if let Some(map) = value.as_mut() {
        for (mut key, mut value) in map.drain() {
            wipe_string(&mut key);
            wipe_string(&mut value);
        }
    }
}

#[derive(Clone)]
pub struct SecretRecord {
    pub item_id: String,
    pub path: String,
    pub vault_id: String,
    pub value: String,
    pub policy: String,
    pub meta: Option<HashMap<String, String>>,
    pub version: i64,
}

type SecretRecordParts = (
    String,
    String,
    String,
    String,
    String,
    Option<HashMap<String, String>>,
    i64,
);

impl fmt::Debug for SecretRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRecord")
            .field("item_id", &self.item_id)
            .field("path", &self.path)
            .field("vault_id", &self.vault_id)
            .field("value", &"<redacted>")
            .field("policy", &"<redacted>")
            .field(
                "meta_count",
                &self.meta.as_ref().map(HashMap::len).unwrap_or(0),
            )
            .field("version", &self.version)
            .finish()
    }
}

impl Drop for SecretRecord {
    fn drop(&mut self) {
        wipe_string(&mut self.item_id);
        wipe_string(&mut self.value);
        wipe_string(&mut self.policy);
        wipe_string_map(&mut self.meta);
    }
}

impl SecretRecord {
    pub(crate) fn into_parts(mut self) -> SecretRecordParts {
        (
            std::mem::take(&mut self.item_id),
            std::mem::take(&mut self.path),
            std::mem::take(&mut self.vault_id),
            std::mem::take(&mut self.value),
            std::mem::take(&mut self.policy),
            self.meta.take(),
            self.version,
        )
    }
}

fn secret_record(
    item_id: Uuid,
    path: String,
    vault_id: Uuid,
    payload: SecretPayload,
    version: i64,
) -> SecretRecord {
    let (value, policy, meta) = payload.into_parts();
    SecretRecord {
        item_id: item_id.to_string(),
        path,
        vault_id: vault_id.to_string(),
        value,
        policy,
        meta,
        version,
    }
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
    version: Option<SecretVersionSelector>,
) -> Result<SecretRecord, SecretError> {
    let normalized_path = normalize_secret_path(path)?;
    let resource = format!("vaults/{vault_id}/secrets/{normalized_path}");
    let action = match version {
        Some(SecretVersionSelector::Previous) => "read_previous",
        None => "read",
    };
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        action,
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

    if item.type_id != SECRET_TYPE_ID || item.sync_status != SyncStatus::Active {
        return Err(SecretError::NotFound);
    }

    let (payload, response_version) = match version {
        Some(SecretVersionSelector::Previous) => {
            let previous_version = item
                .version
                .checked_sub(1)
                .filter(|version| *version >= 1)
                .ok_or(SecretError::NotFound)?;
            let history_repo = ItemHistoryRepo::new(&state.db);
            let history = history_repo
                .get_by_item_version(item.id, previous_version)
                .await
                .map_err(|_| SecretError::DbError)?
                .ok_or(SecretError::NotFound)?;
            let retention =
                chrono::Duration::seconds(state.config.rotation.stale_retention_seconds.max(0));
            let expires_at = history
                .created_at
                .checked_add_signed(retention)
                .ok_or(SecretError::Internal("invalid_rotation_retention"))?;
            if Utc::now() > expires_at {
                return Err(SecretError::NotFound);
            }
            (
                decrypt_secret_payload_ciphertext(state, &vault, item.id, &history.payload_enc)?,
                history.version,
            )
        }
        None => (decrypt_secret_payload(state, &vault, &item)?, item.version),
    };

    let usage_tracker = state.usage_tracker.clone();
    let user_id = identity.user_id;
    let device_id = identity.device_id;
    let item_id = item.id;
    tokio::spawn(async move {
        usage_tracker.record_read(item_id, user_id, device_id).await;
    });
    Ok(secret_record(
        item.id,
        external_secret_path(&item.path),
        vault.id,
        payload,
        response_version,
    ))
}

pub(crate) async fn list_secrets(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    prefix: Option<&str>,
    limit: Option<i64>,
    cursor: Option<&str>,
) -> Result<ItemListPage, SecretError> {
    let prefix = normalize_secret_list_prefix(prefix)?;
    let authorization_path = prefix.as_deref().unwrap_or_default();
    let resource = if authorization_path.is_empty() {
        format!("vaults/{vault_id}/secrets")
    } else {
        format!("vaults/{vault_id}/secrets/{authorization_path}")
    };
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "list",
        &resource,
        authorization_path,
        VaultScope::Items,
    )
    .await?;

    ensure_server_encryption(state, &vault)?;
    let cursor = parse_item_list_cursor(cursor)?;
    let limit = limit
        .unwrap_or(ITEM_LIST_DEFAULT_LIMIT)
        .clamp(1, ITEM_LIST_MAX_LIMIT);
    fetch_item_list_page(
        state,
        vault.id,
        prefix.as_deref(),
        Some(SECRET_TYPE_ID),
        cursor,
        limit,
    )
    .await
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
        if item.type_id != SECRET_TYPE_ID || item.sync_status != SyncStatus::Active {
            return Err(SecretError::Conflict("path_in_use"));
        }
        let mut payload = decrypt_secret_payload(state, &vault, &item)?;
        let requested_policy = resolve_policy_name(state, policy_name);
        if payload.policy != requested_policy {
            return Err(SecretError::PolicyMismatch {
                existing: std::mem::take(&mut payload.policy),
                requested: requested_policy,
            });
        }
        let record = secret_record(
            item.id,
            external_secret_path(&item.path),
            vault.id,
            payload,
            item.version,
        );
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
        type_id: SECRET_TYPE_ID.to_string(),
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

    let created = match create_secret_aggregate(state, identity, &item).await {
        Ok(()) => true,
        Err(err) => {
            tracing::warn!(event = "secret_create_conflict", error = %err);
            if !err
                .as_database_error()
                .is_some_and(|database_error| database_error.is_unique_violation())
            {
                return Err(SecretError::DbError);
            }
            let existing = item_repo
                .get_by_vault_path(vault.id, &normalized_path)
                .await
                .map_err(|_| SecretError::DbError)?;
            if let Some(existing) = existing {
                if existing.type_id != SECRET_TYPE_ID || existing.sync_status != SyncStatus::Active
                {
                    return Err(SecretError::Conflict("path_in_use"));
                }
                let mut payload = decrypt_secret_payload(state, &vault, &existing)?;
                let requested_policy = resolve_policy_name(state, Some(policy_name.as_str()));
                if payload.policy != requested_policy {
                    return Err(SecretError::PolicyMismatch {
                        existing: std::mem::take(&mut payload.policy),
                        requested: requested_policy,
                    });
                }
                let record = secret_record(
                    existing.id,
                    external_secret_path(&existing.path),
                    vault.id,
                    payload,
                    existing.version,
                );
                return Ok((record, false));
            }
            return Err(SecretError::DbError);
        }
    };

    let record = SecretRecord {
        item_id: item.id.to_string(),
        path: external_secret_path(&item.path),
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
        if item.type_id != SECRET_TYPE_ID || item.sync_status != SyncStatus::Active {
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
            let record = secret_record(
                item.id,
                external_secret_path(&item.path),
                vault.id,
                payload,
                item.version,
            );
            return Ok((record, false));
        }

        let expected_row_version = item.row_version;
        let (payload_enc, checksum) = encrypt_secret_payload(state, &vault, item.id, &payload)?;
        item.payload_enc = payload_enc;
        item.checksum = checksum;
        item.version = next_item_version(item.version)
            .map_err(|_| SecretError::Conflict("invalid_version"))?;
        item.device_id = device_id;
        item.updated_at = Utc::now();

        update_secret_aggregate(
            state,
            identity,
            expected_row_version,
            &item,
            ChangeType::Update,
        )
        .await?;

        let record = secret_record(
            item.id,
            external_secret_path(&item.path),
            vault.id,
            payload,
            item.version,
        );
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
        type_id: SECRET_TYPE_ID.to_string(),
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

    match create_secret_aggregate(state, identity, &item).await {
        Ok(()) => {}
        Err(err) => {
            tracing::warn!(event = "secret_set_conflict", error = %err);
            if err
                .as_database_error()
                .is_some_and(|database_error| database_error.is_unique_violation())
            {
                // A concurrent SET may carry a different value/policy/meta.
                // The randomized ciphertext cannot prove exact idempotency, so
                // never echo the winner as though this request was applied.
                return Err(SecretError::Conflict("concurrent_create"));
            }
            return Err(SecretError::DbError);
        }
    }

    let record = SecretRecord {
        item_id: item.id.to_string(),
        path: external_secret_path(&item.path),
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

    if item.type_id != SECRET_TYPE_ID || item.sync_status != SyncStatus::Active {
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
    let expected_row_version = item.row_version;

    item.payload_enc = payload_enc;
    item.checksum = checksum;
    item.version =
        next_item_version(item.version).map_err(|_| SecretError::Conflict("invalid_version"))?;
    item.device_id = device_id;
    item.updated_at = Utc::now();

    update_secret_aggregate(
        state,
        identity,
        expected_row_version,
        &item,
        ChangeType::Update,
    )
    .await?;

    let record = SecretRecord {
        item_id: item.id.to_string(),
        path: external_secret_path(&item.path),
        vault_id: vault.id.to_string(),
        value,
        policy: policy_name,
        meta: normalized_meta,
        version: item.version,
    };
    Ok((record, previous_version))
}

async fn create_secret_aggregate(
    state: &AppState,
    identity: &Identity,
    item: &Item,
) -> Result<(), sqlx_core::Error> {
    let actor = actor_snapshot(state, identity, Some(item.device_id)).await;
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
        changed_by_device_id: Some(item.device_id),
        changed_by_device_name: actor.device_name,
        created_at: item.updated_at,
    };
    let change = Change {
        seq: 0,
        vault_id: item.vault_id,
        item_id: item.id,
        op: ChangeOp::Create,
        version: item.version,
        device_id: item.device_id,
        created_at: item.updated_at,
    };
    let item_repo = ItemRepo::new(&state.db);
    let history_repo = ItemHistoryRepo::new(&state.db);
    let change_repo = ChangeRepo::new(&state.db);
    let mut tx = state.db.begin().await?;
    item_repo.create_in(&mut tx, item).await?;
    history_repo.create_in(&mut tx, &history).await?;
    history_repo
        .prune_by_item_in(&mut tx, item.id, ITEM_HISTORY_LIMIT)
        .await?;
    change_repo.create_in(&mut tx, &change).await?;
    tx.commit().await
}

async fn update_secret_aggregate(
    state: &AppState,
    identity: &Identity,
    expected_row_version: i64,
    item: &Item,
    change_type: ChangeType,
) -> Result<(), SecretError> {
    let actor = actor_snapshot(state, identity, Some(item.device_id)).await;
    let item_repo = ItemRepo::new(&state.db);
    let history_repo = ItemHistoryRepo::new(&state.db);
    let change_repo = ChangeRepo::new(&state.db);
    let mut tx = state.db.begin().await.map_err(|err| {
        tracing::error!(event = "secret_mutation_failed", error = %err, "DB error");
        SecretError::DbError
    })?;
    let locked = item_repo
        .get_by_id_for_update_in(&mut tx, item.id)
        .await
        .map_err(|err| {
            tracing::error!(event = "secret_mutation_failed", error = %err, "DB error");
            SecretError::DbError
        })?
        .ok_or(SecretError::NotFound)?;
    if locked.vault_id != item.vault_id || locked.row_version != expected_row_version {
        return Err(SecretError::Conflict("row_version_conflict"));
    }
    if locked.type_id != SECRET_TYPE_ID || locked.sync_status != SyncStatus::Active {
        return Err(SecretError::NotFound);
    }
    let expected_version =
        next_item_version(locked.version).map_err(|_| SecretError::Conflict("invalid_version"))?;
    if item.version != expected_version {
        return Err(SecretError::Conflict("row_version_conflict"));
    }
    let history = ItemHistory {
        id: Uuid::now_v7(),
        item_id: locked.id,
        payload_enc: locked.payload_enc,
        checksum: locked.checksum,
        version: locked.version,
        change_type,
        fields_changed: None,
        changed_by_user_id: identity.user_id,
        changed_by_email: actor.email,
        changed_by_name: actor.name,
        changed_by_device_id: Some(item.device_id),
        changed_by_device_name: actor.device_name,
        created_at: item.updated_at,
    };
    history_repo
        .create_in(&mut tx, &history)
        .await
        .map_err(|err| {
            tracing::error!(event = "secret_history_create_failed", error = %err);
            SecretError::DbError
        })?;
    history_repo
        .prune_by_item_in(&mut tx, item.id, ITEM_HISTORY_LIMIT)
        .await
        .map_err(|err| {
            tracing::error!(event = "secret_history_prune_failed", error = %err);
            SecretError::DbError
        })?;
    let affected = item_repo.update_in(&mut tx, item).await.map_err(|err| {
        tracing::error!(event = "secret_mutation_failed", error = %err, "DB error");
        SecretError::DbError
    })?;
    if affected != 1 {
        return Err(SecretError::Conflict("row_version_conflict"));
    }
    let change = Change {
        seq: 0,
        vault_id: item.vault_id,
        item_id: item.id,
        op: ChangeOp::Update,
        version: item.version,
        device_id: item.device_id,
        created_at: item.updated_at,
    };
    change_repo
        .create_in(&mut tx, &change)
        .await
        .map_err(|err| {
            tracing::error!(event = "secret_change_create_failed", error = %err);
            SecretError::DbError
        })?;
    tx.commit().await.map_err(|err| {
        tracing::error!(event = "secret_mutation_commit_failed", error = %err);
        SecretError::DbError
    })
}

fn normalize_secret_path(path: &str) -> Result<String, SecretError> {
    let storage_path = path.strip_prefix('/').unwrap_or(path);
    canonical_create_location(storage_path, None)
        .map(|(path, _)| path)
        .map_err(|error| SecretError::BadRequest(error.code()))
}

fn normalize_secret_list_prefix(prefix: Option<&str>) -> Result<Option<String>, SecretError> {
    let Some(prefix) = prefix else {
        return Ok(None);
    };
    let prefix = prefix.trim().trim_matches('/');
    if prefix.is_empty() {
        return Ok(None);
    }
    normalize_secret_path(prefix).map(Some)
}

fn external_secret_path(storage_path: &str) -> String {
    format!("/{storage_path}")
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

/// Converts the secrets API representation into the single canonical typed wire shape.
///
/// Secret typed payloads contain exactly `value` (password) and `policy` (text) fields.
/// The API `meta` map occupies `extra`; field-level metadata is deliberately unsupported
/// so that a payload has only one interpretation across the secrets and items APIs.
pub(crate) fn secret_payload_to_typed(payload: &SecretPayload) -> EncryptedPayload {
    let mut typed = EncryptedPayload::new(SECRET_TYPE_ID);
    typed.fields.insert(
        SECRET_VALUE_FIELD.to_string(),
        FieldValue {
            kind: FieldKind::Password,
            value: payload.value.clone(),
            meta: None,
        },
    );
    typed.fields.insert(
        SECRET_POLICY_FIELD.to_string(),
        FieldValue {
            kind: FieldKind::Text,
            value: payload.policy.clone(),
            meta: None,
        },
    );
    typed.extra = payload.meta.clone();
    typed
}

/// Converts a strictly canonical typed secret payload to the secrets API representation.
pub(crate) fn secret_payload_from_typed(
    mut payload: EncryptedPayload,
) -> Result<SecretPayload, SecretPayloadDecodeError> {
    validate_secret_typed_payload(&payload)?;

    let mut value = payload
        .fields
        .remove(SECRET_VALUE_FIELD)
        .ok_or(SecretPayloadDecodeError::InvalidPayload)?;
    let mut policy = payload
        .fields
        .remove(SECRET_POLICY_FIELD)
        .ok_or(SecretPayloadDecodeError::InvalidPayload)?;
    Ok(SecretPayload {
        value: std::mem::take(&mut value.value),
        policy: std::mem::take(&mut policy.value),
        meta: payload.extra.take(),
    })
}

/// Decodes only the canonical typed secret payload.
///
/// Historical encodings are accepted solely by the explicit provisioning migration command;
/// normal secret reads and writes fail closed instead of negotiating payload formats.
pub(crate) fn decode_secret_payload_bytes(
    mut bytes: Vec<u8>,
) -> Result<EncryptedPayload, SecretPayloadDecodeError> {
    let result = decode_secret_payload_slice(&bytes);
    bytes.zeroize();
    result
}

fn decode_secret_payload_slice(bytes: &[u8]) -> Result<EncryptedPayload, SecretPayloadDecodeError> {
    let payload = EncryptedPayload::from_bytes(bytes)
        .map_err(|_| SecretPayloadDecodeError::InvalidPayload)?;
    validate_secret_typed_payload(&payload)?;
    Ok(payload)
}

pub(crate) fn validate_secret_typed_payload(
    payload: &EncryptedPayload,
) -> Result<(), SecretPayloadDecodeError> {
    validate_typed_payload(payload, SECRET_TYPE_ID).map_err(map_item_contract_error)?;
    if payload.fields.len() != 2 {
        return Err(SecretPayloadDecodeError::InvalidPayload);
    }
    let value = payload
        .fields
        .get(SECRET_VALUE_FIELD)
        .ok_or(SecretPayloadDecodeError::InvalidPayload)?;
    let policy = payload
        .fields
        .get(SECRET_POLICY_FIELD)
        .ok_or(SecretPayloadDecodeError::InvalidPayload)?;
    if value.kind != FieldKind::Password
        || value.meta.is_some()
        || policy.kind != FieldKind::Text
        || policy.meta.is_some()
    {
        return Err(SecretPayloadDecodeError::InvalidPayload);
    }
    Ok(())
}

fn map_item_contract_error(error: ItemContractError) -> SecretPayloadDecodeError {
    match error {
        ItemContractError::PayloadTooLarge => SecretPayloadDecodeError::PayloadTooLarge,
        _ => SecretPayloadDecodeError::InvalidPayload,
    }
}

fn decrypt_secret_payload(
    state: &AppState,
    vault: &Vault,
    item: &Item,
) -> Result<SecretPayload, SecretError> {
    decrypt_secret_payload_ciphertext(state, vault, item.id, &item.payload_enc)
}

fn decrypt_secret_payload_ciphertext(
    state: &AppState,
    vault: &Vault,
    item_id: Uuid,
    payload_enc: &[u8],
) -> Result<SecretPayload, SecretError> {
    let Some(smk) = state.server_master_key.as_ref() else {
        return Err(SecretError::Internal("smk_missing"));
    };
    let vault_key =
        core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc).map_err(|err| {
            tracing::error!(event = "secret_decrypt_failed", error = %err);
            SecretError::Internal("vault_key_decrypt_failed")
        })?;
    let bytes = core_crypto::decrypt_payload_bytes(&vault_key, vault.id, item_id, payload_enc)
        .map_err(|err| {
            tracing::error!(event = "secret_decrypt_failed", error = %err);
            SecretError::Internal("payload_decrypt_failed")
        })?;
    let bytes_len = bytes.len();
    let typed = {
        let _span = tracing::debug_span!("serialize_json", op = "secret_payload_decode", bytes_len)
            .entered();
        decode_secret_payload_bytes(bytes)
    };
    let typed = typed.map_err(|error| {
        tracing::error!(event = "secret_decrypt_failed", reason = error.code());
        SecretError::Internal("decode_failed")
    })?;
    secret_payload_from_typed(typed).map_err(|error| {
        tracing::error!(event = "secret_decrypt_failed", reason = error.code());
        SecretError::Internal("decode_failed")
    })
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
    let typed = secret_payload_to_typed(payload);
    validate_secret_typed_payload(&typed).map_err(|error| {
        tracing::warn!(event = "secret_encrypt_rejected", reason = error.code());
        match error {
            SecretPayloadDecodeError::PayloadTooLarge => {
                SecretError::BadRequest("secret_payload_too_large")
            }
            SecretPayloadDecodeError::InvalidPayload => {
                SecretError::Internal("payload_encode_failed")
            }
        }
    })?;
    let payload_enc =
        core_crypto::encrypt_payload(&vault_key, vault.id, item_id, &typed).map_err(|err| {
            tracing::error!(event = "secret_encrypt_failed", error = %err);
            SecretError::Internal("payload_encrypt_failed")
        })?;
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

    if let Some(service_account_id) = identity.service_account_id {
        let scope_allowed =
            service_account_allows_path(state, service_account_id, &vault, action, path).await;
        if !service_account_access_allowed(
            policies.evaluate(identity, action, resource),
            scope_allowed,
        ) {
            return Err(forbidden_access(action, resource));
        }
        return Ok(vault);
    }

    match policies.evaluate(identity, action, resource) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny => return Err(forbidden_access(action, resource)),
        PolicyDecision::NoMatch => {
            match vault_role_allows(state, identity, vault.id, action, scope).await {
                Ok(true) => {}
                Ok(false) => return Err(forbidden_access(action, resource)),
                Err(_) => {
                    tracing::error!(event = "vault_access_failed", "DB error");
                    return Err(SecretError::DbError);
                }
            }
        }
    }

    Ok(vault)
}

fn service_account_access_allowed(decision: PolicyDecision, scope_allowed: bool) -> bool {
    scope_allowed && !matches!(decision, PolicyDecision::Deny)
}

fn forbidden_access(action: &str, resource: &str) -> SecretError {
    metrics::forbidden_access(resource);
    tracing::warn!(
        event = "forbidden",
        action = action,
        resource = %resource,
        "Access denied"
    );
    SecretError::ForbiddenNoBody
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
    scopes_allow_path(&scopes, vault, action, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zann_crypto::FieldMeta;

    fn sample_secret() -> SecretPayload {
        SecretPayload {
            value: "sentinel-value".to_string(),
            policy: "sentinel-policy".to_string(),
            meta: Some(HashMap::from([
                ("owner".to_string(), "sentinel-owner".to_string()),
                ("purpose".to_string(), "sentinel-purpose".to_string()),
            ])),
        }
    }

    #[test]
    fn secret_payload_roundtrips_through_exact_typed_shape() {
        let secret = sample_secret();
        let typed = secret_payload_to_typed(&secret);

        assert_eq!(typed.v, 1);
        assert_eq!(typed.type_id, SECRET_TYPE_ID);
        assert_eq!(typed.fields.len(), 2);
        let value = typed.fields.get(SECRET_VALUE_FIELD).expect("value field");
        assert_eq!(value.kind, FieldKind::Password);
        assert_eq!(value.value, secret.value);
        assert!(value.meta.is_none());
        let policy = typed.fields.get(SECRET_POLICY_FIELD).expect("policy field");
        assert_eq!(policy.kind, FieldKind::Text);
        assert_eq!(policy.value, secret.policy);
        assert!(policy.meta.is_none());
        assert_eq!(typed.extra, secret.meta);

        let decoded = secret_payload_from_typed(typed).expect("canonical typed payload");
        assert_eq!(decoded.value, secret.value);
        assert_eq!(decoded.policy, secret.policy);
        assert_eq!(decoded.meta, secret.meta);
    }

    #[test]
    fn normal_secret_decode_rejects_historical_raw_payload() {
        let legacy = br#"{
            "value": "sentinel-value",
            "policy": "sentinel-policy",
            "meta": {"owner": "sentinel-owner"}
        }"#;

        assert!(matches!(
            decode_secret_payload_bytes(legacy.to_vec()),
            Err(SecretPayloadDecodeError::InvalidPayload)
        ));
    }

    #[test]
    fn typed_secret_decode_rejects_extra_missing_or_ambiguous_fields() {
        let canonical = secret_payload_to_typed(&sample_secret());

        let mut extra_field = canonical.clone();
        extra_field.fields.insert(
            "password".to_string(),
            FieldValue {
                kind: FieldKind::Password,
                value: "ambiguous".to_string(),
                meta: None,
            },
        );
        assert!(matches!(
            decode_secret_payload_bytes(extra_field.to_bytes().expect("serialize")),
            Err(SecretPayloadDecodeError::InvalidPayload)
        ));

        let mut missing_field = canonical.clone();
        missing_field.fields.remove(SECRET_POLICY_FIELD);
        assert!(matches!(
            decode_secret_payload_bytes(missing_field.to_bytes().expect("serialize")),
            Err(SecretPayloadDecodeError::InvalidPayload)
        ));

        let hybrid = br#"{
            "v": 1,
            "typeId": "secret",
            "fields": {},
            "value": "ambiguous",
            "policy": "ambiguous"
        }"#;
        assert!(matches!(
            decode_secret_payload_bytes(hybrid.to_vec()),
            Err(SecretPayloadDecodeError::InvalidPayload)
        ));

        let unknown_typed_member = br#"{
            "v": 1,
            "typeId": "secret",
            "fields": {},
            "sentinel-unknown": "sentinel-value"
        }"#;
        assert!(matches!(
            decode_secret_payload_bytes(unknown_typed_member.to_vec()),
            Err(SecretPayloadDecodeError::InvalidPayload)
        ));
    }

    #[test]
    fn typed_secret_decode_rejects_wrong_kinds_field_meta_type_and_version() {
        let canonical = secret_payload_to_typed(&sample_secret());

        let mut wrong_kind = canonical.clone();
        wrong_kind
            .fields
            .get_mut(SECRET_VALUE_FIELD)
            .expect("value field")
            .kind = FieldKind::Text;
        assert!(matches!(
            secret_payload_from_typed(wrong_kind),
            Err(SecretPayloadDecodeError::InvalidPayload)
        ));

        let mut field_meta = canonical.clone();
        field_meta
            .fields
            .get_mut(SECRET_POLICY_FIELD)
            .expect("policy field")
            .meta = Some(FieldMeta::default());
        assert!(matches!(
            secret_payload_from_typed(field_meta),
            Err(SecretPayloadDecodeError::InvalidPayload)
        ));

        let mut wrong_type = canonical.clone();
        wrong_type.type_id = "login".to_string();
        assert!(matches!(
            secret_payload_from_typed(wrong_type),
            Err(SecretPayloadDecodeError::InvalidPayload)
        ));

        let mut wrong_version = canonical;
        wrong_version.v = 2;
        assert!(matches!(
            secret_payload_from_typed(wrong_version),
            Err(SecretPayloadDecodeError::InvalidPayload)
        ));
    }

    #[test]
    fn typed_secret_decode_applies_plaintext_size_limit() {
        let oversized = SecretPayload {
            value: "x".repeat(300_000),
            policy: "default".to_string(),
            meta: None,
        };
        assert!(matches!(
            secret_payload_from_typed(secret_payload_to_typed(&oversized)),
            Err(SecretPayloadDecodeError::PayloadTooLarge)
        ));
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let secret = sample_secret();
        let rendered = format!("{secret:?}");
        for sentinel in [
            "sentinel-value",
            "sentinel-policy",
            "sentinel-owner",
            "sentinel-purpose",
        ] {
            assert!(!rendered.contains(sentinel));
        }

        let record = SecretRecord {
            item_id: Uuid::nil().to_string(),
            path: "folder/secret".to_string(),
            vault_id: Uuid::nil().to_string(),
            value: "sentinel-value".to_string(),
            policy: "sentinel-policy".to_string(),
            meta: Some(HashMap::from([(
                "sentinel-owner".to_string(),
                "sentinel-purpose".to_string(),
            )])),
            version: 1,
        };
        let rendered = format!("{record:?}");
        for sentinel in [
            "sentinel-value",
            "sentinel-policy",
            "sentinel-owner",
            "sentinel-purpose",
        ] {
            assert!(!rendered.contains(sentinel));
        }
    }

    #[test]
    fn service_account_scope_is_a_mandatory_policy_ceiling() {
        assert!(!service_account_access_allowed(
            PolicyDecision::Allow,
            false
        ));
        assert!(service_account_access_allowed(PolicyDecision::Allow, true));
        assert!(service_account_access_allowed(
            PolicyDecision::NoMatch,
            true
        ));
        assert!(!service_account_access_allowed(PolicyDecision::Deny, true));
    }
}
