use chrono::Utc;
use serde_json::Value as JsonValue;
use sqlx_core::types::Json as SqlxJson;
use uuid::Uuid;
use zann_core::crypto::{decrypt_blob, encrypt_blob, EncryptedBlob};
use zann_core::vault_crypto as core_crypto;
use zann_core::{
    Attachment, Change, ChangeOp, ChangeType, FieldsChanged, Identity, Item, ItemHistory,
    SyncStatus, Vault, VaultEncryptionType,
};
use zann_db::repo::{
    AttachmentRepo, ChangeRepo, DeviceRepo, ItemHistoryRepo, ItemRepo, UserRepo, VaultRepo,
};

use crate::app::AppState;
use crate::domains::access_control::http::{find_vault, vault_role_allows, VaultScope};
use crate::domains::access_control::policies::PolicyDecision;
use crate::infra::metrics;

pub const ITEM_HISTORY_LIMIT: i64 = 5;
const MAX_CIPHERTEXT_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub enum ItemsError {
    ForbiddenNoBody,
    Forbidden(&'static str),
    NotFound,
    BadRequest(&'static str),
    Conflict(&'static str),
    PayloadTooLarge(&'static str),
    Db,
    Internal(&'static str),
}

pub struct CreateItemCommand {
    pub path: String,
    pub type_id: String,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
    pub payload_enc: Option<Vec<u8>>,
    pub payload: Option<JsonValue>,
    pub checksum: Option<String>,
    pub version: Option<i64>,
    pub fields_changed: Option<FieldsChanged>,
}

pub struct UpdateItemCommand {
    pub path: Option<String>,
    pub name: Option<String>,
    pub type_id: Option<String>,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
    pub payload_enc: Option<Vec<u8>>,
    pub payload: Option<JsonValue>,
    pub checksum: Option<String>,
    pub version: Option<i64>,
    pub base_version: Option<i64>,
    pub fields_changed: Option<FieldsChanged>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRepresentation {
    Plain,
    Opaque,
}

impl FileRepresentation {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "plain" => Ok(Self::Plain),
            "opaque" => Ok(Self::Opaque),
            _ => Err("representation_invalid"),
        }
    }
}

pub struct FileUploadResult {
    pub file_id: Uuid,
}

pub struct FileDownloadResult {
    pub bytes: Vec<u8>,
}

struct ActorSnapshot {
    email: String,
    name: Option<String>,
    device_name: Option<String>,
}

pub async fn list_items(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
) -> Result<Vec<Item>, ItemsError> {
    let resource = format!("vaults/{vault_id}/items");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "list",
        &resource,
        VaultScope::Items,
    )
    .await?;

    let item_repo = ItemRepo::new(&state.db);
    let Ok(items) = item_repo.list_by_vault(vault.id, false).await else {
        tracing::error!(event = "items_list_failed", "DB error");
        return Err(ItemsError::Db);
    };

    tracing::info!(
        event = "items_listed",
        count = items.len(),
        "Item list returned"
    );
    Ok(items)
}

pub async fn get_item(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
) -> Result<Item, ItemsError> {
    let resource = format!("vaults/{vault_id}/items/{item_id}");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "read",
        &resource,
        VaultScope::Items,
    )
    .await?;

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_get_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };

    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }

    tracing::info!(event = "item_fetched", item_id = %item_id, "Item fetched");
    Ok(item)
}

pub async fn upload_item_file(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
    representation: FileRepresentation,
    file_id: Uuid,
    bytes: Vec<u8>,
    filename: Option<String>,
    mime: Option<String>,
) -> Result<FileUploadResult, ItemsError> {
    let resource = format!("vaults/{vault_id}/items/{item_id}/file");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "write",
        &resource,
        VaultScope::Items,
    )
    .await?;

    if vault.encryption_type == VaultEncryptionType::Client
        && representation != FileRepresentation::Opaque
    {
        return Err(ItemsError::Forbidden("representation_not_allowed"));
    }

    if bytes.len() > MAX_CIPHERTEXT_BYTES {
        return Err(ItemsError::PayloadTooLarge("file_too_large"));
    }

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_get_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };
    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }
    if item.type_id != "file_secret" {
        return Err(ItemsError::BadRequest("item_type_not_supported"));
    }
    let attachment_repo = AttachmentRepo::new(&state.db);
    match attachment_repo.get_by_id(file_id).await {
        Ok(Some(existing)) => {
            if existing.item_id != item_id {
                return Err(ItemsError::Conflict("file_id_conflict"));
            }
            return Ok(FileUploadResult {
                file_id: existing.id,
            });
        }
        Ok(None) => {}
        Err(_) => {
            tracing::error!(event = "attachment_lookup_failed", "DB error");
            return Err(ItemsError::Db);
        }
    }
    if vault.encryption_type == VaultEncryptionType::Server {
        let payload_bytes = decrypt_shared_payload_bytes(state, &vault, &item)
            .map_err(|_| ItemsError::BadRequest("invalid_payload"))?;
        let payload: JsonValue = {
            let _span = tracing::debug_span!(
                "serialize_json",
                op = "item_payload_decode",
                bytes_len = payload_bytes.len()
            )
            .entered();
            serde_json::from_slice(&payload_bytes)
                .map_err(|_| ItemsError::BadRequest("invalid_payload"))?
        };
        let extra = payload.get("extra").and_then(|value| value.as_object());
        let upload_state = extra
            .and_then(|map| map.get("upload_state"))
            .and_then(|value| value.as_str());
        if upload_state != Some("pending") {
            return Err(ItemsError::BadRequest("upload_state_invalid"));
        }
        let expected_file_id = extra
            .and_then(|map| map.get("file_id"))
            .and_then(|value| value.as_str())
            .ok_or(ItemsError::BadRequest("file_id_missing"))?;
        if expected_file_id != file_id.to_string() {
            return Err(ItemsError::Conflict("file_id_mismatch"));
        }
    }

    let (content_enc, checksum, enc_mode) = if vault.encryption_type == VaultEncryptionType::Server
    {
        if representation == FileRepresentation::Plain {
            let Some(smk) = state.server_master_key.as_ref() else {
                tracing::error!(event = "file_upload_failed", "SMK not configured");
                return Err(ItemsError::Internal("smk_missing"));
            };
            let vault_key =
                match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
                    Ok(key) => key,
                    Err(err) => {
                        tracing::error!(
                            event = "file_upload_failed",
                            error = %err,
                            "Key decrypt failed"
                        );
                        return Err(ItemsError::Internal(err.as_code()));
                    }
                };
            let aad = file_aad(vault.id, item_id, file_id, representation);
            let blob = encrypt_blob(&vault_key, &bytes, &aad).map_err(|_| {
                tracing::error!(event = "file_upload_failed", "Encryption failed");
                ItemsError::Internal("file_encrypt_failed")
            })?;
            let content_enc = blob.to_bytes();
            let checksum = core_crypto::payload_checksum(&content_enc);
            (content_enc, checksum, "plain".to_string())
        } else {
            let checksum = core_crypto::payload_checksum(&bytes);
            (bytes, checksum, "opaque".to_string())
        }
    } else {
        let checksum = core_crypto::payload_checksum(&bytes);
        (bytes, checksum, "opaque".to_string())
    };

    let attachment = Attachment {
        id: file_id,
        item_id,
        filename: filename.clone().unwrap_or_else(|| "file".to_string()),
        size: content_enc.len() as i64,
        mime_type: mime
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string()),
        enc_mode,
        content_enc,
        checksum,
        storage_url: None,
        created_at: Utc::now(),
        deleted_at: None,
    };

    if attachment_repo.create(&attachment).await.is_err() {
        tracing::error!(event = "attachment_create_failed", "DB error");
        return Err(ItemsError::Db);
    }

    if vault.encryption_type == VaultEncryptionType::Server {
        if let Err(err) = update_file_upload_state(
            state,
            identity,
            vault_id,
            item_id,
            file_id,
            attachment.filename.clone(),
            attachment.mime_type.clone(),
            attachment.size,
            attachment.checksum.clone(),
        )
        .await
        {
            tracing::warn!(
                event = "file_upload_state_update_failed",
                error = ?err,
                item_id = %item_id,
                "Failed to update upload state"
            );
        }
    }

    Ok(FileUploadResult { file_id })
}

pub async fn download_item_file(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
    representation: FileRepresentation,
) -> Result<FileDownloadResult, ItemsError> {
    let resource = format!("vaults/{vault_id}/items/{item_id}/file");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "read",
        &resource,
        VaultScope::Items,
    )
    .await?;

    if vault.encryption_type == VaultEncryptionType::Client
        && representation != FileRepresentation::Opaque
    {
        return Err(ItemsError::Forbidden("representation_not_allowed"));
    }

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_get_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };
    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }
    if item.type_id != "file_secret" {
        return Err(ItemsError::BadRequest("item_type_not_supported"));
    }

    let attachment_repo = AttachmentRepo::new(&state.db);
    let mut attachments = match attachment_repo.list_by_item(item_id).await {
        Ok(attachments) => attachments,
        Err(_) => {
            tracing::error!(event = "attachment_list_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };
    let mut attachment = None;
    if vault.encryption_type == VaultEncryptionType::Server {
        if let Ok(payload_bytes) = decrypt_shared_payload_bytes(state, &vault, &item) {
            if let Ok(payload) = {
                let _span = tracing::debug_span!(
                    "serialize_json",
                    op = "item_payload_decode",
                    bytes_len = payload_bytes.len()
                )
                .entered();
                serde_json::from_slice::<JsonValue>(&payload_bytes)
            } {
                let file_id = payload
                    .get("extra")
                    .and_then(|value| value.as_object())
                    .and_then(|map| map.get("file_id"))
                    .and_then(|value| value.as_str());
                if let Some(file_id) = file_id {
                    if let Ok(file_uuid) = Uuid::parse_str(file_id) {
                        if let Some(idx) =
                            attachments.iter().position(|entry| entry.id == file_uuid)
                        {
                            attachment = Some(attachments.swap_remove(idx));
                        }
                    }
                }
            }
        }
    }
    let attachment =
        attachment.or_else(|| attachments.into_iter().max_by_key(|entry| entry.created_at));
    let Some(attachment) = attachment else {
        return Err(ItemsError::NotFound);
    };

    if representation == FileRepresentation::Opaque {
        return Ok(FileDownloadResult {
            bytes: attachment.content_enc,
        });
    }

    if vault.encryption_type == VaultEncryptionType::Server && attachment.enc_mode == "plain" {
        let Some(smk) = state.server_master_key.as_ref() else {
            tracing::error!(event = "file_download_failed", "SMK not configured");
            return Err(ItemsError::Internal("smk_missing"));
        };
        let vault_key = match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
            Ok(key) => key,
            Err(err) => {
                tracing::error!(event = "file_download_failed", error = %err, "Key decrypt failed");
                return Err(ItemsError::Internal(err.as_code()));
            }
        };
        let aad = file_aad(vault.id, item_id, attachment.id, representation);
        let blob = EncryptedBlob::from_bytes(&attachment.content_enc)
            .map_err(|_| ItemsError::Internal("invalid_blob"))?;
        let bytes = decrypt_blob(&vault_key, &blob, &aad)
            .map_err(|_| ItemsError::Internal("file_decrypt_failed"))?;
        return Ok(FileDownloadResult { bytes });
    }

    Err(ItemsError::Conflict("representation_not_available"))
}

pub async fn create_item(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    command: CreateItemCommand,
) -> Result<Item, ItemsError> {
    let resource = format!("vaults/{vault_id}/items");

    let device_id = match identity.device_id {
        Some(device_id) => device_id,
        None => return Err(ItemsError::Forbidden("device_required")),
    };

    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "write",
        &resource,
        VaultScope::Items,
    )
    .await?;

    let path = command.path.trim();
    let type_id = command.type_id.trim();
    if path.is_empty() || type_id.is_empty() {
        return Err(ItemsError::BadRequest("invalid_item"));
    }
    let name = basename_from_path(path);
    let type_id = type_id.to_string();

    let tags = command
        .tags
        .map(|tags| tags.into_iter().filter(|t| !t.trim().is_empty()).collect());
    let tags = tags.filter(|tags: &Vec<String>| !tags.is_empty());

    let item_id = Uuid::now_v7();

    let (payload_enc, checksum) = if vault.encryption_type == VaultEncryptionType::Server {
        let Some(plaintext_payload) = command.payload else {
            return Err(ItemsError::BadRequest("payload_required"));
        };
        let payload_bytes = {
            let _span =
                tracing::debug_span!("serialize_json", op = "item_payload_encode").entered();
            serde_json::to_vec(&plaintext_payload)
        };
        let payload_bytes = match payload_bytes {
            Ok(bytes) => bytes,
            Err(_) => return Err(ItemsError::BadRequest("invalid_payload")),
        };
        let Some(smk) = state.server_master_key.as_ref() else {
            tracing::error!(event = "item_create_failed", "SMK not configured");
            return Err(ItemsError::Internal("smk_missing"));
        };
        let vault_key = match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
            Ok(key) => key,
            Err(err) => {
                tracing::error!(event = "item_create_failed", error = %err, "Key decrypt failed");
                return Err(ItemsError::Internal(err.as_code()));
            }
        };
        let payload_enc =
            match core_crypto::encrypt_payload_bytes(&vault_key, vault.id, item_id, &payload_bytes)
            {
                Ok(enc) => enc,
                Err(err) => {
                    tracing::error!(
                        event = "item_create_failed",
                        error = %err,
                        "Encryption failed"
                    );
                    return Err(ItemsError::Internal(err.as_code()));
                }
            };
        let checksum = core_crypto::payload_checksum(&payload_enc);
        (payload_enc, checksum)
    } else {
        let Some(enc) = command.payload_enc else {
            return Err(ItemsError::BadRequest("payload_enc_required"));
        };
        let checksum = command.checksum.as_deref().unwrap_or("").trim();
        if checksum.is_empty() {
            return Err(ItemsError::BadRequest("checksum_required"));
        }
        (enc, checksum.to_string())
    };

    let now = Utc::now();
    let item = Item {
        id: item_id,
        vault_id: vault.id,
        path: path.to_string(),
        name,
        type_id: type_id.to_string(),
        tags: tags.map(SqlxJson),
        favorite: command.favorite.unwrap_or(false),
        payload_enc,
        checksum,
        version: command.version.unwrap_or(1),
        row_version: 1,
        device_id,
        sync_status: SyncStatus::Active,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        created_at: now,
        updated_at: now,
    };

    let item_repo = ItemRepo::new(&state.db);
    if let Err(err) = item_repo.create(&item).await {
        tracing::error!(event = "item_create_failed", error = %err, "DB error");
        return Err(ItemsError::Db);
    }

    let history_repo = ItemHistoryRepo::new(&state.db);
    let actor = actor_snapshot(state, identity, Some(device_id)).await;
    let history = ItemHistory {
        id: Uuid::now_v7(),
        item_id: item.id,
        payload_enc: item.payload_enc.clone(),
        checksum: item.checksum.clone(),
        version: item.version,
        change_type: ChangeType::Create,
        fields_changed: command.fields_changed.map(SqlxJson),
        changed_by_user_id: identity.user_id,
        changed_by_email: actor.email,
        changed_by_name: actor.name,
        changed_by_device_id: Some(device_id),
        changed_by_device_name: actor.device_name,
        created_at: now,
    };
    if let Err(err) = history_repo.create(&history).await {
        tracing::error!(
            event = "item_history_create_failed",
            error = %err,
            item_id = %item.id,
            "Failed to create item history"
        );
    }
    if let Err(err) = history_repo
        .prune_by_item(item.id, ITEM_HISTORY_LIMIT)
        .await
    {
        tracing::error!(
            event = "item_history_prune_failed",
            error = %err,
            item_id = %item.id,
            "Failed to prune item history"
        );
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
        tracing::error!(
            event = "item_change_create_failed",
            error = %err,
            item_id = %item.id,
            "Failed to create change entry"
        );
    }

    tracing::info!(event = "item_created", item_id = %item.id, "Item created");
    Ok(item)
}

pub async fn update_item(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
    command: UpdateItemCommand,
) -> Result<Item, ItemsError> {
    let resource = format!("vaults/{vault_id}/items/{item_id}");

    let device_id = match identity.device_id {
        Some(device_id) => device_id,
        None => return Err(ItemsError::Forbidden("device_required")),
    };

    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "write",
        &resource,
        VaultScope::Items,
    )
    .await?;

    let item_repo = ItemRepo::new(&state.db);
    let mut item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_update_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };

    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }

    if let Some(base_version) = command.base_version {
        if base_version != item.version {
            return Err(ItemsError::Conflict("version_conflict"));
        }
    }

    let previous_payload = item.payload_enc.clone();
    let previous_checksum = item.checksum.clone();
    let previous_version = item.version;
    let mut updated = false;
    let mut payload_changed = false;
    if let Some(path) = command.path.as_deref() {
        let path = path.trim();
        if path.is_empty() {
            return Err(ItemsError::BadRequest("invalid_path"));
        }
        if path != item.path {
            item.path = path.to_string();
            updated = true;
        }
    }
    if let Some(name) = command.name.as_deref() {
        let name = name.trim();
        if name.is_empty() {
            return Err(ItemsError::BadRequest("invalid_name"));
        }
        let next_path = replace_basename(&item.path, &basename_from_path(name));
        if next_path != item.path {
            item.path = next_path;
            updated = true;
        }
    }
    if updated {
        let normalized = basename_from_path(&item.path);
        if item.name != normalized {
            item.name = normalized;
        }
    }
    if let Some(type_id) = command.type_id.as_deref() {
        let type_id = type_id.trim();
        if type_id.is_empty() {
            return Err(ItemsError::BadRequest("invalid_type"));
        }
        if type_id != item.type_id {
            item.type_id = type_id.to_string();
            updated = true;
        }
    }
    if let Some(tags) = command.tags {
        let tags: Vec<String> = tags.into_iter().filter(|t| !t.trim().is_empty()).collect();
        let tags = if tags.is_empty() { None } else { Some(tags) };
        if item.tags.as_ref().map(|t| t.0.clone()) != tags {
            item.tags = tags.map(SqlxJson);
            updated = true;
        }
    }
    if let Some(favorite) = command.favorite {
        if favorite != item.favorite {
            item.favorite = favorite;
            updated = true;
        }
    }
    if let Some(plaintext_payload) = command.payload {
        if vault.encryption_type != VaultEncryptionType::Server {
            return Err(ItemsError::BadRequest("plaintext_not_allowed"));
        }
        let payload_bytes = {
            let _span =
                tracing::debug_span!("serialize_json", op = "item_payload_encode").entered();
            serde_json::to_vec(&plaintext_payload)
        };
        let payload_bytes = match payload_bytes {
            Ok(bytes) => bytes,
            Err(_) => return Err(ItemsError::BadRequest("invalid_payload")),
        };
        let Some(smk) = state.server_master_key.as_ref() else {
            tracing::error!(event = "item_update_failed", "SMK not configured");
            return Err(ItemsError::Internal("smk_missing"));
        };
        let vault_key = match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
            Ok(key) => key,
            Err(err) => {
                tracing::error!(event = "item_update_failed", error = %err, "Key decrypt failed");
                return Err(ItemsError::Internal(err.as_code()));
            }
        };
        let payload_enc =
            match core_crypto::encrypt_payload_bytes(&vault_key, vault.id, item.id, &payload_bytes)
            {
                Ok(enc) => enc,
                Err(err) => {
                    tracing::error!(
                        event = "item_update_failed",
                        error = %err,
                        "Encryption failed"
                    );
                    return Err(ItemsError::Internal(err.as_code()));
                }
            };
        item.payload_enc = payload_enc;
        item.checksum = core_crypto::payload_checksum(&item.payload_enc);
        updated = true;
        payload_changed = item.checksum != previous_checksum;
    } else if let Some(payload_enc) = command.payload_enc {
        let checksum = command.checksum.as_deref().unwrap_or("").trim();
        if checksum.is_empty() {
            return Err(ItemsError::BadRequest("checksum_required"));
        }
        item.payload_enc = payload_enc;
        item.checksum = checksum.to_string();
        updated = true;
        payload_changed = item.checksum != previous_checksum;
    } else if command.checksum.is_some() {
        return Err(ItemsError::BadRequest("checksum_without_payload"));
    }

    if !updated {
        return Err(ItemsError::BadRequest("no_changes"));
    }

    if payload_changed {
        let history_repo = ItemHistoryRepo::new(&state.db);
        let actor = actor_snapshot(state, identity, Some(device_id)).await;
        let history = ItemHistory {
            id: Uuid::now_v7(),
            item_id: item.id,
            payload_enc: previous_payload,
            checksum: previous_checksum,
            version: previous_version,
            change_type: ChangeType::Update,
            fields_changed: command.fields_changed.map(SqlxJson),
            changed_by_user_id: identity.user_id,
            changed_by_email: actor.email,
            changed_by_name: actor.name,
            changed_by_device_id: Some(device_id),
            changed_by_device_name: actor.device_name,
            created_at: Utc::now(),
        };
        if let Err(err) = history_repo.create(&history).await {
            tracing::error!(
                event = "item_history_create_failed",
                error = %err,
                item_id = %item.id,
                "Failed to create item history"
            );
        }
        if let Err(err) = history_repo
            .prune_by_item(item.id, ITEM_HISTORY_LIMIT)
            .await
        {
            tracing::error!(
                event = "item_history_prune_failed",
                error = %err,
                item_id = %item.id,
                "Failed to prune item history"
            );
        }
    }

    item.version = command.version.unwrap_or(item.version + 1);
    item.device_id = device_id;
    item.updated_at = Utc::now();

    let Ok(affected) = item_repo.update(&item).await else {
        tracing::error!(event = "item_update_failed", "DB error");
        return Err(ItemsError::Db);
    };
    if affected == 0 {
        return Err(ItemsError::Conflict("row_version_conflict"));
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
        tracing::error!(
            event = "item_change_create_failed",
            error = %err,
            item_id = %item.id,
            "Failed to create change entry"
        );
    }

    tracing::info!(event = "item_updated", item_id = %item_id, "Item updated");
    Ok(item)
}

pub async fn delete_item(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
) -> Result<(), ItemsError> {
    let resource = format!("vaults/{vault_id}/items/{item_id}");

    let device_id = match identity.device_id {
        Some(device_id) => device_id,
        None => return Err(ItemsError::Forbidden("device_required")),
    };

    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "write",
        &resource,
        VaultScope::Items,
    )
    .await?;

    let item_repo = ItemRepo::new(&state.db);
    let mut item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_delete_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };

    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }

    let now = Utc::now();
    let history_repo = ItemHistoryRepo::new(&state.db);
    let actor = actor_snapshot(state, identity, Some(device_id)).await;
    let history = ItemHistory {
        id: Uuid::now_v7(),
        item_id: item.id,
        payload_enc: item.payload_enc.clone(),
        checksum: item.checksum.clone(),
        version: item.version,
        change_type: ChangeType::Delete,
        fields_changed: None,
        changed_by_user_id: identity.user_id,
        changed_by_email: actor.email,
        changed_by_name: actor.name,
        changed_by_device_id: Some(device_id),
        changed_by_device_name: actor.device_name,
        created_at: now,
    };
    if let Err(err) = history_repo.create(&history).await {
        tracing::error!(
            event = "item_history_create_failed",
            error = %err,
            item_id = %item.id,
            "Failed to create item history"
        );
    }
    if let Err(err) = history_repo
        .prune_by_item(item.id, ITEM_HISTORY_LIMIT)
        .await
    {
        tracing::error!(
            event = "item_history_prune_failed",
            error = %err,
            item_id = %item.id,
            "Failed to prune item history"
        );
    }

    item.deleted_at = Some(now);
    item.deleted_by_user_id = Some(identity.user_id);
    item.deleted_by_device_id = Some(device_id);
    item.sync_status = SyncStatus::Tombstone;
    item.version += 1;
    item.device_id = device_id;
    item.updated_at = now;

    let attachment_repo = AttachmentRepo::new(&state.db);
    if let Err(err) = attachment_repo.mark_deleted_by_item(item.id, now).await {
        tracing::error!(
            event = "item_attachment_mark_deleted_failed",
            error = %err,
            item_id = %item.id,
            "Failed to mark attachments deleted"
        );
    }
    let grace_days = state.config.server.attachments_gc_grace_days.max(0);
    let cutoff = now - chrono::Duration::days(grace_days);
    if let Err(err) = attachment_repo.purge_deleted_before(cutoff).await {
        tracing::error!(
            event = "item_attachment_purge_failed",
            error = %err,
            item_id = %item.id,
            "Failed to purge deleted attachments"
        );
    }

    let Ok(affected) = item_repo.update(&item).await else {
        tracing::error!(event = "item_delete_failed", "DB error");
        return Err(ItemsError::Db);
    };
    if affected == 0 {
        return Err(ItemsError::Conflict("row_version_conflict"));
    }

    let change_repo = ChangeRepo::new(&state.db);
    let change = Change {
        seq: 0,
        vault_id: vault.id,
        item_id: item.id,
        op: ChangeOp::Delete,
        version: item.version,
        device_id,
        created_at: now,
    };
    if let Err(err) = change_repo.create(&change).await {
        tracing::error!(
            event = "item_change_create_failed",
            error = %err,
            item_id = %item.id,
            "Failed to create change entry"
        );
    }

    tracing::info!(event = "item_deleted", item_id = %item_id, "Item deleted");
    Ok(())
}

pub async fn list_item_versions(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
    limit: Option<i64>,
) -> Result<Vec<ItemHistory>, ItemsError> {
    let resource = format!("vaults/{vault_id}/items/{item_id}/versions");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "read",
        &resource,
        VaultScope::Items,
    )
    .await?;

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_versions_list_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };

    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }

    let limit = limit
        .unwrap_or(ITEM_HISTORY_LIMIT)
        .clamp(1, ITEM_HISTORY_LIMIT);
    let history_repo = ItemHistoryRepo::new(&state.db);
    let versions = match history_repo.list_by_item_limit(item.id, limit).await {
        Ok(rows) => rows,
        Err(_) => {
            tracing::error!(event = "item_versions_list_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };

    tracing::info!(
        event = "item.view_history_list",
        item_id = %item.id,
        vault_id = %vault.id,
        path = %item.path,
        actor_id = %identity.user_id,
        device_id = ?identity.device_id,
        "History list viewed"
    );
    Ok(versions)
}

pub async fn get_item_version(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
    version: i64,
) -> Result<ItemHistory, ItemsError> {
    let resource = format!("vaults/{vault_id}/items/{item_id}/versions/{version}");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "read",
        &resource,
        VaultScope::Items,
    )
    .await?;

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_version_get_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };

    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }

    let history_repo = ItemHistoryRepo::new(&state.db);
    let history = match history_repo.get_by_item_version(item.id, version).await {
        Ok(Some(history)) => history,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_version_get_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };

    tracing::info!(
        event = "item.read_previous",
        item_id = %item.id,
        vault_id = %vault.id,
        path = %item.path,
        version_rev = version,
        actor_id = %identity.user_id,
        device_id = ?identity.device_id,
        "History version read"
    );
    Ok(history)
}

pub async fn restore_item_version(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
    version: i64,
) -> Result<Item, ItemsError> {
    let resource = format!("vaults/{vault_id}/items/{item_id}/versions/{version}/restore");

    let device_id = match identity.device_id {
        Some(device_id) => device_id,
        None => return Err(ItemsError::Forbidden("device_required")),
    };

    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "write",
        &resource,
        VaultScope::Items,
    )
    .await?;

    let item_repo = ItemRepo::new(&state.db);
    let mut item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_restore_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };
    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }

    let history_repo = ItemHistoryRepo::new(&state.db);
    let history = match history_repo.get_by_item_version(item.id, version).await {
        Ok(Some(history)) => history,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_restore_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };

    if history.checksum == item.checksum {
        return Err(ItemsError::BadRequest("no_changes"));
    }

    let actor = actor_snapshot(state, identity, Some(device_id)).await;
    let now = Utc::now();
    let history_snapshot = ItemHistory {
        id: Uuid::now_v7(),
        item_id: item.id,
        payload_enc: item.payload_enc.clone(),
        checksum: item.checksum.clone(),
        version: item.version,
        change_type: ChangeType::Restore,
        fields_changed: None,
        changed_by_user_id: identity.user_id,
        changed_by_email: actor.email,
        changed_by_name: actor.name,
        changed_by_device_id: Some(device_id),
        changed_by_device_name: actor.device_name,
        created_at: now,
    };
    if let Err(err) = history_repo.create(&history_snapshot).await {
        tracing::error!(
            event = "item_history_create_failed",
            error = %err,
            item_id = %item.id,
            "Failed to create item history"
        );
    }
    if let Err(err) = history_repo
        .prune_by_item(item.id, ITEM_HISTORY_LIMIT)
        .await
    {
        tracing::error!(
            event = "item_history_prune_failed",
            error = %err,
            item_id = %item.id,
            "Failed to prune item history"
        );
    }

    item.payload_enc = history.payload_enc;
    item.checksum = history.checksum;
    item.version = item.version.saturating_add(1);
    item.device_id = device_id;
    item.sync_status = SyncStatus::Active;
    item.deleted_at = None;
    item.deleted_by_user_id = None;
    item.deleted_by_device_id = None;
    item.updated_at = now;

    if item.type_id == "file_secret" {
        let attachment_repo = AttachmentRepo::new(&state.db);
        if let Err(err) = attachment_repo.clear_deleted_by_item(item.id).await {
            tracing::error!(
                event = "item_attachment_clear_deleted_failed",
                error = %err,
                item_id = %item.id,
                "Failed to clear deleted attachments"
            );
        }
    }

    let Ok(affected) = item_repo.update(&item).await else {
        tracing::error!(event = "item_restore_failed", "DB error");
        return Err(ItemsError::Db);
    };
    if affected == 0 {
        return Err(ItemsError::Conflict("row_version_conflict"));
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
        tracing::error!(
            event = "item_change_create_failed",
            error = %err,
            item_id = %item.id,
            "Failed to create change entry"
        );
    }

    tracing::info!(
        event = "item.restore_previous",
        item_id = %item_id,
        vault_id = %vault.id,
        path = %item.path,
        version_rev = version,
        actor_id = %identity.user_id,
        device_id = %device_id,
        "History version restored"
    );
    tracing::info!(event = "item_restored", item_id = %item_id, "Item restored");
    Ok(item)
}

pub(crate) fn basename_from_path(path: &str) -> String {
    path.trim_matches('/')
        .split('/')
        .rfind(|part| !part.is_empty())
        .unwrap_or(path)
        .to_string()
}

pub(crate) fn replace_basename(path: &str, name: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return name.to_string();
    }
    let mut parts: Vec<&str> = trimmed.split('/').collect();
    if let Some(last) = parts.last_mut() {
        *last = name;
    }
    parts.join("/")
}

fn file_aad(
    vault_id: Uuid,
    item_id: Uuid,
    file_id: Uuid,
    representation: FileRepresentation,
) -> Vec<u8> {
    let mode = match representation {
        FileRepresentation::Plain => "plain",
        FileRepresentation::Opaque => "opaque",
    };
    format!("{vault_id}:{item_id}:{file_id}:v1:{mode}").into_bytes()
}

fn decrypt_shared_payload_bytes(
    state: &AppState,
    vault: &Vault,
    item: &Item,
) -> Result<Vec<u8>, ItemsError> {
    let Some(smk) = state.server_master_key.as_ref() else {
        tracing::error!(event = "item_payload_decrypt_failed", "SMK not configured");
        return Err(ItemsError::Internal("smk_missing"));
    };
    let vault_key = match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
        Ok(key) => key,
        Err(err) => {
            tracing::error!(
                event = "item_payload_decrypt_failed",
                error = %err,
                "Key decrypt failed"
            );
            return Err(ItemsError::Internal(err.as_code()));
        }
    };
    core_crypto::decrypt_payload_bytes(&vault_key, vault.id, item.id, &item.payload_enc)
        .map_err(|_| ItemsError::Internal("payload_decrypt_failed"))
}

async fn update_file_upload_state(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
    file_id: Uuid,
    filename: String,
    mime: String,
    size: i64,
    checksum: String,
) -> Result<(), ItemsError> {
    let resource = format!("vaults/{vault_id}/items/{item_id}/file");
    let vault = authorize_vault_access(
        state,
        identity,
        vault_id,
        "write",
        &resource,
        VaultScope::Items,
    )
    .await?;
    if vault.encryption_type != VaultEncryptionType::Server {
        return Ok(());
    }

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_get_failed", "DB error");
            return Err(ItemsError::Db);
        }
    };
    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }

    let payload_bytes = match decrypt_shared_payload_bytes(state, &vault, &item) {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::warn!(event = "item_update_failed", "Payload decrypt failed");
            return Ok(());
        }
    };
    let payload_result = {
        let _span = tracing::debug_span!(
            "serialize_json",
            op = "item_payload_decode",
            bytes_len = payload_bytes.len()
        )
        .entered();
        serde_json::from_slice(&payload_bytes)
    };
    let mut payload: JsonValue = match payload_result {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };

    let mut updated = false;
    if let JsonValue::Object(ref mut map) = payload {
        let extra = map
            .entry("extra")
            .or_insert_with(|| JsonValue::Object(Default::default()));
        if let JsonValue::Object(extra_map) = extra {
            extra_map
                .entry("upload_state")
                .and_modify(|value| *value = JsonValue::String("ready".to_string()))
                .or_insert_with(|| JsonValue::String("ready".to_string()));
            extra_map
                .entry("file_id")
                .and_modify(|value| *value = JsonValue::String(file_id.to_string()))
                .or_insert_with(|| JsonValue::String(file_id.to_string()));
            extra_map
                .entry("filename")
                .and_modify(|value| *value = JsonValue::String(filename.clone()))
                .or_insert_with(|| JsonValue::String(filename.clone()));
            extra_map
                .entry("mime")
                .and_modify(|value| *value = JsonValue::String(mime.clone()))
                .or_insert_with(|| JsonValue::String(mime.clone()));
            extra_map
                .entry("size")
                .and_modify(|value| *value = JsonValue::String(size.to_string()))
                .or_insert_with(|| JsonValue::String(size.to_string()));
            extra_map
                .entry("checksum")
                .and_modify(|value| *value = JsonValue::String(checksum.clone()))
                .or_insert_with(|| JsonValue::String(checksum.clone()));
            updated = true;
        }
    }

    if !updated {
        return Ok(());
    }

    let command = UpdateItemCommand {
        path: None,
        name: None,
        type_id: None,
        tags: None,
        favorite: None,
        payload_enc: None,
        payload: Some(payload),
        checksum: None,
        version: None,
        base_version: None,
        fields_changed: None,
    };
    update_item(state, identity, vault_id, item_id, command).await?;
    Ok(())
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

async fn authorize_vault_access(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    action: &str,
    resource: &str,
    scope: VaultScope,
) -> Result<Vault, ItemsError> {
    let policies = state.policy_store.get();

    let vault_repo = VaultRepo::new(&state.db);
    let vault = match find_vault(&vault_repo, vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "vault_access_failed", "DB error");
            return Err(ItemsError::Db);
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
            return Err(ItemsError::ForbiddenNoBody);
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
                    return Err(ItemsError::ForbiddenNoBody);
                }
                Err(_) => {
                    tracing::error!(event = "vault_access_failed", "DB error");
                    return Err(ItemsError::Db);
                }
            }
        }
    }

    Ok(vault)
}
