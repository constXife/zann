use chrono::{DateTime, Utc};
use sqlx_core::row::Row;
use sqlx_core::types::Json as SqlxJson;
use uuid::Uuid;
use zann_core::{
    Attachment, Change, ChangeOp, ChangeType, FieldsChanged, Identity, Item, ItemHistory,
    SyncStatus, Vault, VaultEncryptionType,
};
use zann_crypto::crypto::{decrypt_blob, encrypt_blob, EncryptedBlob};
use zann_crypto::vault_crypto as core_crypto;
use zann_crypto::EncryptedPayload;
use zann_db::repo::{
    AttachmentRepo, ChangeRepo, DeviceRepo, ItemHistoryRepo, ItemRepo, ServiceAccountRepo,
    UserRepo, VaultRepo,
};
use zeroize::Zeroizing;

use crate::app::AppState;
use crate::domains::access_control::http::{
    find_vault, scopes_allow_path, scopes_allow_prefix, vault_role_allows, VaultScope,
};
use crate::domains::access_control::policies::PolicyDecision;
use crate::domains::errors::ServiceError;
use crate::domains::items::contract::{
    canonical_create_location, canonical_create_version, canonical_type_id,
    canonical_update_location, next_item_version, validate_existing_type_id,
    validate_personal_ciphertext, validate_server_typed_payload,
};
use crate::domains::secrets::service::{decode_secret_payload_bytes, SECRET_TYPE_ID};
use crate::infra::metrics;

pub const ITEM_HISTORY_LIMIT: i64 = 5;
pub const MAX_TAGS: usize = 50;
pub(crate) const ITEM_LIST_DEFAULT_LIMIT: i64 = 50;
pub(crate) const ITEM_LIST_MAX_LIMIT: i64 = 100;
const MAX_CIPHERTEXT_BYTES: usize = 10 * 1024 * 1024;
const MAX_ATTACHMENT_CONTENT_BYTES: usize = MAX_CIPHERTEXT_BYTES + 1024;
const MAX_ATTACHMENT_FILENAME_BYTES: usize = 255;
const MAX_ATTACHMENT_MIME_BYTES: usize = 255;

pub type ItemsError = ServiceError;

pub struct ItemWithVault {
    pub vault: Vault,
    pub item: Item,
}

pub struct ItemHistoryWithVault {
    pub vault: Vault,
    pub history: ItemHistory,
    pub item_type_id: String,
}

pub(crate) struct ItemListEntry {
    pub(crate) id: Uuid,
    pub(crate) vault_id: Uuid,
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) type_id: String,
    pub(crate) tags: Option<SqlxJson<Vec<String>>>,
    pub(crate) favorite: bool,
    pub(crate) checksum: String,
    pub(crate) version: i64,
    pub(crate) deleted_at: Option<DateTime<Utc>>,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) payload_size: i64,
}

pub(crate) struct ItemListPage {
    pub(crate) items: Vec<ItemListEntry>,
    pub(crate) has_more: bool,
}

pub struct CreateItemCommand {
    pub path: String,
    pub type_id: String,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
    pub payload_enc: Option<Vec<u8>>,
    pub payload: Option<EncryptedPayload>,
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
    pub payload: Option<EncryptedPayload>,
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

pub(crate) async fn list_items(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    prefix: Option<&str>,
    limit: Option<i64>,
    cursor: Option<&str>,
) -> Result<ItemListPage, ItemsError> {
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

    let prefix = normalize_prefix(prefix);
    if let Some(service_account_id) = identity.service_account_id {
        if !service_account_allows_prefix(
            state,
            service_account_id,
            &vault,
            "list",
            prefix.as_deref(),
        )
        .await
        {
            metrics::forbidden_access(&resource);
            return Err(ItemsError::ForbiddenNoBody);
        }
    }

    let cursor = parse_item_list_cursor(cursor)?;
    let limit = limit
        .unwrap_or(ITEM_LIST_DEFAULT_LIMIT)
        .clamp(1, ITEM_LIST_MAX_LIMIT);
    let page =
        fetch_item_list_page(state, vault.id, prefix.as_deref(), None, cursor, limit).await?;

    tracing::info!(
        event = "items_listed",
        count = page.items.len(),
        "Item list returned"
    );
    Ok(page)
}

pub(crate) fn parse_item_list_cursor(
    cursor: Option<&str>,
) -> Result<Option<(DateTime<Utc>, Uuid)>, ItemsError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let (timestamp, item_id) = cursor
        .split_once('|')
        .ok_or(ItemsError::BadRequest("invalid_cursor"))?;
    if item_id.contains('|') {
        return Err(ItemsError::BadRequest("invalid_cursor"));
    }
    let timestamp = DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| ItemsError::BadRequest("invalid_cursor"))?
        .with_timezone(&Utc);
    let item_id = Uuid::parse_str(item_id).map_err(|_| ItemsError::BadRequest("invalid_cursor"))?;
    Ok(Some((timestamp, item_id)))
}

pub(crate) fn encode_item_list_cursor(item: &ItemListEntry) -> String {
    format!("{}|{}", item.updated_at.to_rfc3339(), item.id)
}

/// Fetches only bounded list metadata. Payload bytes are deliberately excluded
/// so summary endpoints cannot materialize ciphertext they never return.
pub(crate) async fn fetch_item_list_page(
    state: &AppState,
    vault_id: Uuid,
    prefix: Option<&str>,
    type_id: Option<&str>,
    cursor: Option<(DateTime<Utc>, Uuid)>,
    limit: i64,
) -> Result<ItemListPage, ItemsError> {
    debug_assert!(limit > 0);
    let (cursor_timestamp, cursor_id) = cursor.unzip();
    let rows = sqlx_core::query::query(
        r#"
        SELECT
            id,
            vault_id,
            path,
            name,
            type_id,
            tags,
            favorite,
            checksum,
            version,
            deleted_at,
            updated_at,
            octet_length(payload_enc)::bigint AS payload_size
        FROM items
        WHERE vault_id = $1
          AND sync_status = 1
          AND ($2::text IS NULL OR path = $2 OR starts_with(path, $2 || '/'))
          AND ($3::text IS NULL OR type_id = $3)
          AND (
                $4::timestamptz IS NULL
                OR updated_at < $4
                OR (updated_at = $4 AND id < $5)
              )
        ORDER BY updated_at DESC, id DESC
        LIMIT $6
        "#,
    )
    .bind(vault_id)
    .bind(prefix)
    .bind(type_id)
    .bind(cursor_timestamp)
    .bind(cursor_id)
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await
    .map_err(|err| {
        tracing::error!(event = "items_list_failed", error = %err, "DB error");
        ItemsError::DbError
    })?;

    let mut items = Vec::with_capacity(rows.len().min(limit as usize));
    for row in rows {
        let item = ItemListEntry {
            id: row.try_get("id").map_err(|_| ItemsError::DbError)?,
            vault_id: row.try_get("vault_id").map_err(|_| ItemsError::DbError)?,
            path: row.try_get("path").map_err(|_| ItemsError::DbError)?,
            name: row.try_get("name").map_err(|_| ItemsError::DbError)?,
            type_id: row.try_get("type_id").map_err(|_| ItemsError::DbError)?,
            tags: row.try_get("tags").map_err(|_| ItemsError::DbError)?,
            favorite: row.try_get("favorite").map_err(|_| ItemsError::DbError)?,
            checksum: row.try_get("checksum").map_err(|_| ItemsError::DbError)?,
            version: row.try_get("version").map_err(|_| ItemsError::DbError)?,
            deleted_at: row.try_get("deleted_at").map_err(|_| ItemsError::DbError)?,
            updated_at: row.try_get("updated_at").map_err(|_| ItemsError::DbError)?,
            payload_size: row
                .try_get("payload_size")
                .map_err(|_| ItemsError::DbError)?,
        };
        items.push(item);
    }
    let has_more = items.len() > limit as usize;
    if has_more {
        items.truncate(limit as usize);
    }
    Ok(ItemListPage { items, has_more })
}

pub(crate) async fn fetch_current_item_payload(
    state: &AppState,
    item: &ItemListEntry,
    max_payload_bytes: usize,
) -> Result<Vec<u8>, ItemsError> {
    if item.payload_size <= 0 || item.payload_size as usize > max_payload_bytes {
        return Err(ItemsError::PayloadTooLarge("payload_too_large"));
    }
    let row = sqlx_core::query::query(
        r#"
        SELECT payload_enc
        FROM items
        WHERE id = $1
          AND vault_id = $2
          AND version = $3
          AND updated_at = $4
          AND octet_length(payload_enc) <= $5
        "#,
    )
    .bind(item.id)
    .bind(item.vault_id)
    .bind(item.version)
    .bind(item.updated_at)
    .bind(max_payload_bytes as i64)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| {
        tracing::error!(event = "item_payload_fetch_failed", error = %err, "DB error");
        ItemsError::DbError
    })?
    .ok_or(ItemsError::Conflict("item_changed_during_list"))?;
    row.try_get("payload_enc").map_err(|_| ItemsError::DbError)
}

pub async fn get_item(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
) -> Result<ItemWithVault, ItemsError> {
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
            return Err(ItemsError::DbError);
        }
    };

    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }
    if item.sync_status != SyncStatus::Active || item.deleted_at.is_some() {
        return Err(ItemsError::NotFound);
    }
    if let Some(service_account_id) = identity.service_account_id {
        if !service_account_allows_path(state, service_account_id, &vault, "read", &item.path).await
        {
            metrics::forbidden_access(&resource);
            return Err(ItemsError::ForbiddenNoBody);
        }
    }

    tracing::info!(event = "item_fetched", item_id = %item_id, "Item fetched");
    Ok(ItemWithVault { vault, item })
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
    let mut bytes = Zeroizing::new(bytes);
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
    if filename
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > MAX_ATTACHMENT_FILENAME_BYTES)
        || mime
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_ATTACHMENT_MIME_BYTES)
    {
        return Err(ItemsError::BadRequest("file_metadata_invalid"));
    }

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_get_failed", "DB error");
            return Err(ItemsError::DbError);
        }
    };
    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }
    if item.sync_status != SyncStatus::Active {
        return Err(ItemsError::NotFound);
    }
    if item.type_id != "file_secret" {
        return Err(ItemsError::BadRequest("item_type_not_supported"));
    }
    let mut server_payload = None;
    if vault.encryption_type == VaultEncryptionType::Server {
        let payload =
            decrypt_typed_payload(state, &vault, item.id, &item.payload_enc, &item.type_id)
                .map_err(|_| ItemsError::BadRequest("invalid_payload"))?;
        let extra = payload.extra.as_ref();
        let upload_state = extra
            .and_then(|map| map.get("upload_state"))
            .map(String::as_str);
        if upload_state != Some("pending") {
            return Err(ItemsError::BadRequest("upload_state_invalid"));
        }
        let expected_file_id = extra
            .and_then(|map| map.get("file_id"))
            .map(String::as_str)
            .ok_or(ItemsError::BadRequest("file_id_missing"))?;
        if expected_file_id != file_id.to_string() {
            return Err(ItemsError::Conflict("file_id_mismatch"));
        }
        server_payload = Some(payload);
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
            let blob = encrypt_blob(&vault_key, bytes.as_slice(), &aad).map_err(|_| {
                tracing::error!(event = "file_upload_failed", "Encryption failed");
                ItemsError::Internal("file_encrypt_failed")
            })?;
            let content_enc = blob.to_bytes();
            let checksum = core_crypto::payload_checksum(&content_enc);
            (content_enc, checksum, "plain".to_string())
        } else {
            let checksum = core_crypto::payload_checksum(bytes.as_slice());
            (std::mem::take(&mut *bytes), checksum, "opaque".to_string())
        }
    } else {
        let checksum = core_crypto::payload_checksum(bytes.as_slice());
        (std::mem::take(&mut *bytes), checksum, "opaque".to_string())
    };
    if content_enc.is_empty() || content_enc.len() > MAX_ATTACHMENT_CONTENT_BYTES {
        return Err(ItemsError::PayloadTooLarge("file_too_large"));
    }

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

    let mutation = if let Some(mut payload) = server_payload {
        let device_id = identity
            .device_id
            .ok_or(ItemsError::Forbidden("device_required"))?;
        let extra = payload.extra.get_or_insert_with(Default::default);
        extra.insert("upload_state".to_string(), "ready".to_string());
        extra.insert("file_id".to_string(), file_id.to_string());
        extra.insert("filename".to_string(), attachment.filename.clone());
        extra.insert("mime".to_string(), attachment.mime_type.clone());
        extra.insert("size".to_string(), attachment.size.to_string());
        extra.insert("checksum".to_string(), attachment.checksum.clone());
        validate_server_typed_payload(&payload, &item.type_id)
            .map_err(|error| ItemsError::BadRequest(error.code()))?;
        let Some(smk) = state.server_master_key.as_ref() else {
            return Err(ItemsError::Internal("smk_missing"));
        };
        let vault_key = core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)
            .map_err(|err| ItemsError::Internal(err.as_code()))?;
        let payload_enc = core_crypto::encrypt_payload(&vault_key, vault.id, item.id, &payload)
            .map_err(|err| ItemsError::Internal(err.as_code()))?;
        let now = Utc::now();
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
            created_at: now,
        };
        let mut updated_item = item.clone();
        updated_item.payload_enc = payload_enc;
        updated_item.checksum = core_crypto::payload_checksum(&updated_item.payload_enc);
        updated_item.version = next_item_version(updated_item.version)
            .map_err(|error| ItemsError::Conflict(error.code()))?;
        updated_item.device_id = device_id;
        updated_item.updated_at = now;
        let change = Change {
            seq: 0,
            vault_id: vault.id,
            item_id: item.id,
            op: ChangeOp::Update,
            version: updated_item.version,
            device_id,
            created_at: now,
        };
        Some((updated_item, history, change))
    } else {
        None
    };

    let attachment_repo = AttachmentRepo::new(&state.db);
    let history_repo = ItemHistoryRepo::new(&state.db);
    let change_repo = ChangeRepo::new(&state.db);
    let mut tx = state.db.begin().await.map_err(|err| {
        tracing::error!(event = "attachment_create_failed", error = %err, "DB error");
        ItemsError::DbError
    })?;
    let locked = item_repo
        .get_by_id_for_update_in(&mut tx, item.id)
        .await
        .map_err(|err| {
            tracing::error!(event = "attachment_create_failed", error = %err, "DB error");
            ItemsError::DbError
        })?
        .ok_or(ItemsError::NotFound)?;
    if locked.vault_id != vault.id || locked.row_version != item.row_version {
        return Err(ItemsError::Conflict("row_version_conflict"));
    }
    if locked.sync_status != SyncStatus::Active {
        return Err(ItemsError::NotFound);
    }
    let existing_attachment =
        sqlx_core::query::query("SELECT item_id FROM attachments WHERE id = $1")
            .bind(file_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|err| {
                tracing::error!(event = "attachment_lookup_failed", error = %err, "DB error");
                ItemsError::DbError
            })?;
    if existing_attachment.is_some() {
        return Err(ItemsError::Conflict("file_id_conflict"));
    }
    attachment_repo
        .create_in(&mut tx, &attachment)
        .await
        .map_err(|err| {
            tracing::error!(event = "attachment_create_failed", error = %err, "DB error");
            ItemsError::DbError
        })?;
    if let Some((updated_item, history, change)) = mutation.as_ref() {
        history_repo
            .create_in(&mut tx, history)
            .await
            .map_err(|err| {
                tracing::error!(event = "item_history_create_failed", error = %err, item_id = %item.id);
                ItemsError::DbError
            })?;
        history_repo
            .prune_by_item_in(&mut tx, item.id, ITEM_HISTORY_LIMIT)
            .await
            .map_err(|err| {
                tracing::error!(event = "item_history_prune_failed", error = %err, item_id = %item.id);
                ItemsError::DbError
            })?;
        let affected = item_repo
            .update_in(&mut tx, updated_item)
            .await
            .map_err(|err| {
                tracing::error!(event = "item_update_failed", error = %err, item_id = %item.id);
                ItemsError::DbError
            })?;
        if affected != 1 {
            return Err(ItemsError::Conflict("row_version_conflict"));
        }
        change_repo
            .create_in(&mut tx, change)
            .await
            .map_err(|err| {
                tracing::error!(event = "item_change_create_failed", error = %err, item_id = %item.id);
                ItemsError::DbError
            })?;
    }
    tx.commit().await.map_err(|err| {
        tracing::error!(event = "attachment_create_commit_failed", error = %err, item_id = %item.id);
        ItemsError::DbError
    })?;

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
            return Err(ItemsError::DbError);
        }
    };
    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }
    if item.sync_status != SyncStatus::Active {
        return Err(ItemsError::NotFound);
    }
    if item.type_id != "file_secret" {
        return Err(ItemsError::BadRequest("item_type_not_supported"));
    }

    let preferred_file_id = if vault.encryption_type == VaultEncryptionType::Server {
        let payload =
            decrypt_typed_payload(state, &vault, item.id, &item.payload_enc, &item.type_id)
                .map_err(|_| ItemsError::BadRequest("invalid_payload"))?;
        let file_id = payload
            .extra
            .as_ref()
            .and_then(|map| map.get("file_id"))
            .ok_or(ItemsError::BadRequest("file_id_missing"))?;
        Some(Uuid::parse_str(file_id).map_err(|_| ItemsError::BadRequest("file_id_invalid"))?)
    } else {
        None
    };
    let metadata = sqlx_core::query::query(
        r#"
        SELECT
            id,
            octet_length(filename)::bigint AS filename_size,
            octet_length(mime_type)::bigint AS mime_size,
            octet_length(enc_mode)::bigint AS enc_mode_size,
            octet_length(checksum)::bigint AS checksum_size,
            octet_length(content_enc)::bigint AS content_size
        FROM attachments
        WHERE item_id = $1
          AND deleted_at IS NULL
          AND ($2::uuid IS NULL OR id = $2)
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        "#,
    )
    .bind(item_id)
    .bind(preferred_file_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| {
        tracing::error!(event = "attachment_list_failed", error = %err, "DB error");
        ItemsError::DbError
    })?;
    let Some(metadata) = metadata else {
        return Err(ItemsError::NotFound);
    };
    let attachment_id: Uuid = metadata.try_get("id").map_err(|_| ItemsError::DbError)?;
    let filename_size: i64 = metadata
        .try_get("filename_size")
        .map_err(|_| ItemsError::DbError)?;
    let mime_size: i64 = metadata
        .try_get("mime_size")
        .map_err(|_| ItemsError::DbError)?;
    let enc_mode_size: i64 = metadata
        .try_get("enc_mode_size")
        .map_err(|_| ItemsError::DbError)?;
    let checksum_size: i64 = metadata
        .try_get("checksum_size")
        .map_err(|_| ItemsError::DbError)?;
    let content_size: i64 = metadata
        .try_get("content_size")
        .map_err(|_| ItemsError::DbError)?;
    if !(1..=MAX_ATTACHMENT_FILENAME_BYTES as i64).contains(&filename_size)
        || !(1..=MAX_ATTACHMENT_MIME_BYTES as i64).contains(&mime_size)
        || !(1..=6).contains(&enc_mode_size)
        || checksum_size != 64
        || !(1..=MAX_ATTACHMENT_CONTENT_BYTES as i64).contains(&content_size)
    {
        return Err(ItemsError::PayloadTooLarge("attachment_invalid"));
    }
    let attachment = sqlx_core::query::query(
        r#"
        SELECT enc_mode, content_enc, checksum
        FROM attachments
        WHERE id = $1
          AND item_id = $2
          AND deleted_at IS NULL
          AND octet_length(filename) BETWEEN 1 AND $3
          AND octet_length(mime_type) BETWEEN 1 AND $4
          AND octet_length(content_enc) BETWEEN 1 AND $5
          AND octet_length(checksum) = 64
          AND enc_mode IN ('plain', 'opaque')
        "#,
    )
    .bind(attachment_id)
    .bind(item_id)
    .bind(MAX_ATTACHMENT_FILENAME_BYTES as i64)
    .bind(MAX_ATTACHMENT_MIME_BYTES as i64)
    .bind(MAX_ATTACHMENT_CONTENT_BYTES as i64)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| {
        tracing::error!(event = "attachment_fetch_failed", error = %err, "DB error");
        ItemsError::DbError
    })?
    .ok_or(ItemsError::Conflict("attachment_changed_during_read"))?;
    let enc_mode: String = attachment
        .try_get("enc_mode")
        .map_err(|_| ItemsError::DbError)?;
    let content_enc: Vec<u8> = attachment
        .try_get("content_enc")
        .map_err(|_| ItemsError::DbError)?;
    let checksum: String = attachment
        .try_get("checksum")
        .map_err(|_| ItemsError::DbError)?;
    crate::domains::items::contract::validate_checksum(&checksum)
        .map_err(|_| ItemsError::Internal("attachment_invalid"))?;
    if core_crypto::payload_checksum(&content_enc) != checksum {
        return Err(ItemsError::Internal("attachment_checksum_mismatch"));
    }

    if representation == FileRepresentation::Opaque {
        return Ok(FileDownloadResult { bytes: content_enc });
    }

    if vault.encryption_type == VaultEncryptionType::Server && enc_mode == "plain" {
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
        let aad = file_aad(vault.id, item_id, attachment_id, representation);
        let blob = EncryptedBlob::from_bytes(&content_enc)
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
) -> Result<ItemWithVault, ItemsError> {
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

    let type_id = canonical_type_id(&command.type_id)
        .map_err(|error| ItemsError::BadRequest(error.code()))?;
    let (path, name) = canonical_create_location(&command.path, None)
        .map_err(|error| ItemsError::BadRequest(error.code()))?;

    let tags = command.tags.map(|tags| {
        tags.into_iter()
            .filter(|t| !t.trim().is_empty())
            .take(MAX_TAGS)
            .collect()
    });
    let tags = tags.filter(|tags: &Vec<String>| !tags.is_empty());

    let item_id = Uuid::now_v7();

    let (payload_enc, checksum) = if vault.encryption_type == VaultEncryptionType::Server {
        if command.payload_enc.is_some() || command.checksum.is_some() {
            return Err(ItemsError::BadRequest("ambiguous_payload"));
        }
        let Some(plaintext_payload) = command.payload else {
            return Err(ItemsError::BadRequest("payload_required"));
        };
        validate_server_typed_payload(&plaintext_payload, &type_id)
            .map_err(|error| ItemsError::BadRequest(error.code()))?;
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
            match core_crypto::encrypt_payload(&vault_key, vault.id, item_id, &plaintext_payload) {
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
        if command.payload.is_some() {
            return Err(ItemsError::BadRequest("plaintext_not_allowed"));
        }
        let Some(enc) = command.payload_enc else {
            return Err(ItemsError::BadRequest("payload_enc_required"));
        };
        let checksum = command
            .checksum
            .as_deref()
            .ok_or(ItemsError::BadRequest("checksum_required"))?;
        validate_personal_ciphertext(&enc, checksum)
            .map_err(|error| ItemsError::BadRequest(error.code()))?;
        (enc, checksum.to_string())
    };

    let version = canonical_create_version(command.version)
        .map_err(|error| ItemsError::BadRequest(error.code()))?;
    let now = Utc::now();
    let item = Item {
        id: item_id,
        vault_id: vault.id,
        path,
        name,
        type_id,
        tags: tags.map(SqlxJson),
        favorite: command.favorite.unwrap_or(false),
        payload_enc,
        checksum,
        version,
        row_version: 1,
        device_id,
        sync_status: SyncStatus::Active,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        created_at: now,
        updated_at: now,
    };

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
    let change = Change {
        seq: 0,
        vault_id: vault.id,
        item_id: item.id,
        op: ChangeOp::Create,
        version: item.version,
        device_id,
        created_at: now,
    };
    let item_repo = ItemRepo::new(&state.db);
    let history_repo = ItemHistoryRepo::new(&state.db);
    let change_repo = ChangeRepo::new(&state.db);
    let mut tx = state.db.begin().await.map_err(|err| {
        tracing::error!(event = "item_create_failed", error = %err, "DB error");
        ItemsError::DbError
    })?;
    item_repo.create_in(&mut tx, &item).await.map_err(|err| {
        tracing::error!(event = "item_create_failed", error = %err, "DB error");
        ItemsError::DbError
    })?;
    history_repo
        .create_in(&mut tx, &history)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_history_create_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    history_repo
        .prune_by_item_in(&mut tx, item.id, ITEM_HISTORY_LIMIT)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_history_prune_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    change_repo
        .create_in(&mut tx, &change)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_change_create_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    tx.commit().await.map_err(|err| {
        tracing::error!(event = "item_create_commit_failed", error = %err, item_id = %item.id);
        ItemsError::DbError
    })?;

    tracing::info!(event = "item_created", item_id = %item.id, "Item created");
    Ok(ItemWithVault { vault, item })
}

pub async fn update_item(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
    command: UpdateItemCommand,
) -> Result<ItemWithVault, ItemsError> {
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
            return Err(ItemsError::DbError);
        }
    };

    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }
    if item.sync_status != SyncStatus::Active {
        return Err(ItemsError::NotFound);
    }

    if let Some(base_version) = command.base_version {
        if base_version != item.version {
            return Err(ItemsError::Conflict("version_conflict"));
        }
    }

    let UpdateItemCommand {
        path,
        name,
        type_id,
        tags,
        favorite,
        payload_enc,
        payload,
        checksum,
        version: requested_version,
        base_version: _,
        fields_changed,
    } = command;
    let (next_path, next_name) =
        canonical_update_location(&item.path, path.as_deref(), name.as_deref())
            .map_err(|error| ItemsError::BadRequest(error.code()))?;
    validate_existing_type_id(&item.type_id, type_id.as_deref())
        .map_err(|error| ItemsError::BadRequest(error.code()))?;
    let next_type_id = item.type_id.clone();
    if payload.is_some() && payload_enc.is_some() {
        return Err(ItemsError::BadRequest("ambiguous_payload"));
    }

    let payload_update = if let Some(plaintext_payload) = payload {
        if vault.encryption_type != VaultEncryptionType::Server {
            return Err(ItemsError::BadRequest("plaintext_not_allowed"));
        }
        validate_server_typed_payload(&plaintext_payload, &next_type_id)
            .map_err(|error| ItemsError::BadRequest(error.code()))?;
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
        let payload_enc = match core_crypto::encrypt_payload(
            &vault_key,
            vault.id,
            item.id,
            &plaintext_payload,
        ) {
            Ok(enc) => enc,
            Err(err) => {
                tracing::error!(event = "item_update_failed", error = %err, "Encryption failed");
                return Err(ItemsError::Internal(err.as_code()));
            }
        };
        let checksum = core_crypto::payload_checksum(&payload_enc);
        Some((payload_enc, checksum))
    } else if let Some(payload_enc) = payload_enc {
        if vault.encryption_type == VaultEncryptionType::Server {
            return Err(ItemsError::BadRequest("ciphertext_not_allowed"));
        }
        let checksum = checksum
            .as_deref()
            .ok_or(ItemsError::BadRequest("checksum_required"))?;
        validate_personal_ciphertext(&payload_enc, checksum)
            .map_err(|error| ItemsError::BadRequest(error.code()))?;
        Some((payload_enc, checksum.to_string()))
    } else {
        if checksum.is_some() {
            return Err(ItemsError::BadRequest("checksum_without_payload"));
        }
        None
    };

    let previous_payload = item.payload_enc.clone();
    let previous_checksum = item.checksum.clone();
    let previous_version = item.version;
    let mut updated = false;
    if next_path != item.path {
        item.path = next_path;
        item.name = next_name;
        updated = true;
    }
    if let Some(tags) = tags {
        let tags: Vec<String> = tags
            .into_iter()
            .filter(|t| !t.trim().is_empty())
            .take(MAX_TAGS)
            .collect();
        let tags = if tags.is_empty() { None } else { Some(tags) };
        if item.tags.as_ref().map(|t| t.0.clone()) != tags {
            item.tags = tags.map(SqlxJson);
            updated = true;
        }
    }
    if let Some(favorite) = favorite {
        if favorite != item.favorite {
            item.favorite = favorite;
            updated = true;
        }
    }
    if let Some((payload_enc, checksum)) = payload_update {
        item.payload_enc = payload_enc;
        item.checksum = checksum;
        updated = true;
    }

    if !updated {
        return Err(ItemsError::BadRequest("no_changes"));
    }

    let actor = actor_snapshot(state, identity, Some(device_id)).await;
    let history = ItemHistory {
        id: Uuid::now_v7(),
        item_id: item.id,
        payload_enc: previous_payload,
        checksum: previous_checksum,
        version: previous_version,
        change_type: ChangeType::Update,
        fields_changed: fields_changed.map(SqlxJson),
        changed_by_user_id: identity.user_id,
        changed_by_email: actor.email,
        changed_by_name: actor.name,
        changed_by_device_id: Some(device_id),
        changed_by_device_name: actor.device_name,
        created_at: Utc::now(),
    };

    let next_version =
        next_item_version(item.version).map_err(|error| ItemsError::Conflict(error.code()))?;
    if requested_version.is_some_and(|version| version != next_version) {
        return Err(ItemsError::BadRequest("invalid_version"));
    }
    item.version = next_version;
    item.device_id = device_id;
    item.updated_at = Utc::now();

    let change = Change {
        seq: 0,
        vault_id: vault.id,
        item_id: item.id,
        op: ChangeOp::Update,
        version: item.version,
        device_id,
        created_at: item.updated_at,
    };
    let history_repo = ItemHistoryRepo::new(&state.db);
    let change_repo = ChangeRepo::new(&state.db);
    let mut tx = state.db.begin().await.map_err(|err| {
        tracing::error!(event = "item_update_failed", error = %err, "DB error");
        ItemsError::DbError
    })?;
    let locked = item_repo
        .get_by_id_for_update_in(&mut tx, item.id)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_update_failed", error = %err, "DB error");
            ItemsError::DbError
        })?
        .ok_or(ItemsError::NotFound)?;
    if locked.vault_id != vault.id || locked.row_version != item.row_version {
        return Err(ItemsError::Conflict("row_version_conflict"));
    }
    history_repo
        .create_in(&mut tx, &history)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_history_create_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    history_repo
        .prune_by_item_in(&mut tx, item.id, ITEM_HISTORY_LIMIT)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_history_prune_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    let affected = item_repo.update_in(&mut tx, &item).await.map_err(|err| {
        tracing::error!(event = "item_update_failed", error = %err, "DB error");
        ItemsError::DbError
    })?;
    if affected != 1 {
        return Err(ItemsError::Conflict("row_version_conflict"));
    }
    change_repo
        .create_in(&mut tx, &change)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_change_create_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    tx.commit().await.map_err(|err| {
        tracing::error!(event = "item_update_commit_failed", error = %err, item_id = %item.id);
        ItemsError::DbError
    })?;

    tracing::info!(event = "item_updated", item_id = %item_id, "Item updated");
    Ok(ItemWithVault { vault, item })
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
            return Err(ItemsError::DbError);
        }
    };

    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }
    if item.sync_status != SyncStatus::Active {
        return Err(ItemsError::NotFound);
    }

    let now = Utc::now();
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
    item.deleted_at = Some(now);
    item.deleted_by_user_id = Some(identity.user_id);
    item.deleted_by_device_id = Some(device_id);
    item.sync_status = SyncStatus::Tombstone;
    item.version =
        next_item_version(item.version).map_err(|error| ItemsError::Conflict(error.code()))?;
    item.device_id = device_id;
    item.updated_at = now;

    let change = Change {
        seq: 0,
        vault_id: vault.id,
        item_id: item.id,
        op: ChangeOp::Delete,
        version: item.version,
        device_id,
        created_at: now,
    };
    let history_repo = ItemHistoryRepo::new(&state.db);
    let attachment_repo = AttachmentRepo::new(&state.db);
    let change_repo = ChangeRepo::new(&state.db);
    let mut tx = state.db.begin().await.map_err(|err| {
        tracing::error!(event = "item_delete_failed", error = %err, "DB error");
        ItemsError::DbError
    })?;
    let locked = item_repo
        .get_by_id_for_update_in(&mut tx, item.id)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_delete_failed", error = %err, "DB error");
            ItemsError::DbError
        })?
        .ok_or(ItemsError::NotFound)?;
    if locked.vault_id != vault.id || locked.row_version != item.row_version {
        return Err(ItemsError::Conflict("row_version_conflict"));
    }
    history_repo
        .create_in(&mut tx, &history)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_history_create_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    history_repo
        .prune_by_item_in(&mut tx, item.id, ITEM_HISTORY_LIMIT)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_history_prune_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    attachment_repo
        .mark_deleted_by_item_in(&mut tx, item.id, now)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_attachment_mark_deleted_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    let affected = item_repo.update_in(&mut tx, &item).await.map_err(|err| {
        tracing::error!(event = "item_delete_failed", error = %err, "DB error");
        ItemsError::DbError
    })?;
    if affected != 1 {
        return Err(ItemsError::Conflict("row_version_conflict"));
    }
    change_repo
        .create_in(&mut tx, &change)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_change_create_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    tx.commit().await.map_err(|err| {
        tracing::error!(event = "item_delete_commit_failed", error = %err, item_id = %item.id);
        ItemsError::DbError
    })?;

    // Garbage collection is independent housekeeping. Aggregate deletion is
    // already durable; never report a failed mutation after its commit.
    let grace_days = state.config.server.attachments_gc_grace_days.max(0);
    let cutoff = now - chrono::Duration::days(grace_days);
    if let Err(err) = attachment_repo.purge_deleted_before(cutoff).await {
        tracing::error!(event = "item_attachment_purge_failed", error = %err, item_id = %item.id);
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
            return Err(ItemsError::DbError);
        }
    };

    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }
    if let Some(service_account_id) = identity.service_account_id {
        if !service_account_allows_path(state, service_account_id, &vault, "read", &item.path).await
        {
            metrics::forbidden_access(&resource);
            return Err(ItemsError::ForbiddenNoBody);
        }
    }

    let limit = limit
        .unwrap_or(ITEM_HISTORY_LIMIT)
        .clamp(1, ITEM_HISTORY_LIMIT);
    let history_repo = ItemHistoryRepo::new(&state.db);
    let versions = match history_repo.list_by_item_limit(item.id, limit).await {
        Ok(rows) => rows,
        Err(_) => {
            tracing::error!(event = "item_versions_list_failed", "DB error");
            return Err(ItemsError::DbError);
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
) -> Result<ItemHistoryWithVault, ItemsError> {
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
            return Err(ItemsError::DbError);
        }
    };

    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }
    if let Some(service_account_id) = identity.service_account_id {
        if !service_account_allows_path(state, service_account_id, &vault, "read", &item.path).await
        {
            metrics::forbidden_access(&resource);
            return Err(ItemsError::ForbiddenNoBody);
        }
    }

    let history_repo = ItemHistoryRepo::new(&state.db);
    let history = match history_repo.get_by_item_version(item.id, version).await {
        Ok(Some(history)) => history,
        Ok(None) => return Err(ItemsError::NotFound),
        Err(_) => {
            tracing::error!(event = "item_version_get_failed", "DB error");
            return Err(ItemsError::DbError);
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
    Ok(ItemHistoryWithVault {
        vault,
        history,
        item_type_id: item.type_id,
    })
}

pub async fn restore_item_version(
    state: &AppState,
    identity: &Identity,
    vault_id: &str,
    item_id: Uuid,
    version: i64,
) -> Result<ItemWithVault, ItemsError> {
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

    let actor = actor_snapshot(state, identity, Some(device_id)).await;
    let now = Utc::now();
    let item_repo = ItemRepo::new(&state.db);
    let history_repo = ItemHistoryRepo::new(&state.db);
    let attachment_repo = AttachmentRepo::new(&state.db);
    let change_repo = ChangeRepo::new(&state.db);
    let mut tx = state.db.begin().await.map_err(|err| {
        tracing::error!(event = "item_restore_failed", error = %err, "DB error");
        ItemsError::DbError
    })?;
    let mut item = item_repo
        .get_by_id_for_update_in(&mut tx, item_id)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_restore_failed", error = %err, "DB error");
            ItemsError::DbError
        })?
        .ok_or(ItemsError::NotFound)?;
    if item.vault_id != vault.id {
        return Err(ItemsError::NotFound);
    }
    let history = history_repo
        .get_by_item_version_in(&mut tx, item.id, version)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_restore_failed", error = %err, "DB error");
            ItemsError::DbError
        })?
        .ok_or(ItemsError::NotFound)?;
    if history.checksum == item.checksum && item.sync_status == SyncStatus::Active {
        return Err(ItemsError::BadRequest("no_changes"));
    }

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
    history_repo
        .create_in(&mut tx, &history_snapshot)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_history_create_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;

    item.payload_enc = history.payload_enc;
    item.checksum = history.checksum;
    item.version =
        next_item_version(item.version).map_err(|error| ItemsError::Conflict(error.code()))?;
    item.device_id = device_id;
    item.sync_status = SyncStatus::Active;
    item.deleted_at = None;
    item.deleted_by_user_id = None;
    item.deleted_by_device_id = None;
    item.updated_at = now;

    if item.type_id == "file_secret" {
        attachment_repo
            .clear_deleted_by_item_in(&mut tx, item.id)
            .await
            .map_err(|err| {
                tracing::error!(event = "item_attachment_clear_deleted_failed", error = %err, item_id = %item.id);
                ItemsError::DbError
            })?;
    }

    let affected = item_repo.update_in(&mut tx, &item).await.map_err(|err| {
        tracing::error!(event = "item_restore_failed", error = %err, "DB error");
        ItemsError::DbError
    })?;
    if affected != 1 {
        return Err(ItemsError::Conflict("row_version_conflict"));
    }

    let change = Change {
        seq: 0,
        vault_id: vault.id,
        item_id: item.id,
        op: ChangeOp::Update,
        version: item.version,
        device_id,
        created_at: item.updated_at,
    };
    change_repo
        .create_in(&mut tx, &change)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_change_create_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    history_repo
        .prune_by_item_in(&mut tx, item.id, ITEM_HISTORY_LIMIT)
        .await
        .map_err(|err| {
            tracing::error!(event = "item_history_prune_failed", error = %err, item_id = %item.id);
            ItemsError::DbError
        })?;
    tx.commit().await.map_err(|err| {
        tracing::error!(event = "item_restore_commit_failed", error = %err, item_id = %item.id);
        ItemsError::DbError
    })?;

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
    Ok(ItemWithVault { vault, item })
}

pub(crate) fn basename_from_path(path: &str) -> String {
    crate::domains::items::contract::basename(path).to_string()
}

fn normalize_prefix(value: Option<&str>) -> Option<String> {
    let trimmed = value?.trim().trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
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

async fn service_account_allows_prefix(
    state: &AppState,
    service_account_id: Uuid,
    vault: &Vault,
    action: &str,
    prefix: Option<&str>,
) -> bool {
    let Some(scopes) = service_account_scopes(state, service_account_id).await else {
        return false;
    };
    scopes_allow_prefix(&scopes, vault, action, prefix)
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

pub(crate) fn decrypt_typed_payload(
    state: &AppState,
    vault: &Vault,
    item_id: Uuid,
    payload_enc: &[u8],
    type_id: &str,
) -> Result<EncryptedPayload, ItemsError> {
    let Some(smk) = state.server_master_key.as_ref() else {
        return Err(ItemsError::Internal("smk_missing"));
    };
    let vault_key = core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)
        .map_err(|_| ItemsError::Internal("payload_decrypt_failed"))?;
    let payload = if type_id == SECRET_TYPE_ID {
        let bytes = core_crypto::decrypt_payload_bytes(&vault_key, vault.id, item_id, payload_enc)
            .map_err(|_| ItemsError::Internal("payload_decrypt_failed"))?;
        decode_secret_payload_bytes(bytes)
            .map_err(|_| ItemsError::Internal("invalid_typed_payload"))?
    } else {
        core_crypto::decrypt_payload(&vault_key, vault.id, item_id, payload_enc)
            .map_err(|_| ItemsError::Internal("payload_decrypt_failed"))?
    };
    validate_server_typed_payload(&payload, type_id)
        .map_err(|_| ItemsError::Internal("invalid_typed_payload"))?;
    Ok(payload)
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
            return Err(ItemsError::DbError);
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
                    return Err(ItemsError::DbError);
                }
            }
        }
    }

    Ok(vault)
}
