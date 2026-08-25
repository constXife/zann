use chrono::{DateTime, Utc};
use sqlx_core::row::Row;
use sqlx_sqlite::SqliteRow;
use uuid::Uuid;
use zann_core::{AuthMethod, ChangeType, StorageKind, SyncStatus, VaultKind};

use super::KeyWrapType;

#[derive(Debug)]
pub struct LocalEnumError(&'static str);

impl std::fmt::Display for LocalEnumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for LocalEnumError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistorySource {
    Local = 1,
    Server = 2,
    UiOptimistic = 3,
}

impl HistorySource {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for HistorySource {
    type Error = LocalEnumError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Local),
            2 => Ok(Self::Server),
            3 => Ok(Self::UiOptimistic),
            _ => Err(LocalEnumError("invalid history source")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistorySyncStatus {
    Pending = 1,
    Confirmed = 2,
    Rejected = 3,
}

impl HistorySyncStatus {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for HistorySyncStatus {
    type Error = LocalEnumError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Confirmed),
            3 => Ok(Self::Rejected),
            _ => Err(LocalEnumError("invalid history sync status")),
        }
    }
}

fn parse_uuid(row: &SqliteRow, column: &str) -> Result<Uuid, sqlx_core::Error> {
    match row.try_get::<String, _>(column) {
        Ok(value) => Uuid::parse_str(&value).map_err(|err| sqlx_core::Error::Decode(Box::new(err))),
        Err(_) => {
            let bytes: Vec<u8> = row.try_get(column)?;
            Uuid::from_slice(&bytes).map_err(|err| sqlx_core::Error::Decode(Box::new(err)))
        }
    }
}

#[derive(Clone)]
pub struct LocalVault {
    pub id: Uuid,
    pub storage_id: Uuid,
    pub slug: String,
    pub name: String,
    pub kind: VaultKind,
    pub is_default: bool,
    pub vault_key_enc: Vec<u8>,
    pub key_wrap_type: KeyWrapType,
    pub cache_key_fp: Option<String>,
    pub last_synced_at: Option<i64>,
}

impl LocalVault {
    /// Returns the deterministic identity assigned to vaults that predate or
    /// do not originate from a remote server catalog.
    pub fn local_slug(id: Uuid) -> String {
        format!("local::{}", id.simple())
    }
}

#[derive(Clone)]
pub struct LocalItem {
    pub id: Uuid,
    pub storage_id: Uuid,
    pub vault_id: Uuid,
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
    pub checksum: String,
    pub cache_key_fp: Option<String>,
    pub version: i64,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub sync_status: SyncStatus,
}

#[derive(Clone)]
pub struct LocalSyncCursor {
    pub storage_id: Uuid,
    pub vault_id: Uuid,
    pub cursor: Option<String>,
    pub last_sync_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct LocalSyncCheckpoint {
    pub storage_id: Uuid,
    pub vault_id: Uuid,
    pub cursor: Option<String>,
    pub last_seq: Option<i64>,
    pub last_sync_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct LocalPendingChange {
    pub id: Uuid,
    pub storage_id: Uuid,
    pub vault_id: Uuid,
    pub item_id: Uuid,
    pub operation: ChangeType,
    pub payload_enc: Option<Vec<u8>>,
    pub checksum: Option<String>,
    pub path: Option<String>,
    pub name: Option<String>,
    pub type_id: Option<String>,
    pub base_seq: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct LocalStorage {
    pub id: Uuid,
    pub kind: StorageKind,
    pub name: String,
    pub server_url: Option<String>,
    pub server_name: Option<String>,
    pub server_fingerprint: Option<String>,
    pub account_subject: Option<String>,
    pub personal_vaults_enabled: bool,
    pub auth_method: Option<AuthMethod>,
}

#[derive(Clone)]
pub struct LocalItemHistory {
    pub id: Uuid,
    pub storage_id: Uuid,
    pub vault_id: Uuid,
    pub item_id: Uuid,
    pub payload_enc: Vec<u8>,
    pub checksum: String,
    pub version: i64,
    pub change_type: ChangeType,
    pub changed_by_email: String,
    pub changed_by_name: Option<String>,
    pub changed_by_device_id: Option<Uuid>,
    pub changed_by_device_name: Option<String>,
    pub source: HistorySource,
    pub sync_status: HistorySyncStatus,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for LocalVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalVault")
            .field("id", &self.id)
            .field("storage_id", &self.storage_id)
            .field("slug", &"<redacted>")
            .field("name", &"<redacted>")
            .field("kind", &self.kind)
            .field("is_default", &self.is_default)
            .field("vault_key_enc_bytes", &self.vault_key_enc.len())
            .field("key_wrap_type", &self.key_wrap_type)
            .field(
                "cache_key_fp",
                &self.cache_key_fp.as_ref().map(|_| "<redacted>"),
            )
            .field("last_synced_at", &self.last_synced_at)
            .finish()
    }
}

impl std::fmt::Debug for LocalItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalItem")
            .field("id", &self.id)
            .field("storage_id", &self.storage_id)
            .field("vault_id", &self.vault_id)
            .field("path", &"<redacted>")
            .field("name", &"<redacted>")
            .field("type_id", &self.type_id)
            .field("payload_enc_bytes", &self.payload_enc.len())
            .field("checksum", &"<redacted>")
            .field(
                "cache_key_fp",
                &self.cache_key_fp.as_ref().map(|_| "<redacted>"),
            )
            .field("version", &self.version)
            .field("deleted", &self.deleted_at.is_some())
            .field("updated_at", &self.updated_at)
            .field("sync_status", &self.sync_status)
            .finish()
    }
}

impl std::fmt::Debug for LocalSyncCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalSyncCursor")
            .field("storage_id", &self.storage_id)
            .field("vault_id", &self.vault_id)
            .field("cursor_bytes", &self.cursor.as_ref().map(String::len))
            .field("last_sync_at", &self.last_sync_at)
            .finish()
    }
}

impl std::fmt::Debug for LocalSyncCheckpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalSyncCheckpoint")
            .field("storage_id", &self.storage_id)
            .field("vault_id", &self.vault_id)
            .field("cursor_bytes", &self.cursor.as_ref().map(String::len))
            .field("last_seq", &self.last_seq)
            .field("last_sync_at", &self.last_sync_at)
            .finish()
    }
}

impl std::fmt::Debug for LocalPendingChange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalPendingChange")
            .field("id", &self.id)
            .field("storage_id", &self.storage_id)
            .field("vault_id", &self.vault_id)
            .field("item_id", &self.item_id)
            .field("operation", &self.operation)
            .field(
                "payload_enc_bytes",
                &self.payload_enc.as_ref().map(Vec::len),
            )
            .field("checksum", &self.checksum.as_ref().map(|_| "<redacted>"))
            .field("path", &self.path.as_ref().map(|_| "<redacted>"))
            .field("name", &self.name.as_ref().map(|_| "<redacted>"))
            .field("type_id", &self.type_id)
            .field("base_seq", &self.base_seq)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl std::fmt::Debug for LocalStorage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalStorage")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("name", &"<redacted>")
            .field(
                "server_url",
                &self.server_url.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "server_name",
                &self.server_name.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "server_fingerprint",
                &self.server_fingerprint.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "account_subject",
                &self.account_subject.as_ref().map(|_| "<redacted>"),
            )
            .field("personal_vaults_enabled", &self.personal_vaults_enabled)
            .field("auth_method", &self.auth_method)
            .finish()
    }
}

impl std::fmt::Debug for LocalItemHistory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalItemHistory")
            .field("id", &self.id)
            .field("storage_id", &self.storage_id)
            .field("vault_id", &self.vault_id)
            .field("item_id", &self.item_id)
            .field("payload_enc_bytes", &self.payload_enc.len())
            .field("checksum", &"<redacted>")
            .field("version", &self.version)
            .field("change_type", &self.change_type)
            .field("changed_by_email", &"<redacted>")
            .field(
                "changed_by_name",
                &self.changed_by_name.as_ref().map(|_| "<redacted>"),
            )
            .field("changed_by_device_id", &self.changed_by_device_id)
            .field(
                "changed_by_device_name",
                &self.changed_by_device_name.as_ref().map(|_| "<redacted>"),
            )
            .field("source", &self.source)
            .field("sync_status", &self.sync_status)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl sqlx_core::from_row::FromRow<'_, SqliteRow> for LocalVault {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx_core::Error> {
        let kind: i32 = row.try_get("kind")?;
        let key_wrap_type: i32 = row.try_get("key_wrap_type")?;
        Ok(Self {
            id: parse_uuid(row, "id")?,
            storage_id: parse_uuid(row, "storage_id")?,
            slug: row.try_get("slug")?,
            name: row.try_get("name")?,
            kind: VaultKind::try_from(kind)
                .map_err(|err| sqlx_core::Error::Decode(Box::new(err)))?,
            is_default: row.try_get("is_default")?,
            vault_key_enc: row.try_get("vault_key_enc")?,
            key_wrap_type: KeyWrapType::try_from(key_wrap_type)
                .map_err(|err| sqlx_core::Error::Decode(Box::new(err)))?,
            cache_key_fp: row.try_get("cache_key_fp")?,
            last_synced_at: row.try_get("last_synced_at")?,
        })
    }
}

impl sqlx_core::from_row::FromRow<'_, SqliteRow> for LocalStorage {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx_core::Error> {
        let kind: i32 = row.try_get("kind")?;
        let auth_method: Option<i32> = row.try_get("auth_method")?;
        Ok(Self {
            id: parse_uuid(row, "id")?,
            kind: StorageKind::try_from(kind)
                .map_err(|err| sqlx_core::Error::Decode(Box::new(err)))?,
            name: row.try_get("name")?,
            server_url: row.try_get("server_url")?,
            server_name: row.try_get("server_name")?,
            server_fingerprint: row.try_get("server_fingerprint")?,
            account_subject: row.try_get("account_subject")?,
            personal_vaults_enabled: row
                .try_get::<bool, _>("personal_vaults_enabled")
                .unwrap_or(true),
            auth_method: auth_method
                .map(AuthMethod::try_from)
                .transpose()
                .map_err(|err| sqlx_core::Error::Decode(Box::new(err)))?,
        })
    }
}

impl sqlx_core::from_row::FromRow<'_, SqliteRow> for LocalItem {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx_core::Error> {
        let sync_status: i32 = row.try_get("sync_status")?;
        Ok(Self {
            id: parse_uuid(row, "id")?,
            storage_id: parse_uuid(row, "storage_id")?,
            vault_id: parse_uuid(row, "vault_id")?,
            path: row.try_get("path")?,
            name: row.try_get("name")?,
            type_id: row.try_get("type_id")?,
            payload_enc: row.try_get("payload_enc")?,
            checksum: row.try_get("checksum")?,
            cache_key_fp: row.try_get("cache_key_fp")?,
            version: row.try_get("version")?,
            deleted_at: row.try_get("deleted_at")?,
            updated_at: row.try_get("updated_at")?,
            sync_status: SyncStatus::try_from(sync_status)
                .map_err(|err| sqlx_core::Error::Decode(Box::new(err)))?,
        })
    }
}

impl sqlx_core::from_row::FromRow<'_, SqliteRow> for LocalSyncCursor {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx_core::Error> {
        Ok(Self {
            storage_id: parse_uuid(row, "storage_id")?,
            vault_id: parse_uuid(row, "vault_id")?,
            cursor: row.try_get("cursor")?,
            last_sync_at: row.try_get("last_sync_at")?,
        })
    }
}

impl sqlx_core::from_row::FromRow<'_, SqliteRow> for LocalSyncCheckpoint {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx_core::Error> {
        Ok(Self {
            storage_id: parse_uuid(row, "storage_id")?,
            vault_id: parse_uuid(row, "vault_id")?,
            cursor: row.try_get("cursor")?,
            last_seq: row.try_get("last_seq")?,
            last_sync_at: row.try_get("last_sync_at")?,
        })
    }
}

impl sqlx_core::from_row::FromRow<'_, SqliteRow> for LocalPendingChange {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx_core::Error> {
        let operation: i32 = row.try_get("operation")?;
        Ok(Self {
            id: parse_uuid(row, "id")?,
            storage_id: parse_uuid(row, "storage_id")?,
            vault_id: parse_uuid(row, "vault_id")?,
            item_id: parse_uuid(row, "item_id")?,
            operation: ChangeType::try_from(operation)
                .map_err(|err| sqlx_core::Error::Decode(Box::new(err)))?,
            payload_enc: row.try_get("payload_enc")?,
            checksum: row.try_get("checksum")?,
            path: row.try_get("path")?,
            name: row.try_get("name")?,
            type_id: row.try_get("type_id")?,
            base_seq: row.try_get("base_seq")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

impl sqlx_core::from_row::FromRow<'_, SqliteRow> for LocalItemHistory {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx_core::Error> {
        let change_type: i32 = row.try_get("change_type")?;
        let source: i32 = row.try_get("source")?;
        let sync_status: i32 = row.try_get("sync_status")?;
        Ok(Self {
            id: parse_uuid(row, "id")?,
            storage_id: parse_uuid(row, "storage_id")?,
            vault_id: parse_uuid(row, "vault_id")?,
            item_id: parse_uuid(row, "item_id")?,
            payload_enc: row.try_get("payload_enc")?,
            checksum: row.try_get("checksum")?,
            version: row.try_get("version")?,
            change_type: ChangeType::try_from(change_type)
                .map_err(|err| sqlx_core::Error::Decode(Box::new(err)))?,
            changed_by_email: row.try_get("changed_by_email")?,
            changed_by_name: row.try_get("changed_by_name")?,
            changed_by_device_id: row.try_get("changed_by_device_id")?,
            changed_by_device_name: row.try_get("changed_by_device_name")?,
            source: HistorySource::try_from(source)
                .map_err(|err| sqlx_core::Error::Decode(Box::new(err)))?,
            sync_status: HistorySyncStatus::try_from(sync_status)
                .map_err(|err| sqlx_core::Error::Decode(Box::new(err)))?,
            created_at: row.try_get("created_at")?,
        })
    }
}
