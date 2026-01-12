use chrono::{DateTime, Utc};
use sqlx_core::row::Row;
use sqlx_sqlite::SqliteRow;
use uuid::Uuid;
use zann_core::{AuthMethod, ChangeType, StorageKind, SyncStatus, VaultKind};

use super::KeyWrapType;

fn parse_uuid(row: &SqliteRow, column: &str) -> Result<Uuid, sqlx_core::Error> {
    match row.try_get::<String, _>(column) {
        Ok(value) => Uuid::parse_str(&value).map_err(|err| sqlx_core::Error::Decode(Box::new(err))),
        Err(_) => {
            let bytes: Vec<u8> = row.try_get(column)?;
            Uuid::from_slice(&bytes).map_err(|err| sqlx_core::Error::Decode(Box::new(err)))
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalVault {
    pub id: Uuid,
    pub storage_id: Uuid,
    pub name: String,
    pub kind: VaultKind,
    pub is_default: bool,
    pub vault_key_enc: Vec<u8>,
    pub key_wrap_type: KeyWrapType,
    pub last_synced_at: Option<i64>,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct LocalSyncCursor {
    pub storage_id: Uuid,
    pub vault_id: Uuid,
    pub cursor: Option<String>,
    pub last_sync_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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
    pub created_at: DateTime<Utc>,
}

impl sqlx_core::from_row::FromRow<'_, SqliteRow> for LocalVault {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx_core::Error> {
        let kind: i32 = row.try_get("kind")?;
        let key_wrap_type: i32 = row.try_get("key_wrap_type")?;
        Ok(Self {
            id: parse_uuid(row, "id")?,
            storage_id: parse_uuid(row, "storage_id")?,
            name: row.try_get("name")?,
            kind: VaultKind::try_from(kind)
                .map_err(|err| sqlx_core::Error::Decode(Box::new(err)))?,
            is_default: row.try_get("is_default")?,
            vault_key_enc: row.try_get("vault_key_enc")?,
            key_wrap_type: KeyWrapType::try_from(key_wrap_type)
                .map_err(|err| sqlx_core::Error::Decode(Box::new(err)))?,
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
            created_at: row.try_get("created_at")?,
        })
    }
}
