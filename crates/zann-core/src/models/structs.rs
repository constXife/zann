use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx_core::types::Json;
use uuid::Uuid;

use super::enums::{
    CachePolicy, ChangeOp, ChangeType, SyncStatus, UserStatus, VaultEncryptionType, VaultKind,
    VaultMemberRole,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub full_name: Option<String>,
    pub password_hash: Option<String>,
    pub kdf_salt: String,
    pub kdf_algorithm: String,
    pub kdf_iterations: i64,
    pub kdf_memory_kb: i64,
    pub kdf_parallelism: i64,
    pub recovery_key_hash: Option<String>,
    pub status: UserStatus,
    pub deleted_at: Option<DateTime<Utc>>,
    pub deleted_by_user_id: Option<Uuid>,
    pub deleted_by_device_id: Option<Uuid>,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub group_id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcGroupMapping {
    pub id: Uuid,
    pub issuer: String,
    pub oidc_group: String,
    pub internal_group_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub fingerprint: String,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub app_version: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub last_ip: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub token_hash: String,
    pub token_prefix: String,
    pub scopes: Json<Vec<String>>,
    pub allowed_ips: Option<Json<Vec<String>>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_used_ip: Option<String>,
    pub last_used_user_agent: Option<String>,
    pub use_count: i64,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccountSession {
    pub id: Uuid,
    pub service_account_id: Uuid,
    pub access_token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub access_token_hash: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub kind: VaultKind,
    pub encryption_type: VaultEncryptionType,
    pub vault_key_enc: Vec<u8>,
    pub cache_policy: CachePolicy,
    pub tags: Option<Json<Vec<String>>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub deleted_by_user_id: Option<Uuid>,
    pub deleted_by_device_id: Option<Uuid>,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMember {
    pub vault_id: Uuid,
    pub user_id: Uuid,
    pub role: VaultMemberRole,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub tags: Option<Json<Vec<String>>>,
    pub favorite: bool,
    pub payload_enc: Vec<u8>,
    pub checksum: String,
    pub version: i64,
    pub row_version: i64,
    pub device_id: Uuid,
    pub sync_status: SyncStatus,
    pub deleted_at: Option<DateTime<Utc>>,
    pub deleted_by_user_id: Option<Uuid>,
    pub deleted_by_device_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemUsage {
    pub item_id: Uuid,
    pub last_read_at: DateTime<Utc>,
    pub last_read_by_user_id: Option<Uuid>,
    pub last_read_by_device_id: Option<Uuid>,
    pub read_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FieldsChanged {
    pub user_fields: Vec<String>,
    pub system_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemHistory {
    pub id: Uuid,
    pub item_id: Uuid,
    pub payload_enc: Vec<u8>,
    pub checksum: String,
    pub version: i64,
    pub change_type: ChangeType,
    pub fields_changed: Option<Json<FieldsChanged>>,
    pub changed_by_user_id: Uuid,
    pub changed_by_email: String,
    pub changed_by_name: Option<String>,
    pub changed_by_device_id: Option<Uuid>,
    pub changed_by_device_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: Uuid,
    pub item_id: Uuid,
    pub filename: String,
    pub size: i64,
    pub mime_type: String,
    pub enc_mode: String,
    pub content_enc: Vec<u8>,
    pub checksum: String,
    pub storage_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub seq: i64,
    pub vault_id: Uuid,
    pub item_id: Uuid,
    pub op: ChangeOp,
    pub version: i64,
    pub device_id: Uuid,
    pub created_at: DateTime<Utc>,
}
