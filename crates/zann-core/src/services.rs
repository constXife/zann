use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::EncryptedPayload;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageKind {
    LocalOnly,
    Remote,
}

impl StorageKind {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::Remote => "remote",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceError {
    pub kind: String,
    pub message: String,
}

impl ServiceError {
    #[must_use]
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ServiceError {}

pub type ServiceResult<T> = Result<T, ServiceError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSummary {
    pub id: Uuid,
    pub name: String,
    pub kind: StorageKind,
    pub server_url: Option<String>,
    pub server_name: Option<String>,
    pub account_subject: Option<String>,
    pub personal_vaults_enabled: bool,
    pub auth_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSummary {
    pub id: Uuid,
    pub storage_id: Uuid,
    pub name: String,
    pub kind: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemPreview {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub sync_status: String,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemPreviewPage {
    pub items: Vec<ItemPreview>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ItemDetail {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload: EncryptedPayload,
    pub updated_at: DateTime<Utc>,
    pub version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStatus {
    pub initialized: bool,
    pub locked: bool,
    pub storages_count: usize,
    pub has_local_vault: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ItemListParams {
    pub query: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    pub include_deleted: bool,
}

#[async_trait]
pub trait StoragesService {
    async fn list_storages(&self) -> ServiceResult<Vec<StorageSummary>>;
    async fn get_storage(&self, storage_id: Uuid) -> ServiceResult<StorageSummary>;
    fn default_storage_id(&self) -> Uuid;
}

#[async_trait]
pub trait AppService {
    async fn status(&self, locked: bool) -> ServiceResult<AppStatus>;
    async fn initialize_master_password(&self) -> ServiceResult<()>;
}

#[async_trait]
pub trait VaultsService {
    async fn list_vaults(&self, storage_id: Uuid) -> ServiceResult<Vec<VaultSummary>>;
    async fn get_vault_by_name(
        &self,
        storage_id: Uuid,
        name: &str,
    ) -> ServiceResult<Option<VaultSummary>>;
    async fn create_vault(
        &self,
        storage_id: Uuid,
        name: &str,
        kind: &str,
        is_default: bool,
    ) -> ServiceResult<VaultSummary>;
    async fn ensure_default_local_personal(&self) -> ServiceResult<VaultSummary>;
}

#[async_trait]
pub trait ItemsService {
    async fn list_items(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        params: ItemListParams,
    ) -> ServiceResult<ItemPreviewPage>;
    async fn get_item_by_path(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        path: &str,
    ) -> ServiceResult<Option<ItemDetail>>;
    async fn get_item(&self, storage_id: Uuid, item_id: Uuid) -> ServiceResult<ItemDetail>;
    async fn put_item(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        path: String,
        type_id: String,
        payload: EncryptedPayload,
    ) -> ServiceResult<Uuid>;
    async fn delete_item(&self, storage_id: Uuid, item_id: Uuid) -> ServiceResult<()>;
}
