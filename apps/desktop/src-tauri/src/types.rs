use serde::{Deserialize, Serialize};
use zann_core::EncryptedPayload;

#[derive(Serialize)]
pub struct StatusResponse {
    pub unlocked: bool,
    pub db_path: String,
}

#[derive(Serialize)]
pub struct AppStatusResponse {
    pub initialized: bool,
    pub locked: bool,
    pub storages_count: usize,
    pub has_local_vault: bool,
}

#[derive(Serialize)]
pub struct ApiError {
    pub kind: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct ApiResponse<T>
where
    T: Serialize,
{
    pub ok: bool,
    pub api_version: u32,
    pub data: Option<T>,
    pub error: Option<ApiError>,
}

impl<T> ApiResponse<T>
where
    T: Serialize,
{
    pub fn ok(data: T) -> Self {
        Self {
            ok: true,
            api_version: 1,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(kind: &str, message: &str) -> Self {
        Self {
            ok: false,
            api_version: 1,
            data: None,
            error: Some(ApiError {
                kind: kind.to_string(),
                message: message.to_string(),
            }),
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct OidcConfigResponse {
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub audience: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct OidcDiscovery {
    pub authorization_endpoint: String,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    pub token_endpoint: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub id_token: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct TokenErrorResponse {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

#[derive(Deserialize)]
pub struct OidcExchangeResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct SystemInfoResponse {
    #[serde(default)]
    pub server_id: Option<String>,
    #[serde(default)]
    pub identity: Option<SystemIdentity>,
    pub server_fingerprint: String,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default = "default_true")]
    pub personal_vaults_enabled: bool,
    #[serde(default)]
    pub auth_methods: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct SystemIdentity {
    pub public_key: String,
    pub timestamp: i64,
    pub signature: String,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
pub struct OidcLoginStartResponse {
    pub login_id: String,
    pub authorization_url: String,
}

#[derive(Serialize, Clone)]
pub struct OidcLoginStatusResponse {
    pub login_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_fingerprint: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VaultListResponse {
    pub vaults: Vec<VaultSummaryResponse>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct VaultSummaryResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub kind: String,
    pub cache_policy: String,
    pub tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VaultDetailResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub kind: String,
    pub cache_policy: String,
    pub vault_key_enc: Vec<u8>,
    pub encryption_type: String,
    pub tags: Option<Vec<String>>,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct SyncPullRequest {
    pub vault_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub limit: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncPullResponse {
    pub changes: Vec<SyncPullChange>,
    pub next_cursor: String,
    pub has_more: bool,
    pub push_available: bool,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncHistoryEntry {
    pub version: i64,
    pub checksum: String,
    pub change_type: String,
    pub changed_by_name: Option<String>,
    pub changed_by_email: String,
    pub created_at: String,
    pub payload_enc: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncPullChange {
    pub item_id: String,
    pub operation: String,
    pub seq: i64,
    pub updated_at: String,
    pub checksum: String,
    pub payload_enc: Option<Vec<u8>>,
    pub path: String,
    pub name: String,
    pub type_id: String,
    #[serde(default)]
    pub history: Vec<SyncHistoryEntry>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct SyncSharedPullResponse {
    pub changes: Vec<SyncSharedPullChange>,
    pub next_cursor: String,
    pub has_more: bool,
    pub push_available: bool,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncSharedPullChange {
    pub item_id: String,
    pub operation: String,
    pub seq: i64,
    pub updated_at: String,
    pub payload: Option<serde_json::Value>,
    pub checksum: String,
    pub path: String,
    pub name: String,
    pub type_id: String,
    #[serde(default)]
    pub history: Vec<SyncSharedHistoryEntry>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncSharedHistoryEntry {
    pub version: i64,
    pub checksum: String,
    pub change_type: String,
    pub changed_by_name: Option<String>,
    pub changed_by_email: String,
    pub created_at: String,
    pub payload: serde_json::Value,
}

#[derive(Serialize)]
pub struct SyncPushRequest {
    pub vault_id: String,
    pub changes: Vec<SyncPushChange>,
}

#[derive(Serialize)]
pub struct SyncPushChange {
    pub item_id: String,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_enc: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_seq: Option<i64>,
}

#[derive(Serialize)]
pub struct SyncSharedPushRequest {
    pub vault_id: String,
    pub changes: Vec<SyncSharedPushChange>,
}

#[derive(Serialize)]
pub struct SyncSharedPushChange {
    pub item_id: String,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_seq: Option<i64>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct SyncPushResponse {
    pub applied: Vec<String>,
    #[serde(default)]
    pub applied_changes: Vec<SyncAppliedChange>,
    pub conflicts: Vec<SyncPushConflict>,
    pub new_cursor: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct SyncAppliedChange {
    pub item_id: String,
    pub seq: i64,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct SyncPushConflict {
    pub item_id: String,
    pub reason: String,
    pub server_seq: i64,
    pub server_updated_at: String,
}

#[derive(Serialize)]
pub struct AutolockConfig {
    pub enabled: bool,
    pub minutes: u32,
}

#[derive(Serialize)]
pub struct KeystoreStatusResponse {
    pub supported: bool,
    pub biometrics_available: bool,
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct DesktopSettings {
    pub remember_unlock: bool,
    pub auto_unlock: bool,
    pub language: Option<String>,
    pub wrapped_master_key: Option<String>,
    pub biometry_dwk_backup: Option<String>,
    pub auto_lock_minutes: u32,
    pub lock_on_focus_loss: bool,
    pub lock_on_hidden: bool,
    pub clipboard_clear_seconds: u32,
    pub clipboard_clear_on_lock: bool,
    pub clipboard_clear_on_exit: bool,
    pub clipboard_clear_if_unchanged: bool,
    pub auto_hide_reveal_seconds: u32,
    pub require_os_auth: bool,
    pub trash_auto_purge_days: u32,
    pub close_to_tray: bool,
    pub close_to_tray_notice_shown: bool,
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            remember_unlock: false,
            auto_unlock: false,
            language: None,
            wrapped_master_key: None,
            biometry_dwk_backup: None,
            auto_lock_minutes: 10,
            lock_on_focus_loss: false,
            lock_on_hidden: false,
            clipboard_clear_seconds: 60,
            clipboard_clear_on_lock: true,
            clipboard_clear_on_exit: true,
            clipboard_clear_if_unchanged: true,
            auto_hide_reveal_seconds: 20,
            require_os_auth: true,
            trash_auto_purge_days: 90,
            close_to_tray: true,
            close_to_tray_notice_shown: false,
        }
    }
}

#[derive(Serialize)]
pub struct BootstrapResponse {
    pub status: StatusResponse,
    pub settings: DesktopSettings,
    pub auto_unlock_error: Option<String>,
}

#[derive(Serialize)]
pub struct VaultSummary {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub is_default: bool,
}

#[derive(Serialize)]
pub struct StorageSummary {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub server_url: Option<String>,
    pub server_name: Option<String>,
    pub account_subject: Option<String>,
    pub personal_vaults_enabled: bool,
}

#[derive(Serialize)]
pub struct StorageInfoResponse {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub file_path: Option<String>,
    pub file_size: Option<u64>,
    pub last_modified: Option<String>,
    pub server_url: Option<String>,
    pub server_name: Option<String>,
    pub account_subject: Option<String>,
    pub last_synced: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Serialize)]
pub struct ItemSummary {
    pub id: String,
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub sync_status: Option<String>,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Serialize)]
pub struct ItemDetail {
    pub id: String,
    pub vault_id: String,
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload: serde_json::Value,
}

#[derive(Serialize)]
pub struct ItemHistorySummary {
    pub version: i64,
    pub checksum: String,
    pub change_type: String,
    pub changed_by_name: Option<String>,
    pub changed_by_email: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ItemHistoryDetail {
    pub version: i64,
    pub payload: serde_json::Value,
}

#[derive(Deserialize)]
pub struct ItemsListRequest {
    pub storage_id: String,
    pub vault_id: String,
    #[serde(default)]
    pub include_deleted: bool,
}

#[derive(Deserialize)]
pub struct VaultListRequest {
    pub storage_id: String,
}

#[derive(Deserialize)]
pub struct ItemGetRequest {
    pub storage_id: String,
    pub item_id: String,
}

#[derive(Deserialize)]
pub struct ItemHistoryListRequest {
    pub storage_id: String,
    #[allow(dead_code)]
    pub vault_id: String,
    pub item_id: String,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Deserialize)]
pub struct ItemHistoryGetRequest {
    pub storage_id: String,
    pub vault_id: String,
    pub item_id: String,
    pub version: i64,
}

#[derive(Deserialize)]
pub struct ItemHistoryRestoreRequest {
    pub storage_id: String,
    #[allow(dead_code)]
    pub vault_id: String,
    pub item_id: String,
    pub version: i64,
}

#[derive(Deserialize)]
pub struct VaultCreateRequest {
    pub storage_id: String,
    pub name: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub cache_policy: Option<String>,
    #[serde(default)]
    pub is_default: Option<bool>,
}

#[derive(Deserialize)]
pub struct ItemPutRequest {
    pub storage_id: String,
    pub vault_id: String,
    pub path: String,
    pub type_id: String,
    pub payload: EncryptedPayload,
}

#[derive(Deserialize)]
pub struct ItemDeleteRequest {
    pub storage_id: String,
    pub item_id: String,
}

#[derive(Deserialize)]
pub struct ItemsEmptyTrashRequest {
    pub storage_id: String,
}

#[derive(Deserialize)]
pub struct ItemsTrashPurgeRequest {
    pub storage_id: String,
    #[serde(default)]
    pub older_than_days: Option<u32>,
}

#[derive(Deserialize)]
pub struct ItemUpdateRequest {
    pub storage_id: String,
    pub item_id: String,
    pub path: String,
    pub type_id: String,
    pub payload: EncryptedPayload,
}

#[derive(Deserialize, Serialize)]
pub struct VaultCreatePayload {
    #[serde(default)]
    pub id: Option<String>,
    pub slug: String,
    pub name: String,
    pub kind: String,
    pub cache_policy: String,
    #[serde(default)]
    pub vault_key_enc: Option<Vec<u8>>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct VaultCreateResponse {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub vault_key_enc: Vec<u8>,
}

#[derive(Serialize)]
pub struct AppVersionResponse {
    pub version: String,
    pub build: Option<String>,
}
