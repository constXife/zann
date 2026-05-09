use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub internal_users_present: Option<bool>,
    #[serde(default)]
    pub auth_methods: Vec<i32>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personal_vaults_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personal_key_envelopes_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personal_vault_id: Option<String>,
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
    pub kind: i32,
    pub cache_policy: i32,
    pub tags: Option<Vec<String>>,
}

#[derive(Deserialize, Clone)]
#[allow(dead_code)]
pub struct VaultDetailResponse {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub kind: i32,
    pub cache_policy: i32,
    pub vault_key_enc: Vec<u8>,
    pub encryption_type: i32,
    pub tags: Option<Vec<String>>,
    pub created_at: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PersonalVaultStatusResponse {
    pub personal_vaults_present: bool,
    pub personal_key_envelopes_present: bool,
    pub personal_vault_id: Option<String>,
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
    pub change_type: i32,
    pub changed_by_name: Option<String>,
    pub changed_by_email: String,
    pub created_at: String,
    pub payload_enc: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncPullChange {
    pub item_id: String,
    pub operation: i32,
    pub seq: i64,
    pub updated_at: String,
    pub checksum: String,
    pub payload_enc: Option<Vec<u8>>,
    pub path: String,
    pub name: String,
    pub type_id: String,
    #[serde(default)]
    pub deleted_at: Option<String>,
    #[serde(default)]
    pub history: Vec<SyncHistoryEntry>,
    #[serde(default)]
    pub shared_history: Vec<SyncSharedHistoryEntry>,
    #[serde(default)]
    pub share_cursor: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncSharedHistoryEntry {
    pub version: i64,
    pub checksum: String,
    pub change_type: i32,
    pub changed_by_name: Option<String>,
    pub changed_by_email: String,
    pub created_at: String,
    pub payload: serde_json::Value,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncSharedPullChange {
    pub item_id: String,
    pub operation: i32,
    pub seq: i64,
    pub updated_at: String,
    pub checksum: String,
    pub payload: Option<serde_json::Value>,
    pub path: String,
    pub name: String,
    pub type_id: String,
    #[serde(default)]
    pub deleted_at: Option<String>,
    #[serde(default)]
    pub history: Vec<SyncSharedHistoryEntry>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncSharedPullResponse {
    pub changes: Vec<SyncSharedPullChange>,
    pub next_cursor: String,
    pub has_more: bool,
    pub push_available: bool,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct SyncSharedPushRequest {
    pub vault_id: String,
    pub changes: Vec<SyncSharedPushChange>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncSharedPushResponse {
    pub applied: Vec<SyncAppliedChange>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncPushResponse {
    pub applied: Vec<String>,
    #[serde(default)]
    pub applied_changes: Vec<SyncAppliedChange>,
    pub conflicts: Vec<SyncPushConflict>,
    pub new_cursor: String,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct SyncPushRequest {
    pub vault_id: String,
    pub changes: Vec<SyncPushChange>,
}

#[allow(dead_code)]
#[derive(Serialize, Clone)]
pub struct SyncPushChange {
    pub item_id: String,
    pub operation: i32,
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

#[allow(dead_code)]
#[derive(Serialize, Clone)]
pub struct SyncSharedPushChange {
    pub item_id: String,
    pub operation: i32,
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

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncAppliedChange {
    pub item_id: String,
    pub seq: i64,
    pub updated_at: String,
    #[serde(default)]
    pub deleted_at: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncPushConflict {
    pub item_id: String,
    pub reason: String,
    pub server_seq: i64,
    pub server_updated_at: String,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ItemCreateRequest {
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ItemCreateResponse {
    pub item_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ItemUpdateRequest {
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ItemUpdateResponse {
    pub item_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ItemDeleteRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ItemDeleteResponse {
    pub item_id: String,
    pub updated_at: String,
    pub version: i64,
    pub deleted_at: String,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ItemRestoreRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ItemRestoreResponse {
    pub item_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ItemPurgeRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ItemPurgeResponse {
    pub item_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ShareCreateRequest {
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
    pub recipients: Vec<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ShareCreateResponse {
    pub share_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ShareUpdateRequest {
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
    pub base_version: i64,
    pub recipients: Vec<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ShareUpdateResponse {
    pub share_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ShareDeleteRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ShareDeleteResponse {
    pub share_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ShareRestoreRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ShareRestoreResponse {
    pub share_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct SharePurgeRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SharePurgeResponse {
    pub share_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Clone)]
pub struct SyncCursorResponse {
    pub vault_id: String,
    pub cursor: Option<String>,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct SyncCursorListResponse {
    pub cursors: Vec<SyncCursorResponse>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncCacheRequest {
    pub vault_id: String,
    pub cursor: Option<String>,
    pub limit: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct SyncCacheResponse {
    pub items: Vec<SyncCacheItemResponse>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Clone)]
pub struct SyncCacheItemResponse {
    pub item_id: String,
    pub updated_at: String,
    pub version: i64,
    pub checksum: String,
    pub payload_enc: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct PublicLinkListResponse {
    pub links: Vec<PublicLinkSummaryResponse>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct PublicLinkSummaryResponse {
    pub link_id: String,
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct PublicLinkCreateRequest {
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
    pub expires_at: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct PublicLinkCreateResponse {
    pub link_id: String,
    pub link_url: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct PublicLinkUpdateRequest {
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
    pub base_version: i64,
    pub expires_at: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct PublicLinkUpdateResponse {
    pub link_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct PublicLinkDeleteRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct PublicLinkDeleteResponse {
    pub link_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct PublicLinkRestoreRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct PublicLinkRestoreResponse {
    pub link_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct PublicLinkPurgeRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct PublicLinkPurgeResponse {
    pub link_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ReadonlyShareCreateRequest {
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
    pub recipients: Vec<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ReadonlyShareCreateResponse {
    pub share_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ReadonlyShareUpdateRequest {
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
    pub base_version: i64,
    pub recipients: Vec<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ReadonlyShareUpdateResponse {
    pub share_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ReadonlyShareDeleteRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ReadonlyShareDeleteResponse {
    pub share_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ReadonlyShareRestoreRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ReadonlyShareRestoreResponse {
    pub share_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ReadonlySharePurgeRequest {
    pub base_version: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ReadonlySharePurgeResponse {
    pub share_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ReadonlyShareCommitRequest {
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
    pub recipients: Vec<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ReadonlyShareCommitResponse {
    pub share_id: String,
    pub updated_at: String,
    pub version: i64,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct ServerLicenseResponse {
    pub tier: String,
    pub expiration: Option<String>,
    #[serde(default)]
    pub features: HashMap<String, bool>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Clone)]
pub struct StorageInfoResponse {
    pub storage_id: String,
    pub server_url: Option<String>,
    pub server_name: Option<String>,
    pub server_fingerprint: Option<String>,
    pub auth_method: Option<String>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct StorageUpdateRequest {
    pub name: Option<String>,
    pub server_url: Option<String>,
    pub server_fingerprint: Option<String>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct StorageUpdateResponse {
    pub storage_id: String,
    pub server_url: Option<String>,
    pub server_fingerprint: Option<String>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct StorageCacheClearRequest {
    pub storage_id: String,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct StorageCacheClearResponse {
    pub storage_id: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct AuthRefreshResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct SessionLoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct OidcLoginRequest {
    pub token: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct OidcLoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct OidcStatusResponse {
    pub status: String,
    pub message: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthMethodResponse {
    pub auth_methods: Vec<i32>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SaltUpdateResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecurityProfileResponse {
    pub profile_id: String,
    pub kdf_params: zann_core::api::auth::KdfParams,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecurityProfilesResponse {
    pub profiles: Vec<SecurityProfileResponse>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserProfileResponse {
    pub email: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemInfoResponseV2 {
    pub server_id: String,
    pub version: String,
    pub component_status: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileResponse {
    pub filename: String,
    pub content_type: String,
    pub contents: Vec<u8>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct RemoteItemHistoryEntry {
    pub version: i64,
    pub checksum: String,
    pub change_type: i32,
    pub updated_at: String,
    pub deleted_at: Option<String>,
    pub payload_enc: Option<Vec<u8>>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct RemoteItemHistoryResponse {
    pub item_id: String,
    pub history: Vec<RemoteItemHistoryEntry>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct RemoteItemShareHistoryResponse {
    pub share_id: String,
    pub history: Vec<RemoteItemHistoryEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BlobUploadResponse {
    pub blob_id: String,
    pub sha256: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct FeatureUsageResponse {
    pub used_mb: i64,
    pub limit_mb: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InviteTokenResponse {
    pub token: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OidcDeviceStatusResponse {
    pub status: String,
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OidcDeviceStartResponse {
    pub device_code: String,
    pub verification_uri: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OidcDeviceTokenResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub id_token: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicShareSummaryResponse {
    pub share_id: String,
    pub share_url: String,
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicShareListResponse {
    pub shares: Vec<PublicShareSummaryResponse>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicShareListRequest {
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicShareCreateRequest {
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
    pub expires_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicShareUpdateRequest {
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub payload_enc: Vec<u8>,
    pub base_version: i64,
    pub expires_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicShareDeleteRequest {
    pub base_version: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicShareRestoreRequest {
    pub base_version: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicSharePurgeRequest {
    pub base_version: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionStatusResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionRotateResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerStatusResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerStatusComponentsResponse {
    pub components: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthMethodsResponse {
    pub auth_methods: Vec<i32>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HistoryEntryResponse {
    pub version: i64,
    pub checksum: String,
    pub change_type: i32,
    pub updated_at: String,
    pub deleted_at: Option<String>,
    pub payload_enc: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HistoryResponse {
    pub history: Vec<HistoryEntryResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserSummaryResponse {
    pub user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserListResponse {
    pub users: Vec<UserSummaryResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServiceAccountResponse {
    pub service_account_id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServiceAccountListResponse {
    pub service_accounts: Vec<ServiceAccountResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TokenResponseApi {
    pub token_id: String,
    pub token: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TokenListResponse {
    pub tokens: Vec<TokenResponseApi>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TokenRevokeResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceInfoResponse {
    pub device_id: String,
    pub name: String,
    pub device_type: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceInfoResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceDeleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupResponse {
    pub group_id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupListResponse {
    pub groups: Vec<GroupResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupDeleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupMemberResponse {
    pub group_id: String,
    pub user_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupMemberListResponse {
    pub members: Vec<GroupMemberResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupMemberDeleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupMappingResponse {
    pub mapping_id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupMappingListResponse {
    pub mappings: Vec<GroupMappingResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupMappingDeleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupMappingUserResponse {
    pub mapping_id: String,
    pub user_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupMappingUserListResponse {
    pub users: Vec<GroupMappingUserResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupMappingUserDeleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthProviderResponse {
    pub provider_id: String,
    pub name: String,
    pub provider_type: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthProviderListResponse {
    pub providers: Vec<AuthProviderResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthProviderDeleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemConfigResponse {
    pub config: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemConfigUpdateRequest {
    pub config: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemLogsResponse {
    pub filename: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemLogsListResponse {
    pub logs: Vec<SystemLogsResponse>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemSettingsResponse {
    pub settings: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemSettingsUpdateRequest {
    pub settings: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ApiResponseData<T> {
    pub status: String,
    pub data: T,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ApiResponsePage<T> {
    pub status: String,
    pub data: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VersionResponse {
    pub version: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ItemDetailResponse {
    pub item_id: String,
    pub path: String,
    pub name: String,
    pub type_id: String,
    pub updated_at: String,
    pub version: i64,
    pub payload_enc: Vec<u8>,
    pub deleted_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SearchResponse {
    pub results: Vec<ItemDetailResponse>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentUploadResponse {
    pub attachment_id: String,
    pub upload_url: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentCompleteResponse {
    pub attachment_id: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentUploadStatusResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentResponse {
    pub attachment_id: String,
    pub name: String,
    pub size: i64,
    pub content_type: String,
    pub checksum: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentListResponse {
    pub attachments: Vec<AttachmentResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentDownloadResponse {
    pub attachment_id: String,
    pub download_url: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentMetadataResponse {
    pub attachment_id: String,
    pub name: String,
    pub size: i64,
    pub content_type: String,
    pub checksum: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentDeleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentRenameResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentRenameRequest {
    pub attachment_id: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogEntryResponse {
    pub log_id: String,
    pub event: String,
    pub created_at: String,
    pub actor: Option<String>,
    pub actor_type: String,
    pub metadata: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogResponse {
    pub logs: Vec<AuditLogEntryResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogQuery {
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportResponse {
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportStatusResponse {
    pub status: String,
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportStartResponse {
    pub status: String,
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportStatusRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportStartRequest {
    pub query: AuditLogQuery,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportStartStatusResponse {
    pub status: String,
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportStartStatusRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportUploadResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportUploadRequest {
    pub export_id: String,
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportUploadStatusResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportUploadStatusRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportCompleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportCompleteRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportCompleteStatusResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportCompleteStatusRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportListResponse {
    pub exports: Vec<AuditLogExportStartResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogExportListRequest {
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditLogResponseV2 {
    pub logs: Vec<AuditLogEntryResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncCacheRequestV2 {
    pub vault_id: String,
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncCacheResponseV2 {
    pub items: Vec<SyncCacheItemResponse>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncChangeDetail {
    pub item_id: String,
    pub updated_at: String,
    pub version: i64,
    pub checksum: String,
    pub payload_enc: Vec<u8>,
    pub deleted_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncChangeDetailListResponse {
    pub items: Vec<SyncChangeDetail>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncChangeDetailListRequest {
    pub item_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncChangeSummary {
    pub item_id: String,
    pub updated_at: String,
    pub version: i64,
    pub checksum: String,
    pub deleted_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncChangeSummaryListResponse {
    pub items: Vec<SyncChangeSummary>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncChangeSummaryListRequest {
    pub item_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncCursorRequest {
    pub cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncCursorUpdateRequest {
    pub cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncCursorUpdateResponse {
    pub cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncCursorListRequest {
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncCursorListResponseV2 {
    pub cursors: Vec<SyncCursorResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncCursorListResponseV3 {
    pub cursors: Vec<SyncCursorResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageDeleteResponse {
    pub storage_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageDeleteRequest {
    pub also_delete_data: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageDisconnectRequest {
    pub storage_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageDisconnectResponse {
    pub storage_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageSignOutResponse {
    pub storage_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageSignOutRequest {
    pub storage_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageListResponse {
    pub storages: Vec<StorageInfoResponse>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SettingsResponse {
    pub settings: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SettingsUpdateRequest {
    pub settings: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SettingsUpdateResponse {
    pub settings: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BackupSettingsResponse {
    pub settings: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BackupSettingsUpdateRequest {
    pub settings: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BackupSettingsUpdateResponse {
    pub settings: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BackupStatusResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BackupStatusResponseV2 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VersionResponseV2 {
    pub version: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OidcUserResponse {
    pub email: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerConfigResponse {
    pub config: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerConfigUpdateRequest {
    pub config: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageQuotaResponse {
    pub used: i64,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageQuotaHistoryResponse {
    pub days: Vec<StorageQuotaHistoryEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageQuotaHistoryEntry {
    pub date: String,
    pub used: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageQuotaHistoryRequest {
    pub days: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemInfoLogResponse {
    pub log_id: String,
    pub created_at: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemInfoLogListResponse {
    pub logs: Vec<SystemInfoLogResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemInfoLogQuery {
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServiceAccountTokenResponse {
    pub token_id: String,
    pub token: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServiceAccountTokenListResponse {
    pub tokens: Vec<ServiceAccountTokenResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServiceAccountTokenListRequest {
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServiceAccountTokenRevokeResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServiceAccountTokenRevokeRequest {
    pub token_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentSummaryResponse {
    pub attachment_id: String,
    pub name: String,
    pub size: i64,
    pub content_type: String,
    pub checksum: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentSummaryListResponse {
    pub attachments: Vec<AttachmentSummaryResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttachmentSummaryListRequest {
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileUploadResponse {
    pub file_id: String,
    pub upload_url: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileUploadStatusResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileUploadCompleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileUploadCompleteRequest {
    pub file_id: String,
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileUploadCompleteStatusResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileUploadCompleteStatusRequest {
    pub file_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResponse {
    pub status: String,
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStartRequest {
    pub options: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStartResponse {
    pub status: String,
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusListResponse {
    pub exports: Vec<ExportStartResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusListRequest {
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusListResponseV2 {
    pub exports: Vec<ExportStartResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusListResponseV3 {
    pub exports: Vec<ExportStartResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusStartResponse {
    pub status: String,
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusStartRequest {
    pub query: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusStartResponseV2 {
    pub status: String,
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusStartResponseV3 {
    pub status: String,
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusStartRequestV2 {
    pub query: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusStartRequestV3 {
    pub query: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusUploadResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusUploadRequest {
    pub export_id: String,
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusUploadResponseV2 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusUploadRequestV2 {
    pub export_id: String,
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusUploadResponseV3 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusUploadRequestV3 {
    pub export_id: String,
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteStatusResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteStatusRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteResponseV2 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteRequestV2 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteStatusResponseV2 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteStatusRequestV2 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteResponseV3 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteRequestV3 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteStatusResponseV3 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusCompleteStatusRequestV3 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResultResponse {
    pub status: String,
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResultRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResultResponseV2 {
    pub status: String,
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResultRequestV2 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResultResponseV3 {
    pub status: String,
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResultRequestV3 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResumeResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResumeRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResumeResponseV2 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResumeRequestV2 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResumeResponseV3 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusResumeRequestV3 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusAbortResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusAbortRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusAbortResponseV2 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusAbortRequestV2 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusAbortResponseV3 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusAbortRequestV3 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusDeleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusDeleteRequest {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusDeleteResponseV2 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusDeleteRequestV2 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusDeleteResponseV3 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportStatusDeleteRequestV3 {
    pub export_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditEventResponse {
    pub event: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditEventListResponse {
    pub events: Vec<AuditEventResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditEventListRequest {
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStartRequest {
    pub options: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStartResponse {
    pub status: String,
    pub import_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusRequest {
    pub import_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusListResponse {
    pub imports: Vec<ImportStartResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusListRequest {
    pub cursor: Option<String>,
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusResumeResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusResumeRequest {
    pub import_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusAbortResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusAbortRequest {
    pub import_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusDeleteResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusDeleteRequest {
    pub import_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusDeleteResponseV2 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusDeleteRequestV2 {
    pub import_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusDeleteResponseV3 {
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusDeleteRequestV3 {
    pub import_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusResultResponse {
    pub status: String,
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusResultRequest {
    pub import_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusResultResponseV2 {
    pub status: String,
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusResultRequestV2 {
    pub import_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusResultResponseV3 {
    pub status: String,
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ImportStatusResultRequestV3 {
    pub import_id: String,
}
