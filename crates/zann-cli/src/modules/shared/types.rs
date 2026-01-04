use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zann_core::EncryptedPayload;

#[derive(Serialize)]
pub struct RotateStartRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

#[derive(Serialize)]
pub struct RotateAbortRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub force: bool,
}

#[derive(Deserialize, Serialize)]
pub struct RotationStatusResponse {
    pub state: String,
    pub started_at: Option<String>,
    pub started_by: Option<String>,
    pub expires_at: Option<String>,
    pub recover_until: Option<String>,
    pub aborted_reason: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct RotationCandidateResponse {
    pub state: String,
    pub candidate: String,
    pub expires_at: Option<String>,
    pub recover_until: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct RotationCommitResponse {
    pub status: String,
    pub version: i64,
}

#[derive(Deserialize)]
pub struct VaultListResponse {
    pub vaults: Vec<VaultSummaryResponse>,
}

#[derive(Deserialize)]
pub struct VaultSummaryResponse {
    pub id: String,
}

#[derive(Deserialize, Serialize)]
pub struct SharedItemsResponse {
    pub items: Vec<SharedItemResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct SharedItemResponse {
    pub id: String,
    pub path: String,
    pub payload: EncryptedPayload,
}

#[derive(Deserialize, Serialize)]
pub struct SharedHistoryListResponse {
    pub versions: Vec<SharedHistorySummary>,
}

#[derive(Deserialize, Serialize)]
pub struct SharedHistorySummary {
    pub version: i64,
    pub created_at: String,
    pub changed_by_name: Option<String>,
    pub changed_by_email: String,
}

#[derive(Serialize)]
pub struct SharedListJsonItem {
    pub path: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct SharedListJsonResponse {
    pub items: Vec<SharedListJsonItem>,
    pub next_cursor: Option<String>,
}
