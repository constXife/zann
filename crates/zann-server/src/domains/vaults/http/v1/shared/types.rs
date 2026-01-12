use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use zann_core::ChangeType;

#[derive(Serialize, JsonSchema)]
pub(crate) struct ErrorResponse {
    pub(crate) error: &'static str,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SharedItemsResponse {
    pub(crate) items: Vec<SharedItemResponse>,
    pub(crate) next_cursor: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SharedItemResponse {
    pub(crate) id: String,
    pub(crate) vault_id: String,
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) type_id: String,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) favorite: bool,
    pub(crate) payload: JsonValue,
    pub(crate) checksum: String,
    pub(crate) version: i64,
    pub(crate) deleted_at: Option<String>,
    pub(crate) updated_at: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SharedItemsQuery {
    pub(crate) vault_id: String,
    #[serde(default)]
    pub(crate) prefix: Option<String>,
    #[serde(default)]
    pub(crate) limit: Option<i64>,
    #[serde(default)]
    pub(crate) cursor: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct HistoryListQuery {
    pub(crate) limit: Option<i64>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ItemHistorySummary {
    pub(crate) version: i64,
    pub(crate) checksum: String,
    pub(crate) change_type: ChangeType,
    pub(crate) changed_by_name: Option<String>,
    pub(crate) changed_by_email: String,
    pub(crate) created_at: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ItemHistoryListResponse {
    pub(crate) versions: Vec<ItemHistorySummary>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ItemHistoryDetailResponse {
    pub(crate) version: i64,
    pub(crate) checksum: String,
    pub(crate) payload: JsonValue,
    pub(crate) change_type: ChangeType,
    pub(crate) created_at: String,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct RotateStartRequest {
    #[serde(default)]
    pub(crate) policy: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct RotateAbortRequest {
    #[serde(default)]
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) force: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct RotationStatusResponse {
    pub(crate) state: String,
    pub(crate) started_at: Option<String>,
    pub(crate) started_by: Option<String>,
    pub(crate) expires_at: Option<String>,
    pub(crate) recover_until: Option<String>,
    pub(crate) aborted_reason: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct RotationCandidateResponse {
    pub(crate) state: String,
    pub(crate) candidate: String,
    pub(crate) expires_at: Option<String>,
    pub(crate) recover_until: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct RotationCommitResponse {
    pub(crate) status: &'static str,
    pub(crate) version: i64,
}
