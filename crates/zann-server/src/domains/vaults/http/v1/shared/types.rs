use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
pub(crate) use zann_core::api::secrets::{
    RotateAbortRequest, RotateStartRequest, RotationCandidate, RotationCandidateResponse,
    RotationCommitResponse, RotationStatusResponse,
};
use zann_core::ChangeType;
use zann_crypto::EncryptedPayload;

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
    #[schemars(with = "JsonValue")]
    pub(crate) payload: EncryptedPayload,
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
    #[schemars(with = "JsonValue")]
    pub(crate) payload: EncryptedPayload,
    pub(crate) change_type: ChangeType,
    pub(crate) created_at: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct CreateSharedItemRequest {
    pub(crate) vault_id: String,
    pub(crate) path: String,
    pub(crate) type_id: String,
    #[serde(default)]
    pub(crate) tags: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) favorite: Option<bool>,
    #[schemars(with = "JsonValue")]
    pub(crate) payload: EncryptedPayload,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct UpdateSharedItemRequest {
    #[serde(default)]
    pub(crate) path: Option<String>,
    #[serde(default)]
    pub(crate) type_id: Option<String>,
    #[serde(default)]
    pub(crate) tags: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) favorite: Option<bool>,
    #[schemars(with = "JsonValue")]
    pub(crate) payload: EncryptedPayload,
}

#[cfg(test)]
mod tests {
    use super::RotationCandidate;

    #[test]
    fn rotation_candidate_debug_is_redacted_while_wire_value_is_preserved() {
        let candidate = RotationCandidate::new("candidate-secret".to_string());
        let debug = format!("{candidate:?}");
        assert!(!debug.contains("candidate-secret"));
        assert_eq!(
            serde_json::to_string(&candidate).expect("serialize candidate"),
            "\"candidate-secret\""
        );
    }
}
