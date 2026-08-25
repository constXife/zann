use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::fmt;
use zann_core::ChangeType;
use zann_crypto::EncryptedPayload;
use zeroize::Zeroizing;

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
    pub(crate) candidate: RotationCandidate,
    pub(crate) expires_at: Option<String>,
    pub(crate) recover_until: Option<String>,
}

/// Plaintext rotation candidates are response-scoped secrets. Debug output is
/// always redacted and the backing allocation is wiped when the response (or
/// an early-return temporary) is dropped.
pub(crate) struct RotationCandidate(Zeroizing<String>);

impl Default for RotationCandidate {
    fn default() -> Self {
        Self::new(String::new())
    }
}

impl RotationCandidate {
    pub(super) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(super) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(super) fn into_string(mut self) -> String {
        std::mem::take(&mut *self.0)
    }
}

impl fmt::Debug for RotationCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RotationCandidate(<redacted>)")
    }
}

impl Serialize for RotationCandidate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl JsonSchema for RotationCandidate {
    fn schema_name() -> String {
        "RotationCandidate".to_string()
    }

    fn json_schema(generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        String::json_schema(generator)
    }
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct RotationCommitResponse {
    pub(crate) status: &'static str,
    pub(crate) version: i64,
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
