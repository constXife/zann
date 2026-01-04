use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ErrorResponse {
    pub(crate) error: &'static str,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct SyncPullRequest {
    pub(crate) vault_id: Uuid,
    pub(crate) cursor: Option<String>,
    #[serde(default = "crate::domains::sync::http::v1::helpers::default_sync_limit")]
    pub(crate) limit: i64,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct SyncSharedPullRequest {
    pub(crate) vault_id: Uuid,
    pub(crate) cursor: Option<String>,
    #[serde(default = "crate::domains::sync::http::v1::helpers::default_sync_limit")]
    pub(crate) limit: i64,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SyncPullResponse {
    pub(crate) changes: Vec<SyncPullChange>,
    pub(crate) next_cursor: String,
    pub(crate) has_more: bool,
    pub(crate) push_available: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SyncSharedPullResponse {
    pub(crate) changes: Vec<SyncSharedPullChange>,
    pub(crate) next_cursor: String,
    pub(crate) has_more: bool,
    pub(crate) push_available: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SyncPullChange {
    pub(crate) item_id: String,
    pub(crate) operation: String,
    pub(crate) seq: i64,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) checksum: String,
    pub(crate) payload_enc: Option<Vec<u8>>,
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) type_id: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SyncSharedPullChange {
    pub(crate) item_id: String,
    pub(crate) operation: String,
    pub(crate) seq: i64,
    pub(crate) updated_at: String,
    pub(crate) payload: Option<JsonValue>,
    pub(crate) checksum: String,
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) type_id: String,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct SyncPushRequest {
    pub(crate) vault_id: Uuid,
    pub(crate) changes: Vec<SyncPushChange>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct SyncSharedPushRequest {
    pub(crate) vault_id: Uuid,
    pub(crate) changes: Vec<SyncSharedPushChange>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct SyncPushChange {
    pub(crate) item_id: Uuid,
    pub(crate) operation: String,
    pub(crate) payload_enc: Option<Vec<u8>>,
    pub(crate) checksum: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) type_id: Option<String>,
    #[serde(default)]
    pub(crate) base_seq: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct SyncSharedPushChange {
    pub(crate) item_id: Uuid,
    pub(crate) operation: String,
    #[serde(default)]
    pub(crate) payload: Option<JsonValue>,
    #[serde(default)]
    pub(crate) path: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) type_id: Option<String>,
    #[serde(default)]
    pub(crate) base_seq: Option<i64>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SyncPushResponse {
    pub(crate) applied: Vec<String>,
    pub(crate) applied_changes: Vec<SyncAppliedChange>,
    pub(crate) conflicts: Vec<SyncPushConflict>,
    pub(crate) new_cursor: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SyncAppliedChange {
    pub(crate) item_id: String,
    pub(crate) seq: i64,
    pub(crate) updated_at: String,
    pub(crate) deleted_at: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SyncPushConflict {
    pub(crate) item_id: String,
    pub(crate) reason: &'static str,
    pub(crate) server_seq: i64,
    pub(crate) server_updated_at: String,
}

pub(crate) struct SyncPullRow {
    pub(crate) seq: i64,
    pub(crate) op: String,
    pub(crate) item_id: Uuid,
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) type_id: String,
    pub(crate) payload_enc: Vec<u8>,
    pub(crate) checksum: String,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub(crate) struct SyncCursor {
    pub(crate) seq: i64,
}
