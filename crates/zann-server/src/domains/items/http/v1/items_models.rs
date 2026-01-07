use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use zann_core::FieldsChanged;

#[derive(Serialize, JsonSchema)]
pub(crate) struct ErrorResponse {
    pub(crate) error: &'static str,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct CreateItemRequest {
    pub(crate) path: String,
    pub(crate) type_id: String,
    #[serde(default)]
    pub(crate) tags: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) favorite: Option<bool>,
    #[serde(default)]
    pub(crate) payload_enc: Option<Vec<u8>>,
    #[serde(default)]
    pub(crate) payload: Option<JsonValue>,
    #[serde(default)]
    pub(crate) checksum: Option<String>,
    #[serde(default)]
    pub(crate) version: Option<i64>,
    #[serde(default)]
    pub(crate) fields_changed: Option<FieldsChanged>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct UpdateItemRequest {
    #[serde(default)]
    pub(crate) path: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) type_id: Option<String>,
    #[serde(default)]
    pub(crate) tags: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) favorite: Option<bool>,
    #[serde(default)]
    pub(crate) payload_enc: Option<Vec<u8>>,
    #[serde(default)]
    pub(crate) payload: Option<JsonValue>,
    #[serde(default)]
    pub(crate) checksum: Option<String>,
    #[serde(default)]
    pub(crate) version: Option<i64>,
    #[serde(default)]
    pub(crate) base_version: Option<i64>,
    #[serde(default)]
    pub(crate) fields_changed: Option<FieldsChanged>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ItemSummary {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) type_id: String,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) favorite: bool,
    pub(crate) checksum: String,
    pub(crate) version: i64,
    pub(crate) deleted_at: Option<String>,
    pub(crate) updated_at: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ItemsResponse {
    pub(crate) items: Vec<ItemSummary>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ItemResponse {
    pub(crate) id: String,
    pub(crate) vault_id: String,
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) type_id: String,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) favorite: bool,
    pub(crate) payload_enc: Vec<u8>,
    pub(crate) checksum: String,
    pub(crate) version: i64,
    pub(crate) deleted_at: Option<String>,
    pub(crate) updated_at: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct HistoryListQuery {
    pub(crate) limit: Option<i64>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ItemHistorySummary {
    pub(crate) version: i64,
    pub(crate) checksum: String,
    pub(crate) change_type: String,
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
    pub(crate) payload_enc: Vec<u8>,
    pub(crate) change_type: String,
    pub(crate) created_at: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct FileUploadResponse {
    pub(crate) file_id: String,
    pub(crate) upload_state: String,
}
