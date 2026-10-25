//! Shared item wire responses used by remote clients.
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Deserialize, Serialize)]
pub struct SharedItemsResponse {
    pub items: Vec<SharedItemResponse>,
    pub next_cursor: Option<String>,
}

pub struct SharedItemSummariesResponse {
    pub items: Vec<ItemSummaryResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct SharedItemResponse {
    pub id: String,
    pub path: String,
    pub payload: Option<JsonValue>,
    #[serde(default)]
    pub payload_enc: Option<Vec<u8>>,
}

#[derive(Deserialize)]
pub struct ItemsResponse {
    pub items: Vec<ItemSummaryResponse>,
}

#[derive(Deserialize, Clone)]
pub struct ItemSummaryResponse {
    pub id: String,
    pub path: String,
    pub updated_at: String,
}
