use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zann_core::EncryptedPayload;

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
    pub payload: Option<EncryptedPayload>,
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
