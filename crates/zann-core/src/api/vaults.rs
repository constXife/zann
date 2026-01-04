use schemars::JsonSchema;
use serde::Serialize;
use uuid::Uuid;

use crate::{CachePolicy, VaultKind};

#[derive(Debug, Serialize, JsonSchema)]
pub struct VaultSummary {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub kind: VaultKind,
    pub cache_policy: CachePolicy,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct VaultListResponse {
    pub vaults: Vec<VaultSummary>,
}
