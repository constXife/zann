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

#[derive(Debug, Serialize, JsonSchema)]
pub struct PersonalVaultStatusResponse {
    pub personal_vaults_present: bool,
    pub personal_key_envelopes_present: bool,
    pub personal_vault_id: Option<Uuid>,
}
