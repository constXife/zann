use serde::Serialize;

#[derive(Serialize)]
pub struct CreateVaultRequest {
    pub slug: String,
    pub name: String,
    pub kind: String,
    pub cache_policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_key_enc: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}
