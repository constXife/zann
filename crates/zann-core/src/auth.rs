use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Identity {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub avatar_initials: String,
    pub groups: Vec<String>,
    pub source: AuthSource,
    pub device_id: Option<Uuid>,
    pub service_account_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthSource {
    Internal,
    Device,
    ServiceAccount,
    Oidc { issuer: String, subject: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OidcToken {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub claims: Map<String, Value>,
}

#[must_use]
pub fn extract_groups(token: &OidcToken, claim: &str) -> Vec<String> {
    match token.claims.get(claim) {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        Some(Value::Object(obj)) => obj.keys().cloned().collect(),
        _ => Vec::new(),
    }
}
