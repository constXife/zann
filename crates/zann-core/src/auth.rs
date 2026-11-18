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
    /// Server-created, non-wire authority captured at bearer admission.
    #[serde(skip)]
    #[schemars(skip)]
    pub session_authority: Option<InteractiveSessionAuthority>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthSource {
    Internal,
    Passkey,
    Device,
    ServiceAccount,
    Oidc { issuer: String, subject: String },
}

impl AuthSource {
    #[must_use]
    pub fn is_internal_interactive(&self) -> bool {
        matches!(self, Self::Internal | Self::Passkey)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OidcToken {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    /// Whether the issuer attests the `email` claim; an unverified email
    /// must never adopt or create a local account.
    pub email_verified: Option<bool>,
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

#[derive(Clone, Debug)]
pub struct InteractiveSessionAuthority {
    pub session_id: Uuid,
    pub auth_epoch: i64,
}
