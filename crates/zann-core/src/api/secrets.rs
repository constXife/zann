use std::collections::HashMap;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SecretListQuery {
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SecretSummary {
    pub path: String,
    pub version: i64,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SecretListResponse {
    pub secrets: Vec<SecretSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretVersionSelector {
    Previous,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SecretGetQuery {
    #[serde(default)]
    pub version: Option<SecretVersionSelector>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SecretRequest {
    pub path: String,
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default)]
    pub meta: Option<HashMap<String, String>>,
}

impl fmt::Debug for SecretRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRequest")
            .field("path", &self.path)
            .field("policy", &self.policy.as_ref().map(|_| "<redacted>"))
            .field(
                "meta_count",
                &self.meta.as_ref().map(HashMap::len).unwrap_or(0),
            )
            .finish()
    }
}

impl Drop for SecretRequest {
    fn drop(&mut self) {
        wipe_string(&mut self.path);
        wipe_optional_string(&mut self.policy);
        wipe_string_map(&mut self.meta);
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SecretSetRequest {
    pub value: String,
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default)]
    pub meta: Option<HashMap<String, String>>,
}

impl fmt::Debug for SecretSetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretSetRequest")
            .field("value", &"<redacted>")
            .field("policy", &self.policy.as_ref().map(|_| "<redacted>"))
            .field(
                "meta_count",
                &self.meta.as_ref().map(HashMap::len).unwrap_or(0),
            )
            .finish()
    }
}

impl Drop for SecretSetRequest {
    fn drop(&mut self) {
        wipe_string(&mut self.value);
        wipe_optional_string(&mut self.policy);
        wipe_string_map(&mut self.meta);
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct BatchEnsureRequest {
    pub secrets: Vec<SecretRequest>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct BatchGetRequest {
    pub paths: Vec<String>,
}

impl Drop for BatchGetRequest {
    fn drop(&mut self) {
        for path in &mut self.paths {
            wipe_string(path);
        }
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SecretResponse {
    pub item_id: String,
    pub path: String,
    pub vault_id: String,
    pub value: String,
    pub policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<HashMap<String, String>>,
    pub version: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
}

impl fmt::Debug for SecretResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretResponse")
            .field("item_id", &self.item_id)
            .field("path", &self.path)
            .field("vault_id", &self.vault_id)
            .field("value", &"<redacted>")
            .field("policy", &"<redacted>")
            .field(
                "meta_count",
                &self.meta.as_ref().map(HashMap::len).unwrap_or(0),
            )
            .field("version", &self.version)
            .field("previous_version", &self.previous_version)
            .field("created", &self.created)
            .finish()
    }
}

impl Drop for SecretResponse {
    fn drop(&mut self) {
        wipe_string(&mut self.item_id);
        wipe_string(&mut self.path);
        wipe_string(&mut self.vault_id);
        wipe_string(&mut self.value);
        wipe_string(&mut self.policy);
        wipe_string_map(&mut self.meta);
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RotateStartRequest {
    #[serde(default)]
    pub policy: Option<String>,
}

impl fmt::Debug for RotateStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotateStartRequest")
            .field("policy", &self.policy.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Drop for RotateStartRequest {
    fn drop(&mut self) {
        wipe_optional_string(&mut self.policy);
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RotateAbortRequest {
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub force: bool,
}

impl Drop for RotateAbortRequest {
    fn drop(&mut self) {
        wipe_optional_string(&mut self.reason);
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RotationStatusResponse {
    pub state: String,
    pub started_at: Option<String>,
    pub started_by: Option<String>,
    pub expires_at: Option<String>,
    pub recover_until: Option<String>,
    pub aborted_reason: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct RotationCandidate(String);

impl RotationCandidate {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for RotationCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RotationCandidate(<redacted>)")
    }
}

impl Drop for RotationCandidate {
    fn drop(&mut self) {
        wipe_string(&mut self.0);
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RotationCandidateResponse {
    pub state: String,
    pub candidate: RotationCandidate,
    pub previous_version: i64,
    pub expires_at: Option<String>,
    pub recover_until: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RotationCommitResponse {
    pub status: String,
    pub version: i64,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<PolicyMismatchDetails>,
}

impl fmt::Debug for ErrorResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErrorResponse")
            .field("error", &self.error)
            .field("details", &self.details.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Drop for ErrorResponse {
    fn drop(&mut self) {
        wipe_string(&mut self.error);
        if let Some(details) = self.details.as_mut() {
            wipe_string(&mut details.requested_policy);
            wipe_string(&mut details.existing_policy);
        }
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PolicyMismatchDetails {
    pub requested_policy: String,
    pub existing_policy: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct BatchResult {
    pub path: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorResponse>,
}

impl fmt::Debug for BatchResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchResult")
            .field("path", &self.path)
            .field("status", &self.status)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field("error", &self.error)
            .finish()
    }
}

impl Drop for BatchResult {
    fn drop(&mut self) {
        wipe_string(&mut self.path);
        wipe_string(&mut self.status);
    }
}

fn wipe_string(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    bytes.zeroize();
}

fn wipe_optional_string(value: &mut Option<String>) {
    if let Some(value) = value.as_mut() {
        wipe_string(value);
    }
}

fn wipe_string_map(value: &mut Option<HashMap<String, String>>) {
    if let Some(map) = value.as_mut() {
        for (mut key, mut value) in map.drain() {
            wipe_string(&mut key);
            wipe_string(&mut value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ensure_wire_contract_is_stable() {
        let request = SecretRequest {
            path: "services/api/database".to_string(),
            policy: Some("strong".to_string()),
            meta: Some(HashMap::from([(
                "owner".to_string(),
                "platform".to_string(),
            )])),
        };
        assert_eq!(
            serde_json::to_value(request).expect("serialize request"),
            json!({
                "path": "services/api/database",
                "policy": "strong",
                "meta": {"owner": "platform"}
            })
        );

        let response: SecretResponse = serde_json::from_value(json!({
            "item_id": "00000000-0000-0000-0000-000000000001",
            "path": "/services/api/database",
            "vault_id": "vault-id",
            "value": "secret-value",
            "policy": "strong",
            "meta": {"owner": "platform"},
            "version": 2,
            "created": true,
            "future_field": "ignored"
        }))
        .expect("deserialize response");
        assert_eq!(response.value, "secret-value");
        assert_eq!(response.previous_version, None);
    }

    #[test]
    fn list_wire_contract_contains_metadata_only() {
        let response = SecretListResponse {
            secrets: vec![SecretSummary {
                path: "/services/api/database".to_string(),
                version: 3,
                updated_at: "2026-08-29T12:00:00Z".to_string(),
            }],
            next_cursor: Some("opaque-cursor".to_string()),
        };
        let value = serde_json::to_value(response).expect("serialize list response");

        assert_eq!(
            value,
            json!({
                "secrets": [{
                    "path": "/services/api/database",
                    "version": 3,
                    "updated_at": "2026-08-29T12:00:00Z"
                }],
                "next_cursor": "opaque-cursor"
            })
        );
        assert!(value["secrets"][0].get("value").is_none());
        assert!(value["secrets"][0].get("policy").is_none());
        assert!(value["secrets"][0].get("meta").is_none());
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let request = SecretSetRequest {
            value: "sentinel-value".to_string(),
            policy: Some("sentinel-policy".to_string()),
            meta: Some(HashMap::from([(
                "sentinel-key".to_string(),
                "sentinel-meta".to_string(),
            )])),
        };
        let response = SecretResponse {
            item_id: "00000000-0000-0000-0000-000000000001".to_string(),
            path: "/folder/secret".to_string(),
            vault_id: "vault".to_string(),
            value: "sentinel-value".to_string(),
            policy: "sentinel-policy".to_string(),
            meta: Some(HashMap::from([(
                "sentinel-key".to_string(),
                "sentinel-meta".to_string(),
            )])),
            version: 1,
            previous_version: None,
            created: Some(true),
        };
        for rendered in [format!("{request:?}"), format!("{response:?}")] {
            for sentinel in [
                "sentinel-value",
                "sentinel-policy",
                "sentinel-key",
                "sentinel-meta",
            ] {
                assert!(!rendered.contains(sentinel));
            }
        }
    }

    #[test]
    fn rotation_candidate_debug_is_redacted_while_wire_value_is_preserved() {
        let candidate = RotationCandidate::new("candidate-secret".to_string());
        assert!(!format!("{candidate:?}").contains("candidate-secret"));
        assert_eq!(
            serde_json::to_string(&candidate).expect("serialize candidate"),
            "\"candidate-secret\""
        );
    }
}
