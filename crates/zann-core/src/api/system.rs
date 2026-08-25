use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::AuthMethod;

/// Public metadata returned by `GET /v1/system/info`.
///
/// The v1 identity signature authenticates `server_id` and
/// `identity.timestamp`. `server_fingerprint` is separate, unsigned metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SystemInfoResponse {
    pub version: String,
    pub build_commit: Option<String>,
    pub server_id: String,
    pub identity: SystemIdentity,
    pub server_name: Option<String>,
    pub server_fingerprint: String,
    #[serde(default)]
    pub auth_methods: Vec<i32>,
    #[serde(default = "default_personal_vaults_enabled")]
    pub personal_vaults_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_users_present: Option<bool>,
}

fn default_personal_vaults_enabled() -> bool {
    true
}

impl SystemInfoResponse {
    /// Returns whether the server advertised a known authentication method.
    #[must_use]
    pub fn supports_auth_method(&self, method: AuthMethod) -> bool {
        self.auth_methods.contains(&method.as_i32())
    }

    /// Iterates over known authentication methods while preserving unknown
    /// numeric values in `auth_methods` for forward-compatible round trips.
    pub fn known_auth_methods(&self) -> impl Iterator<Item = AuthMethod> + '_ {
        self.auth_methods
            .iter()
            .copied()
            .filter_map(|value| AuthMethod::try_from(value).ok())
    }
}

/// The signed identity proof embedded in [`SystemInfoResponse`].
///
/// Its v1 signature payload is `zann-id:v1:{server_id}:{timestamp}`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SystemIdentity {
    pub public_key: String,
    pub timestamp: i64,
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn wire_contract_preserves_unknown_methods_and_future_fields() {
        let wire = json!({
            "version": "1.2.3",
            "build_commit": "abc123",
            "server_id": "server-id",
            "identity": {
                "public_key": "public-key",
                "timestamp": 1_700_000_000,
                "signature": "signature"
            },
            "server_name": "Example",
            "server_fingerprint": "sha256:transport-metadata",
            "auth_methods": [1, 99, 3],
            "personal_vaults_enabled": true,
            "internal_users_present": false,
            "future_metadata": {"ignored": true}
        });

        let mut expected = wire.clone();
        expected
            .as_object_mut()
            .expect("object fixture")
            .remove("future_metadata");
        let mut response: SystemInfoResponse =
            serde_json::from_value(wire).expect("decode forward-compatible system info");
        assert!(response.supports_auth_method(AuthMethod::Password));
        assert!(response.supports_auth_method(AuthMethod::ServiceAccount));
        assert!(!response.supports_auth_method(AuthMethod::Oidc));
        assert_eq!(
            response.known_auth_methods().collect::<Vec<_>>(),
            vec![AuthMethod::Password, AuthMethod::ServiceAccount]
        );
        assert_eq!(response.auth_methods, vec![1, 99, 3]);

        let serialized = serde_json::to_value(&response).expect("serialize canonical system info");
        assert_eq!(serialized, expected);

        response.internal_users_present = None;
        let without_internal_users =
            serde_json::to_value(response).expect("serialize optional internal user status");
        assert!(without_internal_users
            .get("internal_users_present")
            .is_none());
    }

    #[test]
    fn trust_identity_and_version_are_required() {
        let complete = json!({
            "version": "1.2.3",
            "build_commit": null,
            "server_id": "server-id",
            "identity": {
                "public_key": "public-key",
                "timestamp": 1_700_000_000,
                "signature": "signature"
            },
            "server_name": null,
            "server_fingerprint": "sha256:transport-metadata",
            "auth_methods": [],
            "personal_vaults_enabled": true,
            "internal_users_present": null
        });

        for missing in ["version", "server_id", "identity"] {
            let mut incomplete = complete.clone();
            incomplete
                .as_object_mut()
                .expect("object fixture")
                .remove(missing);
            assert!(
                serde_json::from_value::<SystemInfoResponse>(incomplete).is_err(),
                "missing {missing} must be rejected"
            );
        }

        let mut compatible = complete;
        let compatible_object = compatible.as_object_mut().expect("object fixture");
        compatible_object.remove("auth_methods");
        compatible_object.remove("personal_vaults_enabled");
        compatible_object.remove("internal_users_present");
        let compatible: SystemInfoResponse =
            serde_json::from_value(compatible).expect("decode optional capability metadata");
        assert!(compatible.auth_methods.is_empty());
        assert!(compatible.personal_vaults_enabled);
        assert_eq!(compatible.internal_users_present, None);
    }

    #[test]
    fn openapi_auth_methods_are_numeric() {
        let schema = serde_json::to_value(schemars::schema_for!(SystemInfoResponse))
            .expect("serialize system info schema");
        assert_eq!(
            schema.pointer("/properties/auth_methods/items/type"),
            Some(&json!("integer"))
        );
    }
}
