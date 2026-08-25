//! Authenticated endpoint observations for the crate-internal session owner.

use crate::config::v2::VerifiedEndpointBinding;
use crate::identity::IdentityVerifiedSystemInfo;
use zann_core::api::system::SystemInfoResponse;

/// A `/system/info` response whose signed server identity has been verified.
///
/// This type and its binding are crate-private so interface adapters cannot manufacture trust
/// observations. The crate-internal session owner consumes this result when
/// committing an authenticated session to the config repository.
#[allow(dead_code)]
pub(crate) struct VerifiedSystemInfo {
    info: SystemInfoResponse,
    binding: VerifiedEndpointBinding,
}

#[allow(dead_code)]
impl VerifiedSystemInfo {
    pub(crate) fn info(&self) -> &SystemInfoResponse {
        &self.info
    }

    pub(crate) fn binding(&self) -> &VerifiedEndpointBinding {
        &self.binding
    }

    pub(crate) fn into_parts(self) -> (SystemInfoResponse, VerifiedEndpointBinding) {
        (self.info, self.binding)
    }
}

/// Verifies an already-fetched canonical `/system/info` response and seals it into an endpoint
/// binding.
///
/// Keeping this step pure lets transports enforce their own redirect and response-size policy
/// before any unverified server metadata can enter an authenticated session.
#[allow(dead_code)]
pub(crate) fn verify_and_bind_system_info(
    addr: &str,
    info: SystemInfoResponse,
) -> Result<VerifiedSystemInfo, String> {
    let verified = IdentityVerifiedSystemInfo::verify(info)
        .map_err(|_| "server identity proof did not validate".to_string())?;
    bind_verified_system_info(addr, verified)
}

fn bind_verified_system_info(
    addr: &str,
    verified: IdentityVerifiedSystemInfo,
) -> Result<VerifiedSystemInfo, String> {
    let info = verified.into_inner();
    let binding = seal_endpoint_binding(
        addr,
        info.server_id.clone(),
        info.server_fingerprint.clone(),
    )
    .map_err(|error| error.to_string())?;
    Ok(VerifiedSystemInfo { info, binding })
}

fn seal_endpoint_binding(
    address: impl Into<String>,
    server_id: impl Into<String>,
    server_fingerprint: impl Into<String>,
) -> Result<VerifiedEndpointBinding, crate::config::ConfigError> {
    VerifiedEndpointBinding::new(address, server_id, server_fingerprint)
}

#[cfg(all(test, feature = "session"))]
pub(crate) fn verified_endpoint_binding_for_test(
    address: impl Into<String>,
    server_id: impl Into<String>,
    server_fingerprint: impl Into<String>,
) -> VerifiedEndpointBinding {
    VerifiedEndpointBinding::new_for_test(address, server_id, server_fingerprint)
        .expect("static test endpoint binding must validate")
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use chrono::Utc;
    use data_encoding::BASE32_NOPAD;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    use super::*;
    use zann_core::api::system::SystemIdentity;

    const SIGNATURE_PREFIX: &str = "zann-id:v1";

    fn signed_system_info(signing_key: &SigningKey) -> SystemInfoResponse {
        let public_key = signing_key.verifying_key().to_bytes();
        let server_id = BASE32_NOPAD
            .encode(&Sha256::digest(public_key))
            .to_ascii_lowercase();
        let timestamp = Utc::now().timestamp();
        let message = format!("{SIGNATURE_PREFIX}:{server_id}:{timestamp}");
        let signature = signing_key.sign(message.as_bytes()).to_bytes();
        SystemInfoResponse {
            version: "1.0.0".to_string(),
            build_commit: Some("test-build".to_string()),
            server_id,
            identity: SystemIdentity {
                public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
                timestamp,
                signature: base64::engine::general_purpose::STANDARD.encode(signature),
            },
            server_fingerprint: "fingerprint-1".to_string(),
            server_name: Some("Test server".to_string()),
            personal_vaults_enabled: true,
            internal_users_present: Some(true),
            auth_methods: vec![],
        }
    }

    #[test]
    fn signed_identity_produces_canonical_opaque_binding() {
        let info = signed_system_info(&SigningKey::from_bytes(&[7; 32]));
        let expected_server_id = info.server_id.clone();
        let result = verify_and_bind_system_info("https://EXAMPLE.test/", info)
            .expect("verified response should bind to endpoint");

        assert_eq!(result.info().server_id, expected_server_id);
        assert_eq!(result.binding().address(), "https://example.test");
        assert_eq!(result.binding().server_id(), expected_server_id);
        assert_eq!(result.binding().server_fingerprint(), "fingerprint-1");
    }

    #[test]
    fn invalid_signature_never_produces_identity_proof() {
        let mut info = signed_system_info(&SigningKey::from_bytes(&[7; 32]));
        info.identity.signature = base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[8; 32])
                .sign(b"not the canonical identity message")
                .to_bytes(),
        );

        let error = match verify_and_bind_system_info("https://example.test", info) {
            Ok(_) => panic!("invalid signature must not produce a proof"),
            Err(error) => error,
        };

        assert_eq!(error, "server identity proof did not validate");
    }

    #[test]
    fn missing_identity_is_rejected_before_trust_proof() {
        let mut wire = serde_json::to_value(signed_system_info(&SigningKey::from_bytes(&[7; 32])))
            .expect("serialize fixture");
        wire.as_object_mut()
            .expect("object fixture")
            .remove("identity");

        assert!(serde_json::from_value::<SystemInfoResponse>(wire).is_err());
    }
}
