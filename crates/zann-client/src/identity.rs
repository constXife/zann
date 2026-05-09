use base64::Engine;
use chrono::Utc;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Digest, Sha256};

use crate::types::SystemInfoResponse;

const MAX_IDENTITY_SKEW_SECONDS: i64 = 300;
const SIGNATURE_PREFIX: &str = "zann-id:v1";

#[derive(Debug)]
pub enum IdentityError {
    Missing,
    InvalidId,
    InvalidSignature,
    TimeSkew { skew_seconds: i64 },
    InvalidKey,
    InvalidSignatureBytes,
}

pub fn verify_system_identity(info: &SystemInfoResponse) -> Result<(), IdentityError> {
    let server_id = info
        .server_id
        .as_deref()
        .ok_or(IdentityError::Missing)?;
    let identity = info.identity.as_ref().ok_or(IdentityError::Missing)?;

    let public_key_bytes = decode_b64(&identity.public_key).map_err(|_| IdentityError::InvalidKey)?;
    if public_key_bytes.len() != 32 {
        return Err(IdentityError::InvalidKey);
    }

    let computed_id = derive_server_id(&public_key_bytes);
    if computed_id != server_id {
        return Err(IdentityError::InvalidId);
    }

    let signature_bytes =
        decode_b64(&identity.signature).map_err(|_| IdentityError::InvalidSignatureBytes)?;
    let signature =
        Signature::try_from(signature_bytes.as_slice()).map_err(|_| IdentityError::InvalidSignatureBytes)?;
    let public_key_array: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::InvalidKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_array).map_err(|_| IdentityError::InvalidKey)?;
    let message = canonical_message(server_id, identity.timestamp);
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| IdentityError::InvalidSignature)?;

    let now = Utc::now().timestamp();
    let skew = (now - identity.timestamp).abs();
    if skew > MAX_IDENTITY_SKEW_SECONDS {
        return Err(IdentityError::TimeSkew { skew_seconds: skew });
    }

    Ok(())
}

fn decode_b64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(value.as_bytes())
}

fn derive_server_id(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    BASE32_NOPAD.encode(&hash).to_ascii_lowercase()
}

fn canonical_message(server_id: &str, timestamp: i64) -> String {
    format!("{SIGNATURE_PREFIX}:{server_id}:{timestamp}")
}
