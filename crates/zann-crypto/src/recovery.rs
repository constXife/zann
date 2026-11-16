//! Recovery credentials are server-auth secrets, never E2EE key material.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng, RngCore};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum RecoverySecretError {
    InvalidFormat,
    Base64(base64::DecodeError),
}
impl std::fmt::Display for RecoverySecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid recovery credential encoding")
    }
}
impl std::error::Error for RecoverySecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Base64(source) => Some(source),
            Self::InvalidFormat => None,
        }
    }
}

pub struct RecoverySecrets {
    resume_token: Zeroizing<String>,
    next_recovery_key: Zeroizing<String>,
}
impl RecoverySecrets {
    pub fn generate() -> Self {
        let mut token = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(token.as_mut());
        Self {
            resume_token: Zeroizing::new(URL_SAFE_NO_PAD.encode(token.as_ref())),
            next_recovery_key: generate_server_recovery_key(),
        }
    }
    pub fn from_parts(token: &str, code: &str) -> Result<Self, RecoverySecretError> {
        let _decoded = decode_resume(token)?;
        if !valid_recovery_code(code) {
            return Err(RecoverySecretError::InvalidFormat);
        }
        Ok(Self {
            resume_token: Zeroizing::new(token.to_owned()),
            next_recovery_key: Zeroizing::new(code.to_owned()),
        })
    }
    pub fn resume_token(&self) -> &str {
        &self.resume_token
    }
    pub fn next_recovery_key(&self) -> &str {
        &self.next_recovery_key
    }
    pub fn confirms_code(&self, code: &str) -> bool {
        crate::tokens::constant_time_equal(self.next_recovery_key.as_bytes(), code.as_bytes())
    }
    pub fn encode(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "zann-recovery-v1:{}:{}",
            self.resume_token(),
            self.next_recovery_key()
        ))
    }
    pub fn decode(encoded: &str) -> Result<Self, RecoverySecretError> {
        let value = encoded
            .strip_prefix("zann-recovery-v1:")
            .ok_or(RecoverySecretError::InvalidFormat)?;
        let (token, code) = value
            .split_once(':')
            .ok_or(RecoverySecretError::InvalidFormat)?;
        Self::from_parts(token, code)
    }
}

pub fn generate_server_recovery_key() -> Zeroizing<String> {
    Zeroizing::new(
        OsRng
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect(),
    )
}
fn valid_recovery_code(value: &str) -> bool {
    value.len() == 48 && value.bytes().all(|c| c.is_ascii_alphanumeric())
}
fn decode_resume(value: &str) -> Result<Zeroizing<Vec<u8>>, RecoverySecretError> {
    if value.len() != 43 {
        return Err(RecoverySecretError::InvalidFormat);
    }
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(RecoverySecretError::Base64)?,
    );
    if bytes.len() != 32 {
        return Err(RecoverySecretError::InvalidFormat);
    }
    Ok(bytes)
}
pub fn resume_token_hash(
    operation: Uuid,
    token: &str,
    pepper: &str,
) -> Result<String, RecoverySecretError> {
    let bytes = decode_resume(token)?;
    let mut material = Zeroizing::new(b"zann recovery resume v1\0".to_vec());
    material.extend_from_slice(&16u32.to_be_bytes());
    material.extend_from_slice(operation.as_bytes());
    material.extend_from_slice(&32u32.to_be_bytes());
    material.extend_from_slice(&bytes);
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(material.as_slice()));
    Ok(crate::tokens::hash_token(&encoded, pepper))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundle_roundtrip_and_purpose_binding() {
        let secrets = RecoverySecrets::generate();
        let restored =
            RecoverySecrets::decode(&secrets.encode()).expect("valid generated recovery material");
        assert!(restored.confirms_code(secrets.next_recovery_key()));
        assert!(!restored.confirms_code("wrong"));
        let a = Uuid::from_bytes([1; 16]);
        let b = Uuid::from_bytes([2; 16]);
        assert_ne!(
            resume_token_hash(a, secrets.resume_token(), "test-pepper")
                .expect("valid generated recovery material"),
            resume_token_hash(b, secrets.resume_token(), "test-pepper")
                .expect("valid generated recovery material")
        );
        assert!(RecoverySecrets::decode("malformed").is_err());
        assert!(resume_token_hash(a, "not-a-token", "test-pepper").is_err());
    }
}
