//! Local password wrapping and account-key custody. No network I/O or server password changes.
use super::{ConfigIdentity, ConfigKdfParams, SecretKey};
mod accounts;
mod model;
use base64::{engine::general_purpose::STANDARD, Engine};
pub use model::{AccountKeyEnvelope, DeviceUnlock};
use std::collections::BTreeMap;
use std::sync::Arc;
use zann_crypto::crypto::{decrypt_blob, encrypt_blob_verified, CryptoError, EncryptedBlob};
use zann_crypto::passwords::{derive_auth_hash, random_kdf_salt};
use zeroize::Zeroizing;

const ROOT_CHECK: &[u8] = b"Zann device unlock root";

#[derive(Debug, thiserror::Error)]
pub enum DeviceUnlockError {
    #[error("cannot open the local keyring")]
    Crypto(#[from] CryptoError),
    #[error("invalid keyring encoding")]
    Encoding(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(&'static str),
}

fn derive(password: &str, identity: &ConfigIdentity) -> Result<SecretKey, DeviceUnlockError> {
    let params =
        zann_core::api::auth::KdfParams::from(identity.kdf_params.clone()).to_crypto_params();
    derive_auth_hash(password, &identity.kdf_salt, &params)
        .map(SecretKey::from_bytes)
        .map_err(DeviceUnlockError::Invalid)
}

fn decode_blob(value: &str) -> Result<EncryptedBlob, DeviceUnlockError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| DeviceUnlockError::Invalid("invalid keyring encoding"))?;
    Ok(EncryptedBlob::from_bytes(&bytes)?)
}

fn open_key(key: &SecretKey, bytes: &str, aad: &[u8]) -> Result<SecretKey, DeviceUnlockError> {
    let plain = Zeroizing::new(decrypt_blob(key, &decode_blob(bytes)?, aad)?);
    let bytes: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| DeviceUnlockError::Invalid("invalid keyring key length"))?;
    Ok(SecretKey::from_bytes(bytes))
}

pub fn validate_unlock_password(password: &str) -> Result<(), DeviceUnlockError> {
    if zann_crypto::passwords::normalized_password_length(password) < 8 {
        return Err(DeviceUnlockError::Invalid(
            "password must be at least 8 characters",
        ));
    }
    if password.starts_with(char::is_whitespace) || password.ends_with(char::is_whitespace) {
        return Err(DeviceUnlockError::Invalid(
            "password must not start or end with whitespace",
        ));
    }
    Ok(())
}

impl DeviceUnlock {
    pub fn create(password: &str) -> Result<(Self, Arc<SecretKey>), DeviceUnlockError> {
        validate_unlock_password(password)?;
        let identity = ConfigIdentity {
            kdf_salt: random_kdf_salt(),
            kdf_params: ConfigKdfParams {
                algorithm: "argon2id".into(),
                iterations: 3,
                memory_kb: 65536,
                parallelism: 1,
            },
            salt_fingerprint: None,
            first_seen_at: None,
            email: None,
        };
        let device_id = uuid::Uuid::now_v7().to_string();
        let root = Arc::new(SecretKey::generate());
        let kek = derive(password, &identity)?;
        let wrapped_root = STANDARD
            .encode(encrypt_blob_verified(&kek, root.as_bytes(), device_id.as_bytes())?.to_bytes());
        let root_check = STANDARD
            .encode(encrypt_blob_verified(&root, ROOT_CHECK, device_id.as_bytes())?.to_bytes());
        Ok((
            Self {
                device_id,
                identity,
                wrapped_root,
                root_check,
                accounts: BTreeMap::new(),
            },
            root,
        ))
    }

    pub fn open(&self, password: &str) -> Result<Arc<SecretKey>, DeviceUnlockError> {
        let kek = derive(password, &self.identity)?;
        let root = Arc::new(open_key(
            &kek,
            &self.wrapped_root,
            self.device_id.as_bytes(),
        )?);
        self.check_root(&root)?;
        Ok(root)
    }

    pub fn check_root(&self, root: &SecretKey) -> Result<(), DeviceUnlockError> {
        let plain = Zeroizing::new(decrypt_blob(
            root,
            &decode_blob(&self.root_check)?,
            self.device_id.as_bytes(),
        )?);
        if plain.as_slice() != ROOT_CHECK {
            return Err(DeviceUnlockError::Invalid("invalid device root"));
        }
        Ok(())
    }

    pub fn rewrap(&self, current: &str, replacement: &str) -> Result<Self, DeviceUnlockError> {
        validate_unlock_password(replacement)?;
        let root = self.open(current)?;
        let mut candidate = self.clone();
        candidate.identity.kdf_salt = random_kdf_salt();
        let kek = derive(replacement, &candidate.identity)?;
        candidate.wrapped_root = STANDARD.encode(
            encrypt_blob_verified(&kek, root.as_bytes(), self.device_id.as_bytes())?.to_bytes(),
        );
        // Trial-decrypt the complete persisted candidate before publishing it.
        candidate.open(replacement)?;
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests;
