use uuid::Uuid;

use crate::crypto::{decrypt_blob, encrypt_blob, EncryptedBlob, SecretKey};
use crate::EncryptedPayload;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultCryptoError {
    InvalidBlob,
    InvalidKeyLength,
    InvalidPayload,
    EncryptFailed,
    DecryptFailed,
}

impl VaultCryptoError {
    #[must_use]
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::InvalidBlob => "invalid_blob",
            Self::InvalidKeyLength => "invalid_key_length",
            Self::InvalidPayload => "invalid_payload",
            Self::EncryptFailed => "encrypt_failed",
            Self::DecryptFailed => "decrypt_failed",
        }
    }
}

impl std::fmt::Display for VaultCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBlob => write!(f, "invalid encrypted blob"),
            Self::InvalidKeyLength => write!(f, "invalid key length"),
            Self::InvalidPayload => write!(f, "invalid payload"),
            Self::EncryptFailed => write!(f, "encryption failed"),
            Self::DecryptFailed => write!(f, "decryption failed"),
        }
    }
}

impl std::error::Error for VaultCryptoError {}

#[must_use]
pub fn vault_key_aad(vault_id: Uuid) -> Vec<u8> {
    let mut aad = b"zann:vault_key:v1".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

#[must_use]
pub fn payload_aad(vault_id: Uuid, item_id: Uuid) -> Vec<u8> {
    let mut aad = b"zann:payload:v1".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(item_id.as_bytes());
    aad
}

#[must_use]
pub fn rotation_candidate_aad(vault_id: Uuid, item_id: Uuid) -> Vec<u8> {
    let mut aad = b"zann:rotation_candidate:v1".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(item_id.as_bytes());
    aad
}

pub fn encrypt_vault_key(
    master_key: &SecretKey,
    vault_id: Uuid,
    vault_key: &SecretKey,
) -> Result<Vec<u8>, VaultCryptoError> {
    let aad = vault_key_aad(vault_id);
    let blob = encrypt_blob(master_key, vault_key.as_bytes(), &aad)
        .map_err(|_| VaultCryptoError::EncryptFailed)?;
    Ok(blob.to_bytes())
}

pub fn decrypt_vault_key(
    master_key: &SecretKey,
    vault_id: Uuid,
    vault_key_enc: &[u8],
) -> Result<SecretKey, VaultCryptoError> {
    let blob =
        EncryptedBlob::from_bytes(vault_key_enc).map_err(|_| VaultCryptoError::InvalidBlob)?;
    let aad = vault_key_aad(vault_id);
    let key_bytes =
        decrypt_blob(master_key, &blob, &aad).map_err(|_| VaultCryptoError::DecryptFailed)?;
    if key_bytes.len() != 32 {
        return Err(VaultCryptoError::InvalidKeyLength);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(SecretKey::from_bytes(key))
}

pub fn encrypt_payload_bytes(
    vault_key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    payload_bytes: &[u8],
) -> Result<Vec<u8>, VaultCryptoError> {
    let aad = payload_aad(vault_id, item_id);
    let blob = encrypt_blob(vault_key, payload_bytes, &aad)
        .map_err(|_| VaultCryptoError::EncryptFailed)?;
    Ok(blob.to_bytes())
}

pub fn decrypt_payload_bytes(
    vault_key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    payload_enc: &[u8],
) -> Result<Vec<u8>, VaultCryptoError> {
    let blob = EncryptedBlob::from_bytes(payload_enc).map_err(|_| VaultCryptoError::InvalidBlob)?;
    let aad = payload_aad(vault_id, item_id);
    decrypt_blob(vault_key, &blob, &aad).map_err(|_| VaultCryptoError::DecryptFailed)
}

pub fn encrypt_rotation_candidate(
    vault_key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    candidate: &[u8],
) -> Result<Vec<u8>, VaultCryptoError> {
    let aad = rotation_candidate_aad(vault_id, item_id);
    let blob =
        encrypt_blob(vault_key, candidate, &aad).map_err(|_| VaultCryptoError::EncryptFailed)?;
    Ok(blob.to_bytes())
}

pub fn decrypt_rotation_candidate(
    vault_key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    candidate_enc: &[u8],
) -> Result<Vec<u8>, VaultCryptoError> {
    let blob =
        EncryptedBlob::from_bytes(candidate_enc).map_err(|_| VaultCryptoError::InvalidBlob)?;
    let aad = rotation_candidate_aad(vault_id, item_id);
    decrypt_blob(vault_key, &blob, &aad).map_err(|_| VaultCryptoError::DecryptFailed)
}

pub fn encrypt_payload(
    vault_key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    payload: &EncryptedPayload,
) -> Result<Vec<u8>, VaultCryptoError> {
    let payload_bytes = payload
        .to_bytes()
        .map_err(|_| VaultCryptoError::InvalidPayload)?;
    encrypt_payload_bytes(vault_key, vault_id, item_id, &payload_bytes)
}

pub fn decrypt_payload(
    vault_key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    payload_enc: &[u8],
) -> Result<EncryptedPayload, VaultCryptoError> {
    let payload_bytes = decrypt_payload_bytes(vault_key, vault_id, item_id, payload_enc)?;
    EncryptedPayload::from_bytes(&payload_bytes).map_err(|_| VaultCryptoError::InvalidPayload)
}

#[must_use]
pub fn payload_checksum(payload_enc: &[u8]) -> String {
    blake3::hash(payload_enc).to_hex().to_string()
}
