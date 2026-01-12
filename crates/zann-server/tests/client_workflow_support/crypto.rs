#![allow(dead_code)]

use uuid::Uuid;
use zann_crypto::crypto::SecretKey;
use zann_crypto::vault_crypto as core_crypto;
use zann_core::EncryptedPayload;

pub fn key_fingerprint(key: &SecretKey) -> String {
    let hex = blake3::hash(key.as_bytes()).to_hex().to_string();
    hex.get(0..12).unwrap_or(&hex).to_string()
}

pub fn encrypt_vault_key(master_key: &SecretKey, vault_id: Uuid, vault_key: &SecretKey) -> Vec<u8> {
    core_crypto::encrypt_vault_key(master_key, vault_id, vault_key).expect("encrypt vault key")
}

pub fn decrypt_payload(
    key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    payload_enc: &[u8],
) -> Result<EncryptedPayload, String> {
    core_crypto::decrypt_payload(key, vault_id, item_id, payload_enc).map_err(|err| err.to_string())
}

pub fn login_payload(password: &str) -> EncryptedPayload {
    EncryptedPayload {
        v: 1,
        type_id: "login".to_string(),
        fields: [(
            "password".to_string(),
            zann_core::FieldValue {
                kind: zann_core::FieldKind::Password,
                value: password.to_string(),
                meta: None,
            },
        )]
        .into_iter()
        .collect(),
        extra: None,
    }
}

pub(super) fn payload_aad(vault_id: Uuid, item_id: Uuid) -> Vec<u8> {
    core_crypto::payload_aad(vault_id, item_id)
}

pub(super) fn vault_key_aad(vault_id: Uuid) -> Vec<u8> {
    core_crypto::vault_key_aad(vault_id)
}
