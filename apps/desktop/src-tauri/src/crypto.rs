use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use uuid::Uuid;
use zann_core::crypto::{decrypt_blob, EncryptedBlob, SecretKey};

pub fn decrypt_vault_key_with_master(
    master_key: &SecretKey,
    vault: &zann_db::local::LocalVault,
) -> Result<SecretKey, String> {
    let blob = EncryptedBlob::from_bytes(&vault.vault_key_enc)
        .map_err(|err| err.to_string())?;
    let aad = vault_key_aad(vault.id);
    let key_bytes = decrypt_blob(master_key, &blob, &aad).map_err(|err| err.to_string())?;
    if key_bytes.len() != 32 {
        return Err("invalid vault key length".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(SecretKey::from_bytes(key))
}

pub fn payload_checksum(payload_enc: &[u8]) -> String {
    blake3::hash(payload_enc).to_hex().to_string()
}

pub fn payload_aad(vault_id: Uuid, item_id: Uuid) -> Vec<u8> {
    let mut aad = b"zann:payload:v1".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(item_id.as_bytes());
    aad
}

pub fn vault_key_aad(vault_id: Uuid) -> Vec<u8> {
    let mut aad = b"zann:vault_key:v1".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

pub fn decrypt_payload(
    vault_key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    payload_enc: &[u8],
) -> Result<zann_core::EncryptedPayload, String> {
    let blob = EncryptedBlob::from_bytes(payload_enc).map_err(|err| err.to_string())?;
    let aad = payload_aad(vault_id, item_id);
    let bytes = decrypt_blob(vault_key, &blob, &aad).map_err(|err| err.to_string())?;
    zann_core::EncryptedPayload::from_bytes(&bytes).map_err(|err| err.to_string())
}

#[allow(dead_code)]
pub fn derive_master_key(
    password: &str,
    identity: &crate::state::IdentityConfig,
) -> Result<SecretKey, anyhow::Error> {
    if identity.kdf_params.algorithm != "argon2id" {
        anyhow::bail!("unsupported kdf algorithm");
    }
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&identity.kdf_salt)
        .map_err(|_| anyhow::anyhow!("invalid kdf salt"))?;
    let params = Params::new(
        identity.kdf_params.memory_kb,
        identity.kdf_params.iterations,
        identity.kdf_params.parallelism,
        Some(32),
    )
    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok(SecretKey::from_bytes(key))
}
