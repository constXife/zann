use uuid::Uuid;
use zann_core::crypto::{decrypt_blob, EncryptedBlob, SecretKey};

pub fn decrypt_vault_key_with_master(
    master_key: &SecretKey,
    vault: &zann_db::local::LocalVault,
) -> Result<SecretKey, String> {
    let blob = EncryptedBlob::from_bytes(&vault.vault_key_enc).map_err(|err| err.to_string())?;
    let aad = vault_key_aad(vault.id);
    let key_bytes = decrypt_blob(master_key, &blob, &aad).map_err(|err| err.to_string())?;
    if key_bytes.len() != 32 {
        return Err("invalid vault key length".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(SecretKey::from_bytes(key))
}

pub fn vault_key_aad(vault_id: Uuid) -> Vec<u8> {
    let mut aad = b"zann:vault_key:v1".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

#[allow(dead_code)]
pub fn derive_master_key(
    password: &str,
    identity: &crate::state::IdentityConfig,
) -> Result<SecretKey, anyhow::Error> {
    let params = identity.kdf_params.to_crypto_params();
    let key = zann_core::passwords::derive_auth_hash(password, &identity.kdf_salt, &params)
        .map_err(anyhow::Error::msg)?;
    Ok(SecretKey::from_bytes(key))
}
