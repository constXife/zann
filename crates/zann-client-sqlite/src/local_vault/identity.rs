use super::*;

/// A fresh identity for a vault that is local-only from the start. A vault
/// that came from a server never gets one: its identity is the account's,
/// committed by the login.
pub(super) fn new_local_identity() -> ConfigIdentity {
    let salt = SecretKey::generate();
    ConfigIdentity {
        kdf_salt: base64::engine::general_purpose::STANDARD.encode(salt.as_bytes()),
        kdf_params: ConfigKdfParams {
            algorithm: "argon2id".to_string(),
            iterations: 3,
            memory_kb: 65536,
            parallelism: 4,
        },
        salt_fingerprint: None,
        first_seen_at: None,
        email: None,
    }
}

pub(super) fn derive_master_key(
    password: &str,
    identity: &ConfigIdentity,
) -> LocalResult<SecretKey> {
    let params =
        zann_core::api::auth::KdfParams::from(identity.kdf_params.clone()).to_crypto_params();
    let key = zann_core::passwords::derive_auth_hash(password, &identity.kdf_salt, &params)
        .map_err(|err| LocalError::InvalidArgument(err.to_string()))?;
    Ok(SecretKey::from_bytes(key))
}
