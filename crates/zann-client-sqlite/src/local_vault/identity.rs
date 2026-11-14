use super::*;

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
