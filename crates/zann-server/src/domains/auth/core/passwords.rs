use zann_core::User;

pub use zann_crypto::passwords::{
    derive_auth_hash, hash_password, hash_service_token, kdf_fingerprint, random_kdf_salt,
    KdfParams,
};

#[must_use]
pub fn kdf_params_from_user(user: &User) -> KdfParams {
    KdfParams {
        algorithm: user.kdf_algorithm.clone(),
        iterations: user.kdf_iterations as u32,
        memory_kb: user.kdf_memory_kb as u32,
        parallelism: user.kdf_parallelism as u32,
    }
}

pub fn verify_password(user: &User, password: &str, pepper: &str) -> Result<bool, &'static str> {
    let stored = match user.password_hash.as_deref() {
        Some(value) => value,
        None => return Ok(false),
    };
    let params = kdf_params_from_user(user);
    zann_crypto::passwords::verify_password(stored, password, &user.kdf_salt, &params, pepper)
}
