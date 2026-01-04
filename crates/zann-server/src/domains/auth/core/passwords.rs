use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zann_core::User;

#[derive(Debug, Clone)]
pub struct KdfParams {
    pub algorithm: String,
    pub iterations: u32,
    pub memory_kb: u32,
    pub parallelism: u32,
}

#[must_use]
pub fn kdf_params_from_user(user: &User) -> KdfParams {
    KdfParams {
        algorithm: user.kdf_algorithm.clone(),
        iterations: user.kdf_iterations as u32,
        memory_kb: user.kdf_memory_kb as u32,
        parallelism: user.kdf_parallelism as u32,
    }
}

#[must_use]
pub fn random_kdf_salt() -> String {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    base64::engine::general_purpose::STANDARD.encode(salt)
}

pub fn kdf_fingerprint(kdf_salt: &str, params: &KdfParams) -> Result<String, &'static str> {
    let mut hasher = Sha256::new();
    hasher.update(kdf_salt.as_bytes());
    hasher.update(params.algorithm.as_bytes());
    hasher.update(params.iterations.to_le_bytes());
    hasher.update(params.memory_kb.to_le_bytes());
    hasher.update(params.parallelism.to_le_bytes());
    let hash = hasher.finalize();
    Ok(format!("sha256:{}", hex::encode(hash)))
}

pub fn derive_auth_hash(
    password: &str,
    kdf_salt: &str,
    params: &KdfParams,
) -> Result<[u8; 32], &'static str> {
    if params.algorithm != "argon2id" {
        return Err("unsupported_kdf");
    }
    let salt_bytes = base64::engine::general_purpose::STANDARD
        .decode(kdf_salt)
        .map_err(|_| "invalid_kdf_salt")?;
    let params = Params::new(
        params.memory_kb,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| "invalid_kdf_params")?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut key)
        .map_err(|_| "kdf_failed")?;
    Ok(key)
}

pub fn hash_password(
    auth_hash: &[u8; 32],
    pepper: &str,
    params: &KdfParams,
) -> Result<String, &'static str> {
    if params.algorithm != "argon2id" {
        return Err("unsupported_kdf");
    }
    let mut pepper_hash = Sha256::new();
    pepper_hash.update(pepper.as_bytes());
    let pepper_salt = pepper_hash.finalize();
    let params = Params::new(
        params.memory_kb,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| "invalid_kdf_params")?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(auth_hash, &pepper_salt, &mut key)
        .map_err(|_| "hash_failed")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(key))
}

pub fn hash_service_token(
    token: &str,
    pepper: &str,
    params: &KdfParams,
) -> Result<String, &'static str> {
    if params.algorithm != "argon2id" {
        return Err("unsupported_kdf");
    }
    let mut pepper_hash = Sha256::new();
    pepper_hash.update(pepper.as_bytes());
    let pepper_salt = pepper_hash.finalize();
    let params = Params::new(
        params.memory_kb,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| "invalid_kdf_params")?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(token.as_bytes(), &pepper_salt, &mut key)
        .map_err(|_| "hash_failed")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(key))
}

pub fn verify_password(user: &User, password: &str, pepper: &str) -> Result<bool, &'static str> {
    let stored = match user.password_hash.as_deref() {
        Some(value) => value,
        None => return Ok(false),
    };
    let params = kdf_params_from_user(user);
    let auth_hash = derive_auth_hash(password, &user.kdf_salt, &params)?;
    let candidate = hash_password(&auth_hash, pepper, &params)?;
    let stored_bytes = stored.as_bytes();
    let candidate_bytes = candidate.as_bytes();
    Ok(stored_bytes.ct_eq(candidate_bytes).into())
}
