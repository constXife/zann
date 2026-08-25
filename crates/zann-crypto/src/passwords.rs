use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone)]
pub struct KdfParams {
    pub algorithm: String,
    pub iterations: u32,
    pub memory_kb: u32,
    pub parallelism: u32,
}

pub const KDF_ALGORITHM: &str = "argon2id";
pub const MIN_KDF_ITERATIONS: u32 = 1;
pub const MAX_KDF_ITERATIONS: u32 = 10;
pub const MIN_KDF_MEMORY_KB: u32 = 8;
pub const MAX_KDF_MEMORY_KB: u32 = 256 * 1024;
pub const MIN_KDF_PARALLELISM: u32 = 1;
pub const MAX_KDF_PARALLELISM: u32 = 16;

/// Reject parameters that are invalid or can turn persisted/server-provided
/// configuration into an unbounded CPU or memory request.
pub fn validate_kdf_policy(params: &KdfParams) -> Result<(), &'static str> {
    if params.algorithm != KDF_ALGORITHM {
        return Err("unsupported_kdf");
    }
    if !(MIN_KDF_ITERATIONS..=MAX_KDF_ITERATIONS).contains(&params.iterations) {
        return Err("kdf_iterations_out_of_policy");
    }
    if !(MIN_KDF_MEMORY_KB..=MAX_KDF_MEMORY_KB).contains(&params.memory_kb) {
        return Err("kdf_memory_out_of_policy");
    }
    if !(MIN_KDF_PARALLELISM..=MAX_KDF_PARALLELISM).contains(&params.parallelism) {
        return Err("kdf_parallelism_out_of_policy");
    }
    if params.memory_kb < params.parallelism.saturating_mul(8) {
        return Err("kdf_memory_too_low_for_parallelism");
    }
    Ok(())
}

#[must_use]
pub fn random_kdf_salt() -> String {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    base64::engine::general_purpose::STANDARD.encode(salt)
}

pub fn kdf_fingerprint(kdf_salt: &str, params: &KdfParams) -> Result<String, &'static str> {
    validate_kdf_policy(params)?;
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
    validate_kdf_policy(params)?;
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
    validate_kdf_policy(params)?;
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
    validate_kdf_policy(params)?;
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

pub fn verify_password(
    stored_hash: &str,
    password: &str,
    kdf_salt: &str,
    params: &KdfParams,
    pepper: &str,
) -> Result<bool, &'static str> {
    let auth_hash = derive_auth_hash(password, kdf_salt, params)?;
    let candidate = hash_password(&auth_hash, pepper, params)?;
    let stored_bytes = stored_hash.as_bytes();
    let candidate_bytes = candidate.as_bytes();
    Ok(stored_bytes.ct_eq(candidate_bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_params() -> KdfParams {
        KdfParams {
            algorithm: KDF_ALGORITHM.to_string(),
            iterations: 3,
            memory_kb: 65_536,
            parallelism: 4,
        }
    }

    #[test]
    fn kdf_policy_accepts_the_supported_profile() {
        assert_eq!(validate_kdf_policy(&valid_params()), Ok(()));
    }

    #[test]
    fn kdf_policy_bounds_persisted_resource_requests() {
        let mut params = valid_params();
        params.iterations = MAX_KDF_ITERATIONS + 1;
        assert_eq!(
            validate_kdf_policy(&params),
            Err("kdf_iterations_out_of_policy")
        );

        let mut params = valid_params();
        params.memory_kb = MAX_KDF_MEMORY_KB + 1;
        assert_eq!(
            validate_kdf_policy(&params),
            Err("kdf_memory_out_of_policy")
        );

        let mut params = valid_params();
        params.parallelism = MAX_KDF_PARALLELISM + 1;
        assert_eq!(
            validate_kdf_policy(&params),
            Err("kdf_parallelism_out_of_policy")
        );
    }

    #[test]
    fn kdf_policy_enforces_argon2_lane_memory() {
        let mut params = valid_params();
        params.memory_kb = 8;
        params.parallelism = 2;
        assert_eq!(
            validate_kdf_policy(&params),
            Err("kdf_memory_too_low_for_parallelism")
        );
    }
}
