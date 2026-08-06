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

/// Argon2id is CPU-bound and takes hundreds of milliseconds. Running it inline
/// would park a Tokio worker for that whole time, so with the KDF semaphore at 4
/// a handful of concurrent logins can stall the runtime — health checks included.
/// The `_async` wrappers below move the work to the blocking pool instead.
///
/// Arguments are copied because the closure must be `'static`. The plaintext was
/// already held unzeroized by the callers, so this adds a copy but no new class
/// of exposure.
async fn spawn_kdf<T, F>(f: F) -> Result<T, &'static str>
where
    F: FnOnce() -> Result<T, &'static str> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(err) => {
            tracing::error!(
                event = "kdf_task_failed",
                error = %err,
                "KDF task did not complete"
            );
            Err("kdf_failed")
        }
    }
}

pub async fn derive_auth_hash_async(
    password: &str,
    kdf_salt: &str,
    params: &KdfParams,
) -> Result<[u8; 32], &'static str> {
    let password = password.to_string();
    let kdf_salt = kdf_salt.to_string();
    let params = params.clone();
    spawn_kdf(move || derive_auth_hash(&password, &kdf_salt, &params)).await
}

pub async fn hash_password_async(
    auth_hash: [u8; 32],
    pepper: &str,
    params: &KdfParams,
) -> Result<String, &'static str> {
    let pepper = pepper.to_string();
    let params = params.clone();
    spawn_kdf(move || hash_password(&auth_hash, &pepper, &params)).await
}

pub async fn hash_service_token_async(
    token: &str,
    pepper: &str,
    params: &KdfParams,
) -> Result<String, &'static str> {
    let token = token.to_string();
    let pepper = pepper.to_string();
    let params = params.clone();
    spawn_kdf(move || hash_service_token(&token, &pepper, &params)).await
}

pub async fn verify_password_async(
    user: &User,
    password: &str,
    pepper: &str,
) -> Result<bool, &'static str> {
    let Some(stored) = user.password_hash.clone() else {
        return Ok(false);
    };
    let params = kdf_params_from_user(user);
    let kdf_salt = user.kdf_salt.clone();
    let password = password.to_string();
    let pepper = pepper.to_string();
    spawn_kdf(move || {
        zann_crypto::passwords::verify_password(&stored, &password, &kdf_salt, &params, &pepper)
    })
    .await
}
