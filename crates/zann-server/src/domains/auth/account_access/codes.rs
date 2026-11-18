use super::{runtime::CodeProfile, *};
use crate::app::AppState;
use std::sync::Arc;
use zeroize::Zeroizing;
pub(super) async fn hash_code(
    state: &AppState,
    profile: Arc<CodeProfile>,
    code: &str,
) -> Result<Zeroizing<String>> {
    if !zann_crypto::recovery::valid_recovery_code(code) {
        return Err(AccessError::Rejected);
    }
    let permit = state
        .argon2_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| AccessError::RateLimited)?;
    let code = Zeroizing::new(code.to_owned());
    let pepper = Zeroizing::new(state.password_pepper.clone());
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        zann_crypto::recovery::server_recovery_verifier(
            &code,
            &profile.salt,
            &pepper,
            &profile.params,
        )
        .map_err(AccessError::Kdf)
    })
    .await
    .map_err(AccessError::Worker)?
}
pub(super) async fn user_code_hash(
    state: &AppState,
    user: &zann_core::User,
    code: &str,
) -> Result<Zeroizing<String>> {
    hash_code(state, Arc::new(CodeProfile::user(user)), code).await
}
