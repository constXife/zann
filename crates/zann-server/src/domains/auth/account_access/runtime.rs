//! Bounded admission and one configured dummy KDF profile per server instance.
use super::limiter::AccessLimiter;
use std::{sync::Arc, sync::OnceLock};
#[derive(Default)]
pub struct AccountAccessRuntime {
    pub(crate) admission: AccessLimiter,
    dummy: OnceLock<Arc<CodeProfile>>,
}
pub(super) struct CodeProfile {
    pub salt: String,
    pub params: zann_crypto::passwords::KdfParams,
}
impl CodeProfile {
    pub fn user(user: &zann_core::User) -> Self {
        Self {
            salt: user.kdf_salt.clone(),
            params: crate::domains::auth::core::passwords::kdf_params_from_user(user),
        }
    }
}
impl AccountAccessRuntime {
    pub(super) fn dummy(&self, state: &crate::app::AppState) -> Arc<CodeProfile> {
        self.dummy
            .get_or_init(|| {
                Arc::new(CodeProfile {
                    salt: zann_crypto::passwords::random_kdf_salt(),
                    params: zann_crypto::passwords::KdfParams {
                        algorithm: state.config.auth.kdf.algorithm.clone(),
                        iterations: state.config.auth.kdf.iterations,
                        memory_kb: state.config.auth.kdf.memory_kb,
                        parallelism: state.config.auth.kdf.parallelism,
                    },
                })
            })
            .clone()
    }
}
