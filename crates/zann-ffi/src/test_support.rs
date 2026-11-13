//! Test/dev-only synthetic server replica, excluded from production bindings.
use crate::{CoreFacade, CoreResult, VaultStatus};

#[uniffi::export]
impl CoreFacade {
    pub fn seed_offline_fixture(&self, password: String) -> CoreResult<VaultStatus> {
        self.inner
            .seed_offline_fixture(password)
            .map(Into::into)
            .map_err(Into::into)
    }
}
