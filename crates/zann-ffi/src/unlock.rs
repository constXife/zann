use crate::{CoreFacade, CoreResult, VaultStatus};

#[uniffi::export]
impl CoreFacade {
    pub fn change_unlock_password(&self, current: String, replacement: String) -> CoreResult<()> {
        self.inner
            .change_unlock_password(current, replacement)
            .map_err(Into::into)
    }
    pub fn activate_connected_account(&self) -> CoreResult<bool> {
        self.inner.activate_connected_account().map_err(Into::into)
    }
    pub fn enroll_account_key(&self, password: String) -> CoreResult<VaultStatus> {
        self.inner
            .enroll_account_key(password)
            .map(Into::into)
            .map_err(Into::into)
    }
}
