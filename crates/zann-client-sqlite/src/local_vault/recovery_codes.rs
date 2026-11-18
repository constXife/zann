//! Recovery-code custody and activation for an independently open local root.
use super::*;
use zann_client::{account_access::AccountCeremonyProvider, app::AccountRecoveryCode};
impl LocalVault {
    pub fn prepare_server_recovery_code(&self) -> LocalResult<AccountRecoveryCode> {
        self.root_key()?;
        let client = self.app_client()?;
        let target = client.configured_target(None).map_err(LocalError::from)?;
        let (operation, cancel) =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(60));
        let _active = self.syncs.register(operation.operation_id(), cancel);
        self.runtime
            .block_on(client.prepare_server_recovery_code(&target, operation))
            .map_err(LocalError::from)
    }
    pub fn activate_server_recovery_code(
        &self,
        candidate: &AccountRecoveryCode,
        confirmation: String,
        disable_password: bool,
        provider: Arc<dyn AccountCeremonyProvider>,
    ) -> LocalResult<zann_core::api::account_access::SecurityReceipt> {
        let generation = self.context_generation.load(Ordering::SeqCst);
        let root = self.root_key()?;
        let keyring = self.device_unlock()?;
        let client = self.app_client()?;
        let (operation, cancel) =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(180));
        let _active = self.syncs.register(operation.operation_id(), cancel);
        {
            let _context = self.context_gate.read().expect("lock poisoned");
            self.check_context_generation(generation)?;
        }
        let result = self
            .runtime
            .block_on(client.activate_server_recovery_code(
                candidate,
                zeroize::Zeroizing::new(confirmation),
                disable_password,
                &root,
                &keyring,
                provider,
                operation,
            ))
            .map_err(LocalError::from)?;
        {
            let _context = self.context_gate.read().expect("lock poisoned");
            self.check_context_generation(generation)?;
        }
        Ok(result)
    }
}
