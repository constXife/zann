//! Native adapter: captures local custody, cancels on lock/switch, then publishes
//! through the existing keyring CAS. No network or provider wait holds a lease.
use super::*;
use zann_client::account_access::AccountCeremonyProvider;
use zann_client::app::PasskeyEnrollmentAuthorization;
use zann_core::api::account_access::*;
impl LocalVault {
    pub fn account_security(&self) -> LocalResult<AccountSecurity> {
        let generation = self.context_generation.load(Ordering::SeqCst);
        let client = self.app_client()?;
        let target = client.configured_target(None).map_err(LocalError::from)?;
        let (operation, cancel) =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(60));
        let _active = self.syncs.register(operation.operation_id(), cancel);
        {
            let _context = self.context_gate.read().expect("lock poisoned");
            self.check_context_generation(generation)?;
        }
        let result = self
            .runtime
            .block_on(client.account_security(&target, operation))
            .map_err(LocalError::from)?;
        {
            let _context = self.context_gate.read().expect("lock poisoned");
            self.check_context_generation(generation)?;
        }
        Ok(result)
    }
    pub fn enroll_account_passkey(
        &self,
        name: String,
        mode: PasskeyMode,
        authorization: PasskeyEnrollmentAuthorization,
        provider: Arc<dyn AccountCeremonyProvider>,
    ) -> LocalResult<SecurityReceipt> {
        let generation = self.context_generation.load(Ordering::SeqCst);
        let root = self.root_key()?;
        let keyring = self.device_unlock()?;
        let client = self.app_client()?;
        let target = client.configured_target(None).map_err(LocalError::from)?;
        let (operation, cancel) =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(360));
        let _active = self.syncs.register(operation.operation_id(), cancel);
        // Register first, then verify capture: a lock between capture and
        // registration must not leave a live key-authorized operation behind.
        {
            let _context = self.context_gate.read().expect("lock poisoned");
            self.check_context_generation(generation)?;
        }
        let receipt = self
            .runtime
            .block_on(client.enroll_account_passkey(
                &target,
                &root,
                &keyring,
                name,
                mode,
                authorization,
                provider,
                operation,
            ))
            .map_err(LocalError::from)?;
        {
            let _context = self.context_gate.read().expect("lock poisoned");
            self.check_context_generation(generation)?;
        }
        Ok(receipt)
    }
    pub fn revoke_account_passkey(
        &self,
        credential_id: String,
        provider: Arc<dyn AccountCeremonyProvider>,
    ) -> LocalResult<SecurityReceipt> {
        let generation = self.context_generation.load(Ordering::SeqCst);
        let root = self.root_key()?;
        let keyring = self.device_unlock()?;
        let client = self.app_client()?;
        let target = client.configured_target(None).map_err(LocalError::from)?;
        let (operation, cancel) =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(180));
        let _active = self.syncs.register(operation.operation_id(), cancel);
        {
            let _context = self.context_gate.read().expect("lock poisoned");
            self.check_context_generation(generation)?;
        }
        let result = self
            .runtime
            .block_on(client.revoke_account_passkey(
                &target,
                &root,
                &keyring,
                credential_id,
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
    pub fn acknowledge_account_recovery(&self) -> LocalResult<()> {
        let root = self.root_key()?;
        let keyring = self.device_unlock()?;
        let client = self.app_client()?;
        let target = client.configured_target(None).map_err(LocalError::from)?;
        let (operation, cancel) =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(60));
        let _active = self.syncs.register(operation.operation_id(), cancel);
        self.runtime
            .block_on(client.acknowledge_account_recovery(&target, &root, &keyring, operation))
            .map_err(LocalError::from)
    }
    pub fn complete_account_passkey_login(
        &self,
        bootstrap: zann_client::app::PasskeyVaultBootstrap,
    ) -> LocalResult<VaultStatus> {
        let generation = self.context_generation.load(Ordering::SeqCst);
        // Independent DeviceUnlock must already exist and be open here.
        let root = self.root_key()?;
        let keyring = self.device_unlock()?;
        let client = self.app_client()?;
        let (operation, cancel) =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(60));
        let _active = self.syncs.register(operation.operation_id(), cancel);
        {
            let _context = self.context_gate.read().expect("lock poisoned");
            self.check_context_generation(generation)?;
        }
        let prepared = self
            .runtime
            .block_on(client.prepare_passkey_account_key(bootstrap, &root, &keyring, operation))
            .map_err(LocalError::from)?;
        self.publish_account_keyring(
            generation,
            &root,
            &prepared.enrollment,
            &keyring,
            &prepared.keyring,
        )
    }
}
