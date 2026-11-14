//! One-time E2EE enrollment. Server authentication never supplies a personal key.
use super::unlock::keyring_error;
use super::*;
use zann_client::app::SessionTarget;

impl LocalVault {
    pub fn activate_connected_account(&self) -> LocalResult<bool> {
        let generation = self.context_generation.load(Ordering::SeqCst);
        let client = self.app_client()?;
        let target = client.configured_target(None).map_err(LocalError::from)?;
        let lease = self
            .runtime
            .block_on(client.active_account_key_lease(&target))
            .map_err(keyring_error)?;
        let binding = lease.generation();
        let storage = binding
            .storage_id()
            .ok_or_else(|| LocalError::InvalidArgument("account has no storage binding".into()))?
            .to_owned();
        let server = binding
            .server_id()
            .ok_or_else(|| LocalError::InvalidArgument("account has no server binding".into()))?;
        let subject = binding
            .account_subject()
            .ok_or_else(|| LocalError::InvalidArgument("account has no subject binding".into()))?;
        let keyring = self.device_unlock()?;
        if !keyring
            .accounts
            .get(&storage)
            .is_some_and(|e| e.server_id == server && e.account_subject == subject)
        {
            return Ok(false);
        }
        let id = Uuid::parse_str(&storage)
            .map_err(|_| LocalError::InvalidArgument("invalid storage id".into()))?;
        let _context = self.context_gate.write().expect("lock poisoned");
        self.check_context_generation(generation)?;
        let key = self.account_key_for_storage(id)?;
        let pool = self.pool();
        let vaults = self
            .runtime
            .block_on(LocalVaultRepo::new(&pool).list_by_storage(id))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        self.verify_storage_keys(&key, &vaults)?;
        let vault = preferred_vault(&self.runtime, &pool, id, &vaults)?;
        *self.storage_id.lock().expect("lock poisoned") = Some(id);
        *self.vault_id.lock().expect("lock poisoned") = vault;
        self.item_reads.cancel_all();
        self.context_generation.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }

    pub fn enroll_account_key(&self, password: String) -> LocalResult<VaultStatus> {
        let password = zeroize::Zeroizing::new(password);
        let generation = self.context_generation.load(Ordering::SeqCst);
        let root = self.root_key()?;
        let client = self.app_client()?;
        let target = client.configured_target(None).map_err(LocalError::from)?;
        let (storage, server, subject) =
            client.account_key_binding(&target).map_err(keyring_error)?;
        let identity = client.account_identity(&target).map_err(keyring_error)?;
        let account_key = derive_master_key(&password, &identity)?;
        let (operation, cancel) =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(60));
        let _checking = self.syncs.register(operation.operation_id(), cancel);
        match self
            .runtime
            .block_on(client.verify_account_key(&target, &account_key, operation))
            .map_err(LocalError::from)?
        {
            AccountKeyCheck::Matches => {}
            AccountKeyCheck::Unpublished => {
                zann_client::app::unlock::validate_unlock_password(&password)
                    .map_err(keyring_error)?
            }
            AccountKeyCheck::Mismatch => {
                return Err(LocalError::InvalidArgument(
                    "incorrect account encryption password".into(),
                ))
            }
        }
        let (operation, cancel) =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(60));
        let _publishing = self.syncs.register(operation.operation_id(), cancel);
        let account_key = Arc::new(account_key);
        let enrollment = self
            .runtime
            .block_on(client.prepare_account_key(
                &target,
                account_key.clone(),
                &identity,
                operation,
            ))
            .map_err(LocalError::from)?;
        if (
            enrollment.storage_id.as_str(),
            enrollment.server_id.as_str(),
            enrollment.account_subject.as_str(),
        ) != (storage.as_str(), server.as_str(), subject.as_str())
        {
            return Err(LocalError::InvalidArgument(
                "account changed during enrollment".into(),
            ));
        }
        let id = Uuid::parse_str(&storage)
            .map_err(|_| LocalError::InvalidArgument("invalid storage id".into()))?;
        let pool = self.pool();
        let vaults = self
            .runtime
            .block_on(LocalVaultRepo::new(&pool).list_by_storage(id))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        self.verify_storage_keys(&account_key, &vaults)?;
        let keyring = self.device_unlock()?;
        let mut candidate = keyring.clone();
        candidate
            .insert_account(&root, storage.clone(), server, subject, &account_key)
            .map_err(keyring_error)?;
        let keys = candidate.account_keys(&root).map_err(keyring_error)?;
        let vault = preferred_vault(&self.runtime, &pool, id, &vaults)?;
        let _context = self.context_gate.write().expect("lock poisoned");
        self.check_context_generation(generation)?;
        self.commit_device_unlock(Some(&keyring), &candidate)?;
        *self.account_keys.lock().expect("lock poisoned") = keys;
        *self.storage_id.lock().expect("lock poisoned") = Some(id);
        *self.vault_id.lock().expect("lock poisoned") = vault;
        self.item_reads.cancel_all();
        self.context_generation.fetch_add(1, Ordering::SeqCst);
        Ok(VaultStatus { unlocked: true })
    }

    pub(super) fn account_key_for_target(
        &self,
        target: &SessionTarget,
    ) -> LocalResult<Arc<SecretKey>> {
        let (storage, server, subject) = self
            .app_client()?
            .account_key_binding(target)
            .map_err(keyring_error)?;
        let keyring = self.device_unlock()?;
        let envelope = keyring.accounts.get(&storage).ok_or_else(|| {
            LocalError::InvalidArgument("enroll this account's encryption key first".into())
        })?;
        if envelope.server_id != server || envelope.account_subject != subject {
            return Err(LocalError::InvalidArgument(
                "account encryption key binding mismatch".into(),
            ));
        }
        let id = Uuid::parse_str(&storage)
            .map_err(|_| LocalError::InvalidArgument("invalid storage id".into()))?;
        self.account_key_for_storage(id)
    }
}
