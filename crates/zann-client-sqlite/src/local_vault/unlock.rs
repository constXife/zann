use super::*;

impl LocalVault {
    pub fn core_info(&self) -> String {
        format!("zann-core {}", env!("CARGO_PKG_VERSION"))
    }

    pub fn unlock(&self, password: String) -> LocalResult<VaultStatus> {
        let password = zeroize::Zeroizing::new(password);
        let generation = self.context_generation.load(Ordering::SeqCst);
        let keyring = self.device_unlock()?;
        let root = keyring.open(&password).map_err(keyring_error)?;
        self.finish_unlock(root, generation)
    }

    pub fn remembered_unlock(&self) -> LocalResult<RememberedUnlock> {
        let remembered = self.load_remembered()?;
        Ok(RememberedUnlock {
            armed: remembered.is_armed(),
            source: match remembered.unlock_source {
                UnlockSource::Keystore => "keystore".to_string(),
                UnlockSource::HardwareKey => "hardware_key".to_string(),
            },
            hardware_keys: remembered
                .hardware_keys
                .iter()
                .map(|entry| HardwareKey {
                    label: entry.label.clone(),
                    credential_id: entry.credential_id.clone(),
                    enrolled_at: entry.enrolled_at.clone(),
                })
                .collect(),
            hardware_supported: self.authenticator.supported(),
        })
    }

    /// Unlock using whichever source this device has armed. Blocks on a touch
    /// when that source is a hardware key.
    pub fn unlock_remembered(&self) -> LocalResult<VaultStatus> {
        let generation = self.context_generation.load(Ordering::SeqCst);
        let remembered = self.load_remembered()?;
        let master_key = match remembered.unlock_source {
            UnlockSource::Keystore => remembered.unlock_with_keystore(self.keystore.as_ref()),
            UnlockSource::HardwareKey => {
                remembered.unlock_with_hardware_key(self.authenticator.as_ref())
            }
        }
        .map_err(unlock_error)?;
        self.finish_unlock(Arc::new(SecretKey::from_bytes(master_key)), generation)
    }

    /// Whether an enrolled authenticator is connected. Silent: no touch, so
    /// this is safe to poll for auto-lock.
    pub fn hardware_key_present(&self) -> LocalResult<bool> {
        Ok(self
            .load_remembered()?
            .connected_hardware_key(self.authenticator.as_ref())
            .is_some())
    }

    pub fn remove_hardware_key(&self, credential_id: String) -> LocalResult<()> {
        let mut remembered = self.load_remembered()?;
        remembered.remove_hardware_key(&credential_id);
        self.save_remembered(&remembered)
    }

    /// Remember the unlock in the OS credential store instead.
    pub fn remember_with_keystore(&self) -> LocalResult<()> {
        let master_key = {
            let _context = self.context_gate.read().expect("lock poisoned");
            self.root_key()?
        };
        let mut remembered = self.load_remembered()?;
        remembered
            .remember_with_keystore(self.keystore.as_ref(), master_key.as_bytes())
            .map_err(unlock_error)?;
        let _context = self.context_gate.write().expect("lock poisoned");
        if !Arc::ptr_eq(&self.root_key()?, &master_key) {
            return Err(LocalError::Locked);
        }
        self.save_remembered(&remembered)
    }

    /// Stop remembering entirely. Enrolled authenticators are left alone: they
    /// carry their own copies and removing them is a separate, explicit act.
    pub fn forget_remembered(&self) -> LocalResult<()> {
        let mut remembered = self.load_remembered()?;
        remembered
            .forget_keystore(self.keystore.as_ref())
            .map_err(unlock_error)?;
        self.save_remembered(&remembered)
    }

    /// Drops the master key and cancels pending item reads and syncs, so their
    /// copies do not remain alive while waiting for SQLite or the server.
    pub fn lock(&self) -> LocalResult<VaultStatus> {
        let context = self.context_gate.write().expect("lock poisoned");
        self.lock_in_context(&context)
    }

    pub(super) fn lock_in_context(
        &self,
        _context: &std::sync::RwLockWriteGuard<'_, ()>,
    ) -> LocalResult<VaultStatus> {
        self.context_generation.fetch_add(1, Ordering::SeqCst);
        *self.device_key.lock().expect("lock poisoned") = None;
        self.account_keys.lock().expect("lock poisoned").clear();
        *self.vault_id.lock().expect("lock poisoned") = None;
        self.syncs.cancel_all();
        self.item_reads.cancel_all();
        Ok(VaultStatus { unlocked: false })
    }

    pub fn vault_status(&self) -> LocalResult<VaultStatus> {
        let unlocked = self.device_key.lock().expect("lock poisoned").is_some();
        Ok(VaultStatus { unlocked })
    }

    pub fn initialize_master_password(&self, password: String) -> LocalResult<VaultStatus> {
        let password = zeroize::Zeroizing::new(password);
        let _context = self.context_gate.write().expect("lock poisoned");
        if self.device_unlock_optional()?.is_some() {
            return Err(LocalError::InvalidArgument(
                "Zann unlock password is already set".into(),
            ));
        }
        let (keyring, root) =
            zann_client::app::unlock::DeviceUnlock::create(&password).map_err(keyring_error)?;
        self.commit_device_unlock(None, &keyring)?;
        *self.device_key.lock().expect("lock poisoned") = Some(root);
        self.context_generation.fetch_add(1, Ordering::SeqCst);
        Ok(VaultStatus { unlocked: true })
    }

    pub fn change_unlock_password(&self, current: String, replacement: String) -> LocalResult<()> {
        let current = zeroize::Zeroizing::new(current);
        let replacement = zeroize::Zeroizing::new(replacement);
        let generation = self.context_generation.load(Ordering::SeqCst);
        let root = self.root_key()?;
        let keyring = self.device_unlock()?;
        keyring.check_root(&root).map_err(keyring_error)?;
        let candidate = keyring
            .rewrap(&current, &replacement)
            .map_err(keyring_error)?;
        let _context = self.context_gate.write().expect("lock poisoned");
        self.check_context_generation(generation)?;
        self.commit_device_unlock(Some(&keyring), &candidate)
    }

    pub(super) fn finish_unlock(
        &self,
        root: Arc<SecretKey>,
        generation: u64,
    ) -> LocalResult<VaultStatus> {
        let keyring = self.device_unlock()?;
        let keys = keyring.account_keys(&root).map_err(keyring_error)?;
        let pool = self.pool();
        let storage = *self.storage_id.lock().expect("lock poisoned");
        let storage = storage
            .filter(|id| keys.contains_key(&id.to_string()))
            .or_else(|| keys.keys().find_map(|id| Uuid::parse_str(id).ok()));
        let vault = if let Some(storage) = storage {
            let vaults = self
                .runtime
                .block_on(LocalVaultRepo::new(&pool).list_by_storage(storage))
                .map_err(|err| LocalError::Service(err.to_string()))?;
            self.verify_storage_keys(&keys[&storage.to_string()], &vaults)?;
            preferred_vault(&self.runtime, &pool, storage, &vaults)?
        } else {
            None
        };
        let _context = self.context_gate.write().expect("lock poisoned");
        self.check_context_generation(generation)?;
        *self.device_key.lock().expect("lock poisoned") = Some(root);
        *self.account_keys.lock().expect("lock poisoned") = keys;
        *self.storage_id.lock().expect("lock poisoned") = storage;
        *self.vault_id.lock().expect("lock poisoned") = vault;
        self.context_generation.fetch_add(1, Ordering::SeqCst);
        Ok(VaultStatus { unlocked: true })
    }
}

pub(super) fn keyring_error<E: std::error::Error + Send + Sync + 'static>(source: E) -> LocalError {
    LocalError::Unlock {
        kind: "device_unlock".into(),
        message: source.to_string(),
        source: Box::new(source),
    }
}
