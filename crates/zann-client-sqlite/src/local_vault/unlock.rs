use super::*;

impl LocalVault {
    pub fn core_info(&self) -> String {
        format!("zann-core {}", env!("CARGO_PKG_VERSION"))
    }

    pub fn unlock(&self, password: String) -> LocalResult<VaultStatus> {
        let generation = self.context_generation.load(Ordering::SeqCst);
        let identity = self
            .kdf_identity()?
            .ok_or_else(|| LocalError::InvalidArgument("vault is not initialized".to_string()))?;
        let master_key = Arc::new(derive_master_key(&password, &identity)?);
        self.finish_unlock(master_key, generation)
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
        let master_key = self.master_key()?;
        let mut remembered = self.load_remembered()?;
        remembered
            .remember_with_keystore(self.keystore.as_ref(), master_key.as_bytes())
            .map_err(unlock_error)?;
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
        let _context = self.context_gate.write().expect("lock poisoned");
        self.context_generation.fetch_add(1, Ordering::SeqCst);
        *self.master_key.lock().expect("lock poisoned") = None;
        *self.vault_id.lock().expect("lock poisoned") = None;
        self.syncs.cancel_all();
        self.item_reads.cancel_all();
        Ok(VaultStatus { unlocked: false })
    }

    pub fn vault_status(&self) -> LocalResult<VaultStatus> {
        let unlocked = self.master_key.lock().expect("lock poisoned").is_some();
        Ok(VaultStatus { unlocked })
    }

    pub fn initialize_master_password(&self, password: String) -> LocalResult<VaultStatus> {
        if password.len() < 8 {
            return Err(LocalError::InvalidArgument(
                "password must be at least 8 characters".to_string(),
            ));
        }

        // Check if already initialized
        let status = self.app_status()?;
        if status.initialized {
            return Err(LocalError::InvalidArgument(
                "vault already initialized".to_string(),
            ));
        }

        // Only authentication commits the account KDF identity.
        self.kdf_identity()?.ok_or_else(|| {
            LocalError::InvalidArgument(
                "sign in to a server before setting the master password".to_string(),
            )
        })?;
        self.unlock(password)
    }
}
