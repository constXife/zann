use super::*;

impl LocalVault {
    pub fn core_info(&self) -> String {
        format!("zann-core {}", env!("CARGO_PKG_VERSION"))
    }

    pub fn unlock(&self, password: String) -> LocalResult<VaultStatus> {
        let master_key = Arc::new(derive_master_key(&password, &self.identity())?);
        self.finish_unlock(master_key)
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
            hardware_supported: cfg!(any(target_os = "linux", target_os = "macos")),
        })
    }

    /// Unlock using whichever source this device has armed. Blocks on a touch
    /// when that source is a hardware key.
    pub fn unlock_remembered(&self) -> LocalResult<VaultStatus> {
        let remembered = self.load_remembered()?;
        let master_key = match remembered.unlock_source {
            UnlockSource::Keystore => remembered.unlock_with_keystore(default_keystore().as_ref()),
            UnlockSource::HardwareKey => remembered.unlock_with_hardware_key(),
        }
        .map_err(unlock_error)?;
        self.finish_unlock(Arc::new(SecretKey::from_bytes(master_key)))
    }

    /// Whether an enrolled authenticator is connected. Silent: no touch, so
    /// this is safe to poll for auto-lock.
    pub fn hardware_key_present(&self) -> LocalResult<bool> {
        Ok(self.load_remembered()?.connected_hardware_key().is_some())
    }

    /// Enrol the connected authenticator against the open vault. Two touches.
    pub fn enroll_hardware_key(&self, label: String) -> LocalResult<HardwareKey> {
        let master_key = self.master_key()?;
        let mut remembered = self.load_remembered()?;
        // The policy crate stays clock-free, so the timestamp is stamped here
        // rather than trusted from a caller.
        let entry = remembered
            .enroll_hardware_key(
                master_key.as_bytes(),
                &label,
                chrono::Utc::now().to_rfc3339(),
            )
            .map_err(unlock_error)?;
        remembered.unlock_source = UnlockSource::HardwareKey;
        self.save_remembered(&remembered)?;
        Ok(HardwareKey {
            label: entry.label,
            credential_id: entry.credential_id,
            enrolled_at: entry.enrolled_at,
        })
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
            .remember_with_keystore(default_keystore().as_ref(), master_key.as_bytes())
            .map_err(unlock_error)?;
        self.save_remembered(&remembered)
    }

    /// Stop remembering entirely. Enrolled authenticators are left alone: they
    /// carry their own copies and removing them is a separate, explicit act.
    pub fn forget_remembered(&self) -> LocalResult<()> {
        let mut remembered = self.load_remembered()?;
        remembered
            .forget_keystore(default_keystore().as_ref())
            .map_err(unlock_error)?;
        self.save_remembered(&remembered)
    }

    pub fn lock(&self) -> LocalResult<VaultStatus> {
        *self.master_key.lock().expect("lock poisoned") = None;
        *self.vault_id.lock().expect("lock poisoned") = None;
        Ok(VaultStatus { unlocked: false })
    }

    pub fn vault_status(&self) -> LocalResult<VaultStatus> {
        let unlocked = self.master_key.lock().expect("lock poisoned").is_some();
        Ok(VaultStatus { unlocked })
    }

    pub fn initialize_master_password(&self, password: String) -> LocalResult<VaultStatus> {
        let pool = self.pool();
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

        // Derive master key from password
        let master_key = Arc::new(derive_master_key(&password, &self.identity())?);

        // Create local storage if none exists
        let storage_repo = LocalStorageRepo::new(&pool);
        let storages = self
            .runtime
            .block_on(storage_repo.list())
            .map_err(|err| LocalError::Service(err.to_string()))?;

        let storage_id = if storages.is_empty() {
            let new_storage = LocalStorage {
                id: Uuid::now_v7(),
                kind: zann_core::StorageKind::LocalOnly,
                name: "Local".to_string(),
                server_url: None,
                server_name: None,
                server_fingerprint: None,
                account_subject: None,
                personal_vaults_enabled: true,
                auth_method: None,
            };
            self.runtime
                .block_on(storage_repo.upsert(&new_storage))
                .map_err(|err| LocalError::Service(err.to_string()))?;
            *self.storage_id.lock().expect("lock poisoned") = new_storage.id;
            new_storage.id
        } else {
            self.storage_id()
        };

        // Create the default vault
        let services = LocalServices::new(&pool, master_key.as_ref());
        let vault = self.runtime_block_on(services.ensure_default_local_personal())?;

        // Store master key and vault id
        *self.master_key.lock().expect("lock poisoned") = Some(master_key);
        *self.vault_id.lock().expect("lock poisoned") = Some(vault.id);
        *self.storage_id.lock().expect("lock poisoned") = storage_id;

        Ok(VaultStatus { unlocked: true })
    }
}
