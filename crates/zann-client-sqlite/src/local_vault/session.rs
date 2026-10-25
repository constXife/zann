use super::*;

impl LocalVault {
    pub fn current_vault_id(&self) -> Option<String> {
        self.vault_id
            .lock()
            .expect("lock poisoned")
            .map(|id| id.to_string())
    }

    pub fn list_vaults(&self) -> LocalResult<Vec<VaultSummary>> {
        let pool = self.pool();
        let repo = LocalVaultRepo::new(&pool);
        let item_repo = LocalItemRepo::new(&pool);
        let storage_id = self.storage_id();
        let vaults = self
            .runtime
            .block_on(repo.list_by_storage(storage_id))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        let mut result = Vec::with_capacity(vaults.len());
        for vault in vaults {
            let count = self
                .runtime
                .block_on(item_repo.count_by_vault(storage_id, vault.id))
                .map_err(|err| LocalError::Service(err.to_string()))?;
            result.push(VaultSummary {
                id: vault.id.to_string(),
                name: vault.name,
                kind: match vault.kind {
                    zann_core::VaultKind::Personal => "personal".to_string(),
                    zann_core::VaultKind::Shared => "shared".to_string(),
                },
                is_default: vault.is_default,
                item_count: count as u64,
            });
        }
        Ok(result)
    }

    pub fn set_current_vault(&self, id: String) -> LocalResult<VaultStatus> {
        let pool = self.pool();
        if self.master_key.lock().expect("lock poisoned").is_none() {
            return Err(LocalError::Locked);
        }
        let vault_id = Uuid::parse_str(&id)
            .map_err(|_| LocalError::InvalidArgument("invalid vault id".to_string()))?;
        let repo = LocalVaultRepo::new(&pool);
        let vaults = self
            .runtime
            .block_on(repo.list_by_storage(self.storage_id()))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        if !vaults.iter().any(|vault| vault.id == vault_id) {
            return Err(LocalError::InvalidArgument("vault not found".to_string()));
        }
        *self.vault_id.lock().expect("lock poisoned") = Some(vault_id);
        Ok(VaultStatus { unlocked: true })
    }

    pub fn list_storages(&self) -> LocalResult<Vec<StorageSummary>> {
        let pool = self.pool();
        let repo = LocalStorageRepo::new(&pool);
        let storages = self
            .runtime
            .block_on(repo.list())
            .map_err(|err| LocalError::Service(err.to_string()))?;
        Ok(storages
            .into_iter()
            .map(|s| StorageSummary {
                id: s.id.to_string(),
                name: s.name,
                kind: if s.kind == zann_core::StorageKind::LocalOnly {
                    "local"
                } else {
                    "remote"
                }
                .to_string(),
            })
            .collect())
    }

    pub fn set_current_storage(&self, id: String) -> LocalResult<()> {
        let pool = self.pool();
        let storage_id = Uuid::parse_str(&id)
            .map_err(|_| LocalError::InvalidArgument("invalid storage id".to_string()))?;
        let repo = LocalStorageRepo::new(&pool);
        let storages = self
            .runtime
            .block_on(repo.list())
            .map_err(|err| LocalError::Service(err.to_string()))?;
        if !storages.iter().any(|s| s.id == storage_id) {
            return Err(LocalError::InvalidArgument("storage not found".to_string()));
        }
        *self.storage_id.lock().expect("lock poisoned") = storage_id;
        *self.vault_id.lock().expect("lock poisoned") = None; // Clear selected vault
        Ok(())
    }

    pub fn current_storage_id(&self) -> String {
        self.storage_id().to_string()
    }

    pub fn app_status(&self) -> LocalResult<AppStatus> {
        let pool = self.pool();
        let storage_repo = LocalStorageRepo::new(&pool);
        let vault_repo = LocalVaultRepo::new(&pool);

        let storages = self
            .runtime
            .block_on(storage_repo.list())
            .map_err(|err| LocalError::Service(err.to_string()))?;

        let storages_count = storages.len() as u64;

        // Check if any vaults exist (indicates master password was set)
        let mut has_local_vault = false;
        let mut initialized = false;

        for storage in &storages {
            let vaults = self
                .runtime
                .block_on(vault_repo.list_by_storage(storage.id))
                .map_err(|err| LocalError::Service(err.to_string()))?;
            if !vaults.is_empty() {
                initialized = true;
                if storage.kind == zann_core::StorageKind::LocalOnly {
                    has_local_vault = true;
                }
            }
        }

        let locked = self.master_key.lock().expect("lock poisoned").is_none();

        Ok(AppStatus {
            initialized,
            locked,
            storages_count,
            has_local_vault,
        })
    }

    pub fn remote_sync(&self, storage_id: Option<String>) -> LocalResult<LocalSyncOutcome> {
        let master_key = self.master_key()?;
        let client = self.sync_app_client()?;
        let target = client
            .configured_target(storage_id.as_deref())
            .map_err(|error| LocalError::Service(error.to_string()))?;
        let operation = SessionOperation::new(
            std::time::Instant::now() + std::time::Duration::from_secs(10 * 60),
        )
        .0;
        let operation_key = SecretKey::from_bytes(*master_key.as_bytes());
        let outcome = self
            .runtime
            .block_on(client.sync(target, operation_key, operation))
            .map_err(LocalError::from)?;
        Ok(LocalSyncOutcome::from(outcome))
    }

    /// Removes the storage's complete local projection. This is the recovery
    /// path for a rebuilt or re-trusted server: the next sync rebuilds the
    /// projection from scratch. The reset fails while any unconfirmed local
    /// change would be discarded.
    pub fn sync_reset(&self, storage_id: Option<String>) -> LocalResult<()> {
        let master_key = self.master_key()?;
        let client = self.sync_app_client()?;
        let target = client
            .configured_target(storage_id.as_deref())
            .map_err(|error| LocalError::Service(error.to_string()))?;
        let operation_key = SecretKey::from_bytes(*master_key.as_bytes());
        self.runtime
            .block_on(client.reset_sync(target, operation_key))
            .map_err(LocalError::from)
    }

    /// Commits an already-authenticated legacy desktop session (live tokens
    /// from the legacy config plus its existing local storage id) as a Config
    /// v2 connection. Verifies the live server fingerprint and reads the
    /// account identity with the supplied access token; no login call is
    /// made and the master password is never required.
    #[allow(clippy::too_many_arguments)]
    pub fn import_legacy_account(
        &self,
        endpoint: String,
        connection_name: String,
        profile_name: String,
        storage_id: Option<String>,
        access_token: String,
        refresh_token: String,
        access_expires_at: Option<String>,
    ) -> LocalResult<()> {
        let client = self.sync_app_client()?;
        let access = CredentialSecret::new(access_token)
            .map_err(|_| LocalError::InvalidArgument("access token".to_string()))?;
        let refresh = CredentialSecret::new(refresh_token)
            .map_err(|_| LocalError::InvalidArgument("refresh token".to_string()))?;
        let expires_at = access_expires_at
            .as_deref()
            .map(chrono_datetime_from_rfc3339)
            .transpose()
            .map_err(|_| LocalError::InvalidArgument("access_expires_at".to_string()))?;
        let request = LegacySessionImport::new(
            endpoint,
            connection_name,
            profile_name,
            storage_id,
            access,
            refresh,
            expires_at,
        );
        let operation = SessionOperation::new(
            std::time::Instant::now() + std::time::Duration::from_secs(2 * 60),
        )
        .0;
        self.runtime
            .block_on(client.import_legacy_session(request, operation))
            .map(|_| ())
            .map_err(LocalError::from)
    }
}
