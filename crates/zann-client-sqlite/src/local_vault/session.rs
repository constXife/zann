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
        let storage_id = self.storage_id()?;
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
                kind: vault.kind,
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
            .block_on(repo.list_by_storage(self.storage_id()?))
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
                kind: "remote".to_string(),
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
        *self.storage_id.lock().expect("lock poisoned") = Some(storage_id);
        *self.vault_id.lock().expect("lock poisoned") = None; // Clear selected vault
        Ok(())
    }

    pub fn current_storage_id(&self) -> LocalResult<String> {
        Ok(self.storage_id()?.to_string())
    }

    pub fn app_status(&self) -> LocalResult<AppStatus> {
        let pool = self.pool();
        let storage_repo = LocalStorageRepo::new(&pool);

        let storages = self
            .runtime
            .block_on(storage_repo.list())
            .map_err(|err| LocalError::Service(err.to_string()))?;

        let storages_count = storages.len() as u64;

        // A server cache can have an empty catalog (e.g. personal vaults disabled).
        // No local vault is invented to mark the account initialized.
        let initialized = !storages.is_empty() && self.kdf_identity()?.is_some();

        let locked = self.master_key.lock().expect("lock poisoned").is_none();
        let server_connected = self.app_client()?.configured_target(None).is_ok();

        Ok(AppStatus {
            initialized,
            locked,
            storages_count,
            server_connected,
        })
    }

    /// Runs until done or until [`Self::lock`] cancels it.
    pub fn remote_sync(&self, storage_id: Option<String>) -> LocalResult<LocalSyncOutcome> {
        let (operation, cancel) = SessionOperation::new(
            std::time::Instant::now() + std::time::Duration::from_secs(10 * 60),
        );
        // Registered before the key is read: a lock that clears the key after
        // this point always finds the sync to cancel.
        let _in_flight = self.syncs.register(operation.operation_id(), cancel);
        let master_key = self.master_key()?;
        let client = self.app_client()?;
        let target = client
            .configured_target(storage_id.as_deref())
            .map_err(|error| LocalError::Service(error.to_string()))?;
        let selection_before = *self.storage_id.lock().expect("lock poisoned");
        let synced_storage = storage_id;
        let operation_key = SecretKey::from_bytes(*master_key.as_bytes());
        let outcome = self
            .runtime
            .block_on(client.sync(target, operation_key, operation))
            .map_err(LocalError::from)?;
        self.select_synced_catalog(synced_storage, selection_before, &master_key)?;
        Ok(LocalSyncOutcome::from(outcome))
    }

    /// Removes the storage's complete local projection. This is the recovery
    /// path for a rebuilt or re-trusted server: the next sync rebuilds the
    /// projection from scratch. The reset fails while any unconfirmed local
    /// change would be discarded.
    pub fn sync_reset(&self, storage_id: Option<String>) -> LocalResult<()> {
        let master_key = self.master_key()?;
        let client = self.app_client()?;
        let target = client
            .configured_target(storage_id.as_deref())
            .map_err(|error| LocalError::Service(error.to_string()))?;
        let operation_key = SecretKey::from_bytes(*master_key.as_bytes());
        self.runtime
            .block_on(client.reset_sync(target, operation_key))
            .map_err(LocalError::from)
    }

    pub fn storage_sync_state(&self, storage_id: String) -> LocalResult<StorageSyncState> {
        let id = Uuid::parse_str(&storage_id)
            .map_err(|_| LocalError::InvalidArgument("invalid storage id".to_string()))?;
        let pool = self.pool();
        let storage = self
            .runtime
            .block_on(LocalStorageRepo::new(&pool).get(id))
            .map_err(|err| LocalError::Service(err.to_string()))?
            .ok_or_else(|| LocalError::InvalidArgument("storage not found".to_string()))?;
        let link = if self
            .app_client()?
            .syncs_storage(&storage_id)
            .map_err(LocalError::from)?
        {
            StorageLink::Connected
        } else {
            StorageLink::Disconnected
        };
        let last_synced_at = self
            .runtime
            .block_on(SyncCursorRepo::new(&pool).last_synced_at(id))
            .map_err(|err| LocalError::Service(err.to_string()))?
            .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        Ok(StorageSyncState {
            link,
            server_url: storage.server_url,
            pending_changes: self.pending_change_count(storage_id)?,
            last_synced_at,
        })
    }

    pub fn pending_change_count(&self, storage_id: String) -> LocalResult<u64> {
        let storage_id = Uuid::parse_str(&storage_id)
            .map_err(|_| LocalError::InvalidArgument("invalid storage id".to_string()))?;
        let pool = self.pool();
        self.runtime
            .block_on(PendingChangeRepo::new(&pool).count_by_storage(storage_id))
            .map_err(|err| LocalError::Service(err.to_string()))
    }

    pub fn forget_server(&self, storage_id: String) -> LocalResult<Option<String>> {
        self.app_client()?
            .remove_storage_connection(&storage_id)
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
        let client = self.app_client()?;
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
