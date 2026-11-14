//! Explicit offline-ready server replica for tests and development tools.
//! Feature-gated out of production builds. Never creates authenticated sessions.
use super::*;
use zann_client::app::ConfigKdfParams;
use zann_db::local::LocalStorage;

impl LocalVault {
    pub fn seed_offline_fixture(&self, password: String) -> LocalResult<VaultStatus> {
        if !self.list_storages()?.is_empty() || self.app_status()?.initialized {
            return Err(LocalError::InvalidArgument(
                "fixture requires an empty client root".into(),
            ));
        }
        let identity = ConfigIdentity {
            kdf_salt: "c3ludGhldGljLWFjY291bnQtc2FsdC1maXh0dXJlAAA=".into(),
            kdf_params: ConfigKdfParams {
                algorithm: "argon2id".into(),
                iterations: 2,
                memory_kb: 19456,
                parallelism: 1,
            },
            salt_fingerprint: None,
            first_seen_at: None,
            email: Some("fixture@example.test".into()),
        };
        self.initialize_master_password(password.clone())?;
        let master_key = Arc::new(derive_master_key(&password, &identity)?);
        let pool = self.pool();
        let storage_id = Uuid::now_v7();
        let storage = LocalStorage {
            id: storage_id,
            kind: zann_core::StorageKind::Remote,
            name: "Offline fixture".into(),
            server_url: Some("https://fixture.example.test".into()),
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: true,
            auth_method: None,
        };
        self.runtime
            .block_on(LocalStorageRepo::new(&pool).upsert(&storage))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        let id = Uuid::now_v7();
        let key = SecretKey::generate();
        let vault = zann_db::local::LocalVault {
            id,
            storage_id,
            slug: "personal".into(),
            name: "Personal".into(),
            kind: zann_core::VaultKind::Personal,
            is_default: true,
            vault_key_enc: vault_crypto::encrypt_vault_key(&master_key, id, &key)
                .map_err(|err| LocalError::Service(err.to_string()))?,
            key_wrap_type: zann_db::local::KeyWrapType::Master,
            cache_key_fp: Some(vault_crypto::cache_key_fingerprint(&key)),
            last_synced_at: None,
        };
        self.runtime
            .block_on(LocalVaultRepo::new(&pool).create(&vault))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        let keyring = self.device_unlock()?;
        let mut candidate = keyring.clone();
        let root = self.root_key()?;
        candidate
            .insert_account(
                &root,
                storage_id.to_string(),
                "fixture-server".into(),
                "fixture-account".into(),
                &master_key,
            )
            .map_err(unlock::keyring_error)?;
        self.commit_device_unlock(Some(&keyring), &candidate)?;
        *self.storage_id.lock().expect("lock poisoned") = Some(storage_id);
        self.finish_unlock(root, self.context_generation.load(Ordering::SeqCst))
    }
    /// A second synthetic account for native navigation tests. Its wrapping key
    /// is independent, even when vault UUIDs coincide between the replicas.
    pub fn seed_offline_storage(
        &self,
        id: String,
        name: String,
        server_url: String,
    ) -> LocalResult<String> {
        let _context = self.context_gate.write().expect("lock poisoned");
        let id = Uuid::parse_str(&id)
            .map_err(|_| LocalError::InvalidArgument("invalid fixture storage id".into()))?;
        let pool = self.pool();
        let source = self.storage_id()?;
        let source_key = self.account_key()?;
        let target_key = Arc::new(SecretKey::generate());
        let root = self.root_key()?;
        let keyring = self.device_unlock()?;
        let mut candidate = keyring.clone();
        candidate
            .insert_account(
                &root,
                id.to_string(),
                "synthetic-additional-server".into(),
                id.to_string(),
                &target_key,
            )
            .map_err(unlock::keyring_error)?;
        let vaults = self
            .runtime
            .block_on(LocalVaultRepo::new(&pool).list_by_storage(source))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        let storage = LocalStorage {
            id,
            kind: zann_core::StorageKind::Remote,
            name,
            server_url: Some(server_url),
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: true,
            auth_method: None,
        };
        self.commit_device_unlock(Some(&keyring), &candidate)?;
        self.runtime
            .block_on(LocalStorageRepo::new(&pool).upsert(&storage))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        for mut vault in vaults
            .into_iter()
            .filter(|v| v.kind == zann_core::VaultKind::Personal)
        {
            vault.vault_key_enc = vault_crypto::rewrap_vault_key(
                &source_key,
                &target_key,
                vault.id,
                &vault.vault_key_enc,
            )
            .map_err(unlock::keyring_error)?;
            vault.storage_id = id;
            self.runtime
                .block_on(LocalVaultRepo::new(&pool).create(&vault))
                .map_err(|err| LocalError::Service(err.to_string()))?;
        }
        self.account_keys
            .lock()
            .expect("lock poisoned")
            .insert(id.to_string(), target_key);
        Ok(id.to_string())
    }
}
