//! Explicit offline-ready server replica for tests and development tools.
//! Feature-gated out of production builds. Never creates authenticated sessions.
use super::*;
use zann_client::app::ConfigKdfParams;
use zann_db::local::LocalStorage;

impl LocalVault {
    pub fn seed_offline_fixture(&self, password: String) -> LocalResult<VaultStatus> {
        if !self.list_storages()?.is_empty() || self.kdf_identity()?.is_some() {
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
        self.app_client()?
            .replace_kdf_identity_if_matches(None, identity)
            .map_err(|err| LocalError::Service(err.to_string()))?;
        *self.storage_id.lock().expect("lock poisoned") = Some(storage_id);
        self.finish_unlock(master_key, self.context_generation.load(Ordering::SeqCst))
    }
}
