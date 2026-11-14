//! Explicit storage selection; item operations hold the matching read lease.
use super::*;

impl LocalVault {
    pub(super) fn check_context_generation(&self, expected: u64) -> LocalResult<()> {
        if self.context_generation.load(Ordering::SeqCst) != expected {
            return Err(LocalError::Sync {
                kind: "context_changed".into(),
                message: "the open storage changed during the operation".into(),
            });
        }
        Ok(())
    }

    pub(super) fn verify_storage_keys(
        &self,
        master_key: &SecretKey,
        vaults: &[zann_db::local::LocalVault],
    ) -> LocalResult<()> {
        let pool = self.pool();
        let services = LocalServices::new(&pool, master_key);
        for vault in vaults {
            services
                .decrypt_vault_key(vault)
                .map_err(|source| LocalError::Unlock {
                    kind: "storage_key_mismatch".into(),
                    message: "this storage cannot be opened with the current master key".into(),
                    source: Box::new(source),
                })?;
        }
        Ok(())
    }

    /// Resolves cached keys using their canonical wrapping policy before
    /// publishing storage and vault together.
    pub fn set_current_storage(&self, id: String) -> LocalResult<()> {
        let _context = self.context_gate.write().expect("lock poisoned");
        let id =
            Uuid::parse_str(&id).map_err(|error| LocalError::InvalidArgument(error.to_string()))?;
        let pool = self.pool();
        self.runtime
            .block_on(LocalStorageRepo::new(&pool).get(id))
            .map_err(|error| LocalError::Service(error.to_string()))?
            .ok_or_else(|| LocalError::InvalidArgument("storage not found".into()))?;
        let master_key = self.master_key()?;
        let selected_vault = {
            let vaults = self
                .runtime
                .block_on(LocalVaultRepo::new(&pool).list_by_storage(id))
                .map_err(|error| LocalError::Service(error.to_string()))?;
            self.verify_storage_keys(&master_key, &vaults)?;
            preferred_vault(&self.runtime, &pool, id, &vaults)?
        };
        *self.storage_id.lock().expect("lock poisoned") = Some(id);
        *self.vault_id.lock().expect("lock poisoned") = selected_vault;
        self.item_reads.cancel_all();
        self.context_generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
