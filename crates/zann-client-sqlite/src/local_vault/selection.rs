//! Selection among server replicas, including disconnected offline caches.
use super::*;

pub(super) fn resolve_storage_id(
    runtime: &Runtime,
    pool: &SqlitePool,
) -> LocalResult<Option<Uuid>> {
    let storages = runtime
        .block_on(LocalStorageRepo::new(pool).list())
        .map_err(|err| LocalError::Service(err.to_string()))?;
    for storage in &storages {
        let vaults = runtime
            .block_on(LocalVaultRepo::new(pool).list_by_storage(storage.id))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        if !vaults.is_empty() {
            return Ok(Some(storage.id));
        }
    }
    Ok(storages.first().map(|storage| storage.id))
}

/// The vault to show first in `storage_id`: the one holding the most items,
/// else the default vault, else the personal one, else the first.
pub(super) fn preferred_vault(
    runtime: &Runtime,
    pool: &SqlitePool,
    storage_id: Uuid,
    vaults: &[zann_db::local::LocalVault],
) -> LocalResult<Option<Uuid>> {
    let seed = vaults
        .iter()
        .find(|vault| vault.is_default)
        .or_else(|| {
            vaults
                .iter()
                .find(|vault| vault.kind == zann_core::VaultKind::Personal)
        })
        .or_else(|| vaults.first());
    let Some(seed) = seed else {
        return Ok(None);
    };
    let item_repo = LocalItemRepo::new(pool);
    let mut selected = (seed.id, 0u64);
    for vault in vaults {
        let count = runtime
            .block_on(item_repo.count_by_vault(storage_id, vault.id))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        if count as u64 > selected.1 {
            selected = (vault.id, count as u64);
        }
    }
    Ok(Some(selected.0))
}

impl LocalVault {
    /// A first catalog can select a vault only in the unlock that requested it.
    /// Keep the key guard through publication, so lock cannot be undone by a
    /// sync whose remote commit completed just before cancellation.
    pub(super) fn select_synced_catalog(
        &self,
        synced_storage: Option<String>,
        selection_before: Option<Uuid>,
        operation_key: &Arc<SecretKey>,
        generation: u64,
    ) -> LocalResult<()> {
        let _context = self.context_gate.write().expect("lock poisoned");
        let key = self.account_keys.lock().expect("lock poisoned");
        if !key
            .values()
            .any(|current| Arc::ptr_eq(current, operation_key))
        {
            return Err(LocalError::Locked);
        }
        if self.context_generation.load(Ordering::SeqCst) != generation {
            return Ok(());
        }
        let mut storage = self.storage_id.lock().expect("lock poisoned");
        let mut selected_vault = self.vault_id.lock().expect("lock poisoned");
        if selected_vault.is_some() || *storage != selection_before {
            return Ok(());
        }
        let pool = self.pool();
        let target = match synced_storage {
            Some(id) => {
                let target = Uuid::parse_str(&id)
                    .map_err(|_| LocalError::InvalidArgument("invalid storage id".into()))?;
                // The caller can reach Rust after explicit navigation already
                // selected another empty replica. Its old target cannot win.
                if selection_before.is_some_and(|selected| selected != target) {
                    return Ok(());
                }
                Some(target)
            }
            None => match selection_before {
                Some(selected) => Some(selected),
                None => resolve_storage_id(&self.runtime, &pool)?,
            },
        };
        let Some(target) = target else {
            return Ok(());
        };
        let vaults = self
            .runtime
            .block_on(LocalVaultRepo::new(&pool).list_by_storage(target))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        let vault = preferred_vault(&self.runtime, &pool, target, &vaults)?;
        *storage = Some(target);
        *selected_vault = vault;
        self.item_reads.cancel_all();
        self.context_generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_completed_sync_cannot_reopen_a_locked_or_later_unlocked_session() {
        let root = crate::test_support::CanonicalTempDir::new("sync-selection");
        let core = open_vault(format!(
            "sqlite://{}",
            root.path().join("cache.sqlite").display()
        ))
        .expect("open");
        core.seed_offline_fixture("fixture master password".into())
            .expect("fixture");
        let key = core.account_key().expect("key");
        let storage = Some(core.storage_id().expect("storage"));
        core.lock().expect("lock");
        assert!(matches!(
            core.select_synced_catalog(
                None,
                storage,
                &key,
                core.context_generation.load(Ordering::SeqCst)
            ),
            Err(LocalError::Locked)
        ));
        assert!(!core.vault_status().expect("status").unlocked);
        core.unlock("fixture master password".into())
            .expect("new unlock");
        assert!(matches!(
            core.select_synced_catalog(
                None,
                storage,
                &key,
                core.context_generation.load(Ordering::SeqCst)
            ),
            Err(LocalError::Locked)
        ));
    }
    #[test]
    fn an_unlocked_empty_server_catalog_has_no_synthetic_personal_vault() {
        let root = crate::test_support::CanonicalTempDir::new("empty-catalog");
        let core = open_vault(format!(
            "sqlite://{}",
            root.path().join("cache.sqlite").display()
        ))
        .expect("open");
        core.seed_offline_fixture("fixture master password".into())
            .expect("fixture");
        let storage = core.storage_id().expect("storage");
        core.runtime
            .block_on(LocalVaultRepo::new(&core.pool()).delete_by_storage(storage))
            .expect("empty catalog");
        core.set_current_storage(storage.to_string())
            .expect("select storage");
        assert!(core.app_status().expect("account initialized").initialized);
        assert!(core.list_vaults().expect("vaults").is_empty());
        assert!(core.current_vault_id().is_none());
        let page = core
            .items_list(
                ItemsFilter {
                    query: None,
                    include_deleted: false,
                },
                Page {
                    limit: 10,
                    cursor: None,
                },
            )
            .expect("empty list");
        assert!(page.items.is_empty());
        assert_eq!(page.total_count, 0);
    }
}
