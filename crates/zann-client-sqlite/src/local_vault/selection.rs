//! Which storage, and which vault in it, the open session shows. One rule
//! serves opening the database, unlocking and syncing, so every shell lands
//! on the same vault and the choice survives a restart.

use super::*;

/// The storage holding the most items, among those holding any vault. When
/// none holds an item, a server's storage wins over the local one: on a
/// device signed in to a server, the local vault only exists because creating
/// the master password made it. A storage without vaults is never picked, so
/// unlocking always has a vault key to check the password against.
pub(super) fn resolve_storage_id(runtime: &Runtime, pool: &SqlitePool) -> LocalResult<Uuid> {
    let storages = runtime
        .block_on(LocalStorageRepo::new(pool).list())
        .map_err(|err| LocalError::Service(err.to_string()))?;
    let mut fullest: Option<(Uuid, u64)> = None;
    let mut remote_with_vaults = None;
    for storage in &storages {
        let Some(count) = storage_item_count(runtime, pool, storage.id)? else {
            continue;
        };
        if count > fullest.map_or(0, |(_, most)| most) {
            fullest = Some((storage.id, count));
        }
        if storage.kind == zann_core::StorageKind::Remote && remote_with_vaults.is_none() {
            remote_with_vaults = Some(storage.id);
        }
    }
    Ok(fullest
        .map(|(id, _)| id)
        .or(remote_with_vaults)
        .unwrap_or(Uuid::nil()))
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

/// Items across the storage's vaults, or `None` when it holds no vault.
fn storage_item_count(
    runtime: &Runtime,
    pool: &SqlitePool,
    storage_id: Uuid,
) -> LocalResult<Option<u64>> {
    let vaults = runtime
        .block_on(LocalVaultRepo::new(pool).list_by_storage(storage_id))
        .map_err(|err| LocalError::Service(err.to_string()))?;
    if vaults.is_empty() {
        return Ok(None);
    }
    let item_repo = LocalItemRepo::new(pool);
    let mut total = 0u64;
    for vault in vaults {
        let count = runtime
            .block_on(item_repo.count_by_vault(storage_id, vault.id))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        total = total.saturating_add(count as u64);
    }
    Ok(Some(total))
}

impl LocalVault {
    /// Moves an unlocked session whose storage holds no item to the storage
    /// a fresh start would open. A client calls it once after the first sync
    /// of a newly connected server, which lands the device in that server's
    /// personal vault. A storage with items is never left behind.
    pub fn follow_preferred_storage(&self) -> LocalResult<()> {
        let _context = self.context_gate.write().expect("lock poisoned");
        self.master_key()?;
        let pool = self.pool();
        // Held across the check and the switch, so a concurrent selection
        // change cannot interleave with them.
        let mut storage_id = self.storage_id.lock().expect("lock poisoned");
        if storage_item_count(&self.runtime, &pool, *storage_id)?.unwrap_or(0) > 0 {
            return Ok(());
        }
        let resolved = resolve_storage_id(&self.runtime, &pool)?;
        if resolved == *storage_id {
            return Ok(());
        }
        let vaults = self
            .runtime
            .block_on(LocalVaultRepo::new(&pool).list_by_storage(resolved))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        let Some(vault_id) = preferred_vault(&self.runtime, &pool, resolved, &vaults)? else {
            return Ok(());
        };
        self.verify_storage_keys(self.master_key()?.as_ref(), &vaults)?;
        *self.vault_id.lock().expect("lock poisoned") = Some(vault_id);
        *storage_id = resolved;
        self.item_reads.cancel_all();
        self.context_generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_storages_prefer_the_server_over_the_local_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::new().expect("runtime");
        let location =
            SqliteFileLocation::from_path(&dir.path().join("local.sqlite")).expect("location");
        let pool = runtime
            .block_on(connect_sqlite_file_with_max(&location, 1))
            .expect("connect");
        runtime.block_on(migrate_local(&pool)).expect("migrate");
        // The migrations seed the one local storage.
        assert_eq!(
            resolve_storage_id(&runtime, &pool).expect("resolve"),
            Uuid::nil()
        );

        let remote = LocalStorage {
            id: Uuid::now_v7(),
            kind: zann_core::StorageKind::Remote,
            name: "Remote".to_string(),
            server_url: Some("https://zann.example.test".to_string()),
            server_name: None,
            server_fingerprint: None,
            account_subject: None,
            personal_vaults_enabled: true,
            auth_method: None,
        };
        runtime
            .block_on(LocalStorageRepo::new(&pool).upsert(&remote))
            .expect("remote");
        // A sync that failed after writing the storage row leaves it without
        // vaults; it must not win, or unlocking would have nothing to verify.
        assert_eq!(
            resolve_storage_id(&runtime, &pool).expect("resolve"),
            Uuid::nil()
        );

        for (storage_id, kind) in [
            (Uuid::nil(), zann_core::VaultKind::Personal),
            (remote.id, zann_core::VaultKind::Personal),
        ] {
            let id = Uuid::now_v7();
            runtime
                .block_on(LocalVaultRepo::new(&pool).insert_if_absent(
                    &zann_db::local::LocalVault {
                        id,
                        storage_id,
                        slug: zann_db::local::LocalVault::local_slug(id),
                        name: "Personal".to_string(),
                        kind,
                        is_default: storage_id.is_nil(),
                        vault_key_enc: vec![1; 72],
                        key_wrap_type: zann_db::local::KeyWrapType::Master,
                        cache_key_fp: None,
                        last_synced_at: None,
                    },
                ))
                .expect("vault");
        }
        assert_eq!(
            resolve_storage_id(&runtime, &pool).expect("resolve"),
            remote.id
        );
    }
}
