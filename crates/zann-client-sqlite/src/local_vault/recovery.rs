//! Scoped recovery over the existing encrypted snapshot and SQLite owners.
use super::*;
use zann_db::local::recovery::{RecoveryError, RecoverySource};
fn connection_error(source: zann_client::config::ConfigError) -> LocalError {
    let kind = if matches!(
        source,
        zann_client::config::ConfigError::RevisionConflict { .. }
            | zann_client::config::ConfigError::IdentityChanged
    ) {
        "recovery_changed"
    } else {
        "local_recovery_failed"
    };
    LocalError::Unlock {
        kind: kind.into(),
        message: source.to_string(),
        source: Box::new(source),
    }
}
fn storage_error(source: RecoveryError) -> LocalError {
    let kind = if matches!(source, RecoveryError::Changed) {
        "recovery_changed"
    } else {
        "local_recovery_failed"
    };
    LocalError::Unlock {
        kind: kind.into(),
        message: source.to_string(),
        source: Box::new(source),
    }
}

pub(super) struct PreparedRecovery {
    preview: RecoveryPreview,
    generation: u64,
    source: RecoverySource,
    connection: Option<zann_client::app::AccountRemovalPlan>,
}
pub(super) fn failure(code: &'static str) -> LocalError {
    LocalError::Unlock {
        kind: code.into(),
        message: code.into(),
        source: Box::new(std::io::Error::other(code)),
    }
}
impl LocalVault {
    pub fn setup_accounts(&self) -> LocalResult<Vec<SetupAccount>> {
        let _context = self.context_gate.read().expect("context lock");
        self.verify_database()?;
        let configured = self
            .app_client()?
            .account_locations()
            .map_err(unlock::keyring_error)?;
        let keyring = self.device_unlock_optional()?;
        let pool = self.pool();
        let storages = self
            .runtime
            .block_on(LocalStorageRepo::new(&pool).list())
            .map_err(unlock::keyring_error)?;
        let present: std::collections::BTreeSet<_> =
            storages.iter().map(|s| s.id.to_string()).collect();
        let mut locations: std::collections::BTreeMap<_, _> = configured
            .into_iter()
            .map(|account| (account.storage_id.clone(), account))
            .collect();
        for storage in storages {
            let id = storage.id.to_string();
            if let std::collections::btree_map::Entry::Vacant(entry) = locations.entry(id.clone()) {
                entry.insert(AccountLocation {
                    storage_id: id,
                    name: storage.name,
                    account_name: None,
                    key_binding: None,
                    server_url: storage
                        .server_url
                        .ok_or_else(|| failure("recovery_invalid_account"))?,
                });
            }
        }
        if locations.len() > 256 {
            return Err(failure("recovery_limit"));
        }
        Ok(locations
            .into_values()
            .map(|location| SetupAccount {
                enrolled: keyring
                    .as_ref()
                    .and_then(|bag| bag.accounts.get(&location.storage_id))
                    .is_some_and(|entry| {
                        location
                            .key_binding
                            .as_ref()
                            .is_none_or(|(server, subject)| {
                                entry.server_id == *server && entry.account_subject == *subject
                            })
                    }),
                has_replica: present.contains(&location.storage_id),
                location,
            })
            .collect())
    }

    pub fn prepare_local_recovery(&self, scope: RecoveryScope) -> LocalResult<RecoveryPreview> {
        let _context = self.context_gate.read().expect("context lock");
        self.verify_database()?;
        let storage = match &scope {
            RecoveryScope::Device => None,
            RecoveryScope::Account(id) => Some(Uuid::parse_str(id).map_err(unlock::keyring_error)?),
        };
        let connection = match &scope {
            RecoveryScope::Device => None,
            RecoveryScope::Account(id) => Some(
                self.app_client()?
                    .prepare_account_removal(id)
                    .map_err(connection_error)?,
            ),
        };
        let source = self
            .runtime
            .block_on(RecoverySource::prepare(&self.pool(), storage))
            .map_err(storage_error)?;
        if storage.is_some()
            && source.census.accounts == 0
            && !connection.as_ref().is_some_and(|plan| plan.is_configured())
        {
            return Err(failure("recovery_changed"));
        }
        let count = |value: i64| u64::try_from(value).map_err(unlock::keyring_error);
        let preview = RecoveryPreview {
            id: Uuid::now_v7().to_string(),
            scope,
            accounts: count(source.census.accounts)?,
            items: count(source.census.items)?,
            pending: count(source.census.pending)?,
            dirty: count(source.census.dirty)?,
            local_history: count(source.census.local_history)?,
        };
        let _entered = self.runtime.enter();
        *self.recovery.lock().expect("recovery lock") = Some(PreparedRecovery {
            preview: preview.clone(),
            connection,
            source,
            generation: self.context_generation.load(Ordering::SeqCst),
        });
        Ok(preview)
    }
    pub fn cancel_local_recovery(&self, id: String) -> LocalResult<()> {
        let _entered = self.runtime.enter();
        let mut pending = self.recovery.lock().expect("recovery lock");
        if pending.as_ref().is_some_and(|plan| plan.preview.id == id) {
            pending.take();
        }
        Ok(())
    }
    pub fn confirm_local_recovery(
        &self,
        id: String,
        discard_unsent: bool,
    ) -> LocalResult<RecoveryOutcome> {
        let client = self.app_client()?;
        let Some(_maintenance) = client.try_exclusive_local_maintenance() else {
            self.lock()?;
            return Err(failure("recovery_busy"));
        };
        let context = self.context_gate.write().expect("context lock");
        self.verify_database()?;
        let _entered = self.runtime.enter();
        let mut pending = self.recovery.lock().expect("recovery lock");
        let plan = pending
            .as_ref()
            .filter(|plan| plan.preview.id == id)
            .ok_or_else(|| failure("recovery_changed"))?;
        if plan.preview.has_unsent() && !discard_unsent {
            return Err(failure("recovery_unsent_confirmation"));
        }
        self.check_context_generation(plan.generation)?;
        let plan = pending.take().expect("checked plan");
        drop(pending);
        let root = self.device_key.lock().expect("root lock").clone();
        let device_reset = plan.preview.scope == RecoveryScope::Device;
        let replacement = match plan.preview.scope {
            RecoveryScope::Device => None,
            RecoveryScope::Account(storage) => plan
                .source
                .keyring
                .as_deref()
                .map(|raw| {
                    let mut bag = zann_client::app::unlock::DeviceUnlock::decode(raw)
                        .map_err(unlock::keyring_error)?;
                    bag.accounts.remove(&storage);
                    serde_json::to_string(&bag).map_err(unlock::keyring_error)
                })
                .transpose()?,
        };
        self.lock_in_context(&context)?;
        // Retain all earlier recovery material; do not prune during recovery.
        let snapshot = self.snapshot_create(Some(Retention {
            max_count: None,
            max_age_days: None,
        }))?;
        let location = SqliteFileLocation::from_existing_path(&self.database_path)
            .map_err(unlock::keyring_error)?;
        self.runtime.block_on(async {
            // Explicit unpinned maintenance connection; never used by ordinary operations.
            let pool = connect_sqlite_file_with_max(&location, 1)
                .await
                .map_err(unlock::keyring_error)?;
            let result = async {
                let recovery = plan.source.begin(&pool).await.map_err(storage_error)?;
                if let Some(connection) = plan.connection {
                    client
                        .commit_account_removal(connection)
                        .map_err(connection_error)?;
                }
                if device_reset {
                    self.save_remembered(&RememberedUnlockStore::default())?;
                }
                recovery
                    .commit(replacement.as_deref())
                    .await
                    .map_err(storage_error)
            }
            .await;
            pool.close().await;
            result
        })?;
        self.runtime.block_on(
            self.identity_probe
                .lock()
                .expect("identity lock")
                .pool()
                .close(),
        );
        self.runtime.block_on(self.pool().close());
        self.reopen_pool(&context)?;
        if !device_reset {
            if let Some(root) = root {
                self.finish_unlock_in_context(root, &context)?;
            }
        }
        Ok(RecoveryOutcome {
            snapshot_path: snapshot.path,
            device_reset,
        })
    }
}

#[cfg(test)]
mod tests;
