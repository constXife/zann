//! Materialize or explicitly rebind one authenticated account projection.
use super::*;

impl SqliteSyncStore {
    pub(super) async fn resolve_replica_binding(
        &self,
        expected: &TargetBinding,
        personal_vaults_enabled: bool,
    ) -> Result<LocalStorage, SyncStoreError> {
        self.database.verify_identity().await?;
        let storage_repository = LocalStorageRepo::new(self.database.pool());
        let stored = storage_repository
            .get_bounded(expected.storage_id)
            .await
            .map_err(map_projection_read)?;
        if let Some(stored) = stored {
            if ensure_storage_matches_target(&stored, expected).is_err()
                && stored.kind == StorageKind::Remote
                && stored.server_url.as_deref() == Some(expected.address.as_str())
                && stored.account_subject.as_deref() == Some(expected.account_subject.as_str())
            {
                // An explicitly reauthenticated account replica (see
                // `AppSyncStoreFactory::release_storage`) learns what its
                // server proves now. A storage still claimed is left as it
                // is, and the exact check below refuses it.
                let rebound = storage_repository
                    .rebind_released(
                        &stored,
                        &expected.display_name,
                        &expected.server_fingerprint,
                        expected.auth_method,
                        &expected.account_subject,
                    )
                    .await
                    .map_err(|error| {
                        store_error(SyncStoreErrorKind::Unavailable).with_source(error)
                    })?;
                if !rebound
                    && stored.server_fingerprint.as_deref()
                        != Some(expected.server_fingerprint.as_str())
                {
                    // Trust is endpoint-wide, while a cache claim belongs to one
                    // authenticated profile. Reconnect this account explicitly;
                    // another account's trust confirmation cannot release it.
                    return Err(store_error(SyncStoreErrorKind::ReauthenticationRequired));
                }
            }
        } else {
            let candidate = LocalStorage {
                id: expected.storage_id,
                kind: StorageKind::Remote,
                name: expected.display_name.clone(),
                server_url: Some(expected.address.clone()),
                server_name: None,
                server_fingerprint: Some(expected.server_fingerprint.clone()),
                account_subject: Some(expected.account_subject.clone()),
                personal_vaults_enabled,
                auth_method: Some(expected.auth_method),
            };
            storage_repository
                .insert_if_absent(&candidate)
                .await
                .map_err(|error| store_error(SyncStoreErrorKind::Unavailable).with_source(error))?;
        }
        let storage = self.exact_local_storage(expected).await?;
        if storage.personal_vaults_enabled != personal_vaults_enabled {
            return Err(store_error(SyncStoreErrorKind::InvalidData));
        }
        Ok(storage)
    }
}
