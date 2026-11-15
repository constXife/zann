//! Exact profile replica resolution; endpoint trust is connection-scoped.
use super::*;

impl ConfigV2 {
    pub fn canonical_address(address: &str) -> Result<String, ConfigError> {
        normalize_address(address, "$.endpoint")
    }
    pub fn connection_for_address(
        &self,
        address: &str,
    ) -> Result<Option<ConnectionId>, ConfigError> {
        let address = normalize_address(address, "$.endpoint")?;
        let mut found = None;
        for (id, connection) in &self.connections {
            if normalize_address(&connection.metadata.address, "$.connection.address")? == address {
                if found.is_some() {
                    return Err(ConfigError::InvalidConfig {
                        path: "$.connections".into(),
                        reason: "normalized endpoint has multiple trust owners".into(),
                    });
                }
                found = Some(id.clone());
            }
        }
        Ok(found)
    }

    pub fn replica_profile(
        &self,
        storage: &str,
    ) -> Result<Option<(ConnectionId, String)>, ConfigError> {
        let mut found = None;
        for (id, connection) in &self.connections {
            for (name, profile) in connection.credential_profiles() {
                if profile.storage_id() == Some(storage) {
                    if found.is_some() {
                        return Err(ConfigError::InvalidConfig {
                            path: "$.connections.*.credential_profiles.*.storage_id".into(),
                            reason: "replica storage is bound to multiple profiles".into(),
                        });
                    }
                    found = Some((id.clone(), name.clone()));
                }
            }
        }
        Ok(found)
    }
}

impl ConfigRepository {
    /// Startup cutover gate, before native SQLite initialization or credential I/O.
    pub fn validate_existing_replica_format(&self) -> Result<(), ConfigError> {
        for path in [
            self.paths.config(),
            self.paths.backup(),
            self.paths.restore_journal(),
            self.paths.credential_transaction_journal(),
            self.paths.auth_operation_intent(),
            self.paths.legacy_config(),
        ] {
            if validate_regular_file_if_exists(&path)? {
                let bytes = Zeroizing::new(read_file(
                    &path,
                    "validate replica format before SQLite migration",
                )?);
                validate_json_shape(&bytes, CREDENTIAL_TRANSACTION_JOURNAL_NODE_LIMIT).map_err(
                    |source| ConfigError::Malformed {
                        path: path.clone(),
                        source,
                    },
                )?;
                reject_connection_replica_fields(&path, &bytes)?;
            }
        }
        if validate_regular_file_if_exists(&self.paths.auth_operation_intent())? {
            let primary = self.paths.config();
            if !validate_regular_file_if_exists(&primary)? {
                return Err(ConfigError::AuthOperationRecoveryRequired {
                    path: self.paths.auth_operation_intent(),
                });
            }
            // An auth intent contains a source digest, not an embedded Config.
            // Its storage field alone cannot establish profile-scoped ownership.
            let bytes = read_file(&primary, "validate authentication intent source format")?;
            parse_config(&primary, &bytes)?;
        }
        Ok(())
    }
}

pub(super) fn bind_profile_storage(
    config: &mut ConfigV2,
    connection: &ConnectionId,
    name: &str,
    storage: Option<&str>,
) -> Result<(), ConfigError> {
    let Some(storage) = storage else {
        return Ok(());
    };
    validate_required_metadata("$.profile.storage_id", storage)?;
    if let Some((id, profile)) = config.replica_profile(storage)? {
        if id != *connection || profile != name {
            return Err(ConfigError::StorageBindingConflict {
                storage_id: storage.into(),
                connection_id: id,
            });
        }
    }
    let profile = config
        .connections
        .get_mut(connection)
        .and_then(|connection| connection.credential_profiles.get_mut(name))
        .ok_or_else(|| ConfigError::MissingCredentialProfile {
            connection_id: connection.clone(),
            profile_name: name.into(),
        })?;
    if profile
        .storage_id
        .as_deref()
        .is_some_and(|current| current != storage)
    {
        return Err(ConfigError::BindingChangeRequiresRebind {
            connection_id: connection.clone(),
            field: "profile.storage_id",
        });
    }
    profile.storage_id = Some(storage.into());
    Ok(())
}

/// Explicit native provisioning input. It carries no authenticated identity.
#[cfg(feature = "remote")]
pub(crate) struct ReplicaReservation {
    pub profile: String,
    pub storage: String,
    pub expected_subject: Option<String>,
    pub reuse_pending: bool,
}

impl ConfigV2 {
    /// Reuse the sole unowned provisioning slot. Authenticated accounts and
    /// explicitly selected disconnected replicas are never eligible.
    #[cfg(feature = "remote")]
    pub(crate) fn pending_account_profile(&self, connection: &ConnectionId) -> Option<&str> {
        self.connections
            .get(connection)?
            .credential_profiles
            .iter()
            .find_map(|(name, profile)| {
                (profile.storage_id.is_some()
                    && profile.credentials.is_empty()
                    && profile.account_subject.is_none()
                    && profile.expected_account_subject.is_none()
                    && profile.expected_master_key_fp.is_none()
                    && !self
                        .account_identities
                        .contains_key(&identity_slot(connection, name)))
                .then_some(name.as_str())
            })
    }
}
