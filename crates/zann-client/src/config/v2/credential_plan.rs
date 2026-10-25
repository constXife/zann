use super::*;

pub(super) fn preflight_credential_slots(
    credential_store: &dyn CredentialStore,
    credential_ids: &BTreeMap<CredentialKind, CredentialId>,
) -> Result<(), ConfigError> {
    for credential_id in credential_ids.values() {
        let existing =
            credential_store
                .get(credential_id)
                .map_err(|source| ConfigError::CredentialStore {
                    operation: "preflight read",
                    credential_id: credential_id.clone(),
                    source,
                })?;
        if existing.is_some() {
            return Err(ConfigError::CredentialIdConflict {
                credential_id: credential_id.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn prepare_credential_slots(
    credential_store: &dyn CredentialStore,
    bundle: &CredentialBundle,
    credential_ids: &BTreeMap<CredentialKind, CredentialId>,
    created_ids: &mut BTreeSet<CredentialId>,
) -> Result<(), ConfigError> {
    for (kind, credential_id) in credential_ids {
        let secret = bundle
            .secret(*kind)
            .ok_or_else(|| ConfigError::InvalidConfig {
                path: "$.credential_transaction".to_string(),
                reason: format!("planned {kind:?} credential has no secret"),
            })?;
        // Preflight proved this repository-private id absent before the durable intent.
        // It is now an attempt-owned cleanup candidate even when a backend writes then errors.
        created_ids.insert(credential_id.clone());

        if let Err(source) = credential_store.put(credential_id, secret) {
            let put_error = ConfigError::CredentialStore {
                operation: "write",
                credential_id: credential_id.clone(),
                source,
            };
            if let Ok(Some(actual)) = credential_store.get(credential_id) {
                if actual.expose_secret() == secret.expose_secret() {
                    continue;
                }
            }
            return Err(put_error);
        }
        let verified =
            credential_store
                .get(credential_id)
                .map_err(|source| ConfigError::CredentialStore {
                    operation: "verify",
                    credential_id: credential_id.clone(),
                    source,
                })?;
        if verified
            .as_ref()
            .is_none_or(|actual| actual.expose_secret() != secret.expose_secret())
        {
            return Err(ConfigError::CredentialVerification {
                credential_id: credential_id.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn referenced_credential_ids(config: &ConfigV2) -> BTreeSet<CredentialId> {
    config
        .connections
        .values()
        .flat_map(|connection| connection.credential_profiles.values())
        .flat_map(|profile| profile.credentials.values().cloned())
        .collect()
}

pub(super) fn credential_slot_refs(config: &ConfigV2) -> BTreeSet<CredentialSlotRef> {
    config
        .connections
        .iter()
        .flat_map(|(connection_id, connection)| {
            connection
                .credential_profiles
                .iter()
                .flat_map(move |(profile_name, profile)| {
                    profile
                        .credentials
                        .iter()
                        .map(move |(kind, credential_id)| CredentialSlotRef {
                            connection_id: connection_id.clone(),
                            profile_name: profile_name.clone(),
                            kind: *kind,
                            credential_id: credential_id.clone(),
                        })
                })
        })
        .collect()
}

pub(super) fn credential_generation(config: &ConfigV2, raw_digest: String) -> CredentialGeneration {
    CredentialGeneration {
        revision: config.revision,
        raw_digest,
        migration_digest: config
            .migration
            .as_ref()
            .map(|migration| migration.source_digest.clone()),
        slots: credential_slot_refs(config),
    }
}

pub(super) fn credential_ids_from_slots<'a>(
    slots: impl IntoIterator<Item = &'a CredentialSlotRef>,
) -> BTreeSet<CredentialId> {
    slots
        .into_iter()
        .map(|slot| slot.credential_id.clone())
        .collect()
}

pub(super) fn credential_cleanup_targets(
    journal: &CredentialTransactionJournal,
    state: CredentialTransactionState,
) -> BTreeSet<CredentialId> {
    match state {
        CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten => {
            journal.new_ids.clone()
        }
        CredentialTransactionState::Committed | CredentialTransactionState::Cleanup => journal
            .retired_slots
            .iter()
            .map(|slot| slot.credential_id.clone())
            .filter(|credential_id| !journal.settled_retired_ids.contains(credential_id))
            .collect(),
    }
}

pub(super) fn with_cleanup_warnings(
    source: ConfigError,
    warnings: Vec<CredentialTransactionWarning>,
) -> ConfigError {
    if warnings.is_empty() {
        source
    } else {
        ConfigError::CredentialTransactionCleanup {
            source: Box::new(source),
            warnings,
        }
    }
}
