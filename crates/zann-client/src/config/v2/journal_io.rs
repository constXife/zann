use super::*;

pub(super) fn parse_restore_journal(
    path: &Path,
    bytes: &[u8],
) -> Result<RestoreJournal, ConfigError> {
    validate_json_shape(bytes, RESTORE_JOURNAL_NODE_LIMIT).map_err(|source| {
        ConfigError::MalformedRestoreJournal {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let probe: RestoreVersionProbe =
        serde_json::from_slice(bytes).map_err(|source| ConfigError::MalformedRestoreJournal {
            path: path.to_path_buf(),
            source,
        })?;
    let version =
        probe
            .journal_version
            .ok_or_else(|| ConfigError::MissingRestoreJournalVersion {
                path: path.to_path_buf(),
            })?;
    if version > u64::from(RESTORE_JOURNAL_VERSION) {
        return Err(ConfigError::FutureRestoreJournal {
            found: version,
            supported: RESTORE_JOURNAL_VERSION,
        });
    }
    if version != u64::from(RESTORE_JOURNAL_VERSION) {
        return Err(ConfigError::UnsupportedRestoreJournal {
            found: version,
            supported: RESTORE_JOURNAL_VERSION,
        });
    }
    let journal: RestoreJournal =
        serde_json::from_slice(bytes).map_err(|source| ConfigError::MalformedRestoreJournal {
            path: path.to_path_buf(),
            source,
        })?;
    validate_restore_journal(&journal)?;
    if let Some(repository_root) = path.parent() {
        validate_repository_credential_ids(&journal.target_primary, repository_root)?;
        validate_repository_credential_ids(&journal.target_backup, repository_root)?;
    }
    Ok(journal)
}

pub(super) fn serialize_restore_journal(journal: &RestoreJournal) -> Result<Vec<u8>, ConfigError> {
    validate_restore_journal(journal)?;
    serialize_bounded(
        journal,
        RESTORE_JOURNAL_MAX_BYTES,
        CONFIG_RESTORE_JOURNAL_FILENAME,
    )
}

pub(super) fn validate_restore_journal(journal: &RestoreJournal) -> Result<(), ConfigError> {
    if journal.journal_version != RESTORE_JOURNAL_VERSION {
        return Err(ConfigError::InvalidConfig {
            path: "$.journal_version".to_string(),
            reason: format!(
                "expected restore journal version {}, found {}",
                RESTORE_JOURNAL_VERSION, journal.journal_version
            ),
        });
    }
    for (path, digest) in [
        (
            "$.source_primary_digest",
            journal.source_primary_digest.as_str(),
        ),
        (
            "$.source_backup_digest",
            journal.source_backup_digest.as_str(),
        ),
    ] {
        let Some(hex) = digest.strip_prefix("sha256:") else {
            return Err(ConfigError::InvalidConfig {
                path: path.to_string(),
                reason: "restore source digest must use sha256".to_string(),
            });
        };
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ConfigError::InvalidConfig {
                path: path.to_string(),
                reason: "restore source digest must contain 64 hexadecimal digits".to_string(),
            });
        }
    }
    validate_config(&journal.target_primary)?;
    validate_config(&journal.target_backup)?;
    let _target_primary = serialize_config(&journal.target_primary)?;
    let _target_backup = serialize_config(&journal.target_backup)?;
    if journal.target_primary.revision <= journal.target_backup.revision {
        return Err(ConfigError::InvalidConfig {
            path: "$.target_primary.revision".to_string(),
            reason: "restored primary revision must be newer than its backup".to_string(),
        });
    }
    Ok(())
}

pub(super) fn parse_credential_transaction_journal(
    path: &Path,
    bytes: &[u8],
) -> Result<CredentialTransactionJournal, ConfigError> {
    validate_json_shape(bytes, CREDENTIAL_TRANSACTION_JOURNAL_NODE_LIMIT).map_err(|source| {
        ConfigError::MalformedCredentialTransactionJournal {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let probe: CredentialTransactionVersionProbe =
        serde_json::from_slice(bytes).map_err(|source| {
            ConfigError::MalformedCredentialTransactionJournal {
                path: path.to_path_buf(),
                source,
            }
        })?;
    let version = probe.journal_version.ok_or_else(|| {
        ConfigError::MissingCredentialTransactionJournalVersion {
            path: path.to_path_buf(),
        }
    })?;
    if version > u64::from(CREDENTIAL_TRANSACTION_JOURNAL_VERSION) {
        return Err(ConfigError::FutureCredentialTransactionJournal {
            found: version,
            supported: CREDENTIAL_TRANSACTION_JOURNAL_VERSION,
        });
    }
    if version != u64::from(CREDENTIAL_TRANSACTION_JOURNAL_V1)
        && version != u64::from(CREDENTIAL_TRANSACTION_JOURNAL_VERSION)
    {
        return Err(ConfigError::UnsupportedCredentialTransactionJournal {
            found: version,
            supported: CREDENTIAL_TRANSACTION_JOURNAL_VERSION,
        });
    }
    let journal: CredentialTransactionJournal =
        serde_json::from_slice(bytes).map_err(|source| {
            ConfigError::MalformedCredentialTransactionJournal {
                path: path.to_path_buf(),
                source,
            }
        })?;
    validate_credential_transaction_journal(&journal)?;
    if let Some(repository_root) = path.parent() {
        validate_credential_journal_bindings(&journal, repository_root)?;
    }
    Ok(journal)
}

pub(super) fn serialize_credential_transaction_journal(
    journal: &CredentialTransactionJournal,
) -> Result<Vec<u8>, ConfigError> {
    validate_credential_transaction_journal(journal)?;
    let bytes = serialize_bounded(
        journal,
        CREDENTIAL_TRANSACTION_JOURNAL_MAX_BYTES,
        CREDENTIAL_TRANSACTION_JOURNAL_FILENAME,
    )?;
    validate_json_shape(&bytes, CREDENTIAL_TRANSACTION_JOURNAL_NODE_LIMIT).map_err(|source| {
        ConfigError::MalformedCredentialTransactionJournal {
            path: PathBuf::from(CREDENTIAL_TRANSACTION_JOURNAL_FILENAME),
            source,
        }
    })?;
    Ok(bytes)
}

pub(super) fn parse_auth_operation_intent(
    path: &Path,
    bytes: &[u8],
) -> Result<AuthOperationIntent, ConfigError> {
    validate_json_shape(bytes, AUTH_OPERATION_INTENT_NODE_LIMIT).map_err(|source| {
        ConfigError::MalformedAuthOperationIntent {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let probe: AuthOperationIntentVersionProbe =
        serde_json::from_slice(bytes).map_err(|source| {
            ConfigError::MalformedAuthOperationIntent {
                path: path.to_path_buf(),
                source,
            }
        })?;
    let version =
        probe
            .journal_version
            .ok_or_else(|| ConfigError::MissingAuthOperationIntentVersion {
                path: path.to_path_buf(),
            })?;
    if version > u64::from(AUTH_OPERATION_INTENT_VERSION) {
        return Err(ConfigError::FutureAuthOperationIntent {
            found: version,
            supported: AUTH_OPERATION_INTENT_VERSION,
        });
    }
    if version != u64::from(AUTH_OPERATION_INTENT_V1)
        && version != u64::from(AUTH_OPERATION_INTENT_VERSION)
    {
        return Err(ConfigError::UnsupportedAuthOperationIntent {
            found: version,
            supported: AUTH_OPERATION_INTENT_VERSION,
        });
    }
    let intent: AuthOperationIntent = serde_json::from_slice(bytes).map_err(|source| {
        ConfigError::MalformedAuthOperationIntent {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let repository_root = path.parent().ok_or_else(|| ConfigError::InvalidConfig {
        path: "$.repository_binding_digest".to_string(),
        reason: "authentication intent path has no repository root".to_string(),
    })?;
    validate_auth_operation_intent(&intent, repository_root)?;
    Ok(intent)
}

pub(super) fn serialize_auth_operation_intent(
    intent: &AuthOperationIntent,
    repository_root: &Path,
) -> Result<Vec<u8>, ConfigError> {
    validate_auth_operation_intent(intent, repository_root)?;
    let bytes = serialize_bounded(
        intent,
        AUTH_OPERATION_INTENT_MAX_BYTES,
        AUTH_OPERATION_INTENT_FILENAME,
    )?;
    validate_json_shape(&bytes, AUTH_OPERATION_INTENT_NODE_LIMIT).map_err(|source| {
        ConfigError::MalformedAuthOperationIntent {
            path: PathBuf::from(AUTH_OPERATION_INTENT_FILENAME),
            source,
        }
    })?;
    Ok(bytes)
}
