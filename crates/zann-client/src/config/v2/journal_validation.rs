use super::*;

pub(super) fn validate_credential_transaction_journal(
    journal: &CredentialTransactionJournal,
) -> Result<(), ConfigError> {
    if journal.journal_version != CREDENTIAL_TRANSACTION_JOURNAL_V1
        && journal.journal_version != CREDENTIAL_TRANSACTION_JOURNAL_VERSION
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.journal_version".to_string(),
            reason: format!(
                "expected credential transaction journal version {} or {}, found {}",
                CREDENTIAL_TRANSACTION_JOURNAL_V1,
                CREDENTIAL_TRANSACTION_JOURNAL_VERSION,
                journal.journal_version
            ),
        });
    }
    validate_credential_generation("$.source_primary", &journal.source_primary)?;
    if let Some(source_backup) = &journal.source_backup {
        validate_credential_generation("$.source_backup", source_backup)?;
        if source_backup.migration_digest != journal.source_primary.migration_digest {
            return Err(ConfigError::InvalidConfig {
                path: "$.source_backup.migration_digest".to_string(),
                reason: "backup migration digest must match the source primary".to_string(),
            });
        }
    }
    validate_credential_generation("$.candidate", &journal.candidate)?;
    if journal.candidate.revision != journal.source_primary.revision.saturating_add(1)
        || journal.source_primary.revision == u64::MAX
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.candidate.revision".to_string(),
            reason: "credential candidate must advance source revision exactly once".to_string(),
        });
    }
    if journal.candidate.migration_digest != journal.source_primary.migration_digest {
        return Err(ConfigError::InvalidConfig {
            path: "$.candidate.migration_digest".to_string(),
            reason: "candidate migration digest must match the source primary".to_string(),
        });
    }
    if !journal.aborted && journal.aborted_after_backup_write {
        return Err(ConfigError::InvalidConfig {
            path: "$.aborted_after_backup_write".to_string(),
            reason: "backup-write abort state requires aborted=true".to_string(),
        });
    }
    validate_count("$.new_ids", journal.new_ids.len(), 3)?;
    validate_count(
        "$.retired_slots",
        journal.retired_slots.len(),
        MAX_CREDENTIAL_SLOTS,
    )?;
    validate_count(
        "$.carried_retired_slots",
        journal.carried_retired_slots.len(),
        MAX_CREDENTIAL_SLOTS,
    )?;
    validate_count(
        "$.settled_retired_ids",
        journal.settled_retired_ids.len(),
        MAX_CREDENTIAL_SLOTS,
    )?;
    let source_ids = credential_ids_from_slots(&journal.source_primary.slots);
    let candidate_ids = credential_ids_from_slots(&journal.candidate.slots);
    if journal.new_ids.is_empty() {
        if journal.journal_version == CREDENTIAL_TRANSACTION_JOURNAL_V1 {
            return Err(ConfigError::InvalidConfig {
                path: "$.new_ids".to_string(),
                reason: "credential transaction journal v1 requires at least one new id"
                    .to_string(),
            });
        }
        if source_ids.is_subset(&candidate_ids) {
            return Err(ConfigError::InvalidConfig {
                path: "$.new_ids".to_string(),
                reason: "a zero-write journal must describe a real credential retirement"
                    .to_string(),
            });
        }
    }
    let expected_new_ids: BTreeSet<_> = candidate_ids.difference(&source_ids).cloned().collect();
    if journal.new_ids != expected_new_ids {
        return Err(ConfigError::InvalidConfig {
            path: "$.new_ids".to_string(),
            reason: "new_ids do not exactly match candidate refs minus source refs".to_string(),
        });
    }
    let source_slots = &journal.source_primary.slots;
    let candidate_slots = &journal.candidate.slots;
    let mut expected_base_retired_slots = BTreeSet::new();
    if !journal.aborted {
        expected_base_retired_slots.extend(source_slots.difference(candidate_slots).cloned());
    }
    if let Some(source_backup) = &journal.source_backup {
        expected_base_retired_slots.extend(source_backup.slots.difference(source_slots).cloned());
    }
    let mut expected_retired_slots = expected_base_retired_slots.clone();
    expected_retired_slots.extend(journal.carried_retired_slots.iter().cloned());
    if expected_retired_slots != journal.retired_slots {
        return Err(ConfigError::InvalidConfig {
            path: "$.retired_slots".to_string(),
            reason: "retired_slots do not exactly match source, backup, and predecessor proofs"
                .to_string(),
        });
    }
    let expected_carried: BTreeSet<_> = journal
        .retired_slots
        .difference(&expected_base_retired_slots)
        .cloned()
        .collect();
    if expected_carried != journal.carried_retired_slots {
        return Err(ConfigError::InvalidConfig {
            path: "$.carried_retired_slots".to_string(),
            reason: "carried cleanup slots must be exactly those not proven by source generations"
                .to_string(),
        });
    }
    let mut retired_ids = BTreeSet::new();
    for slot in &journal.retired_slots {
        if !retired_ids.insert(slot.credential_id.clone()) {
            return Err(ConfigError::InvalidConfig {
                path: "$.retired_slots".to_string(),
                reason: format!(
                    "credential id {} is retired from more than one slot",
                    slot.credential_id
                ),
            });
        }
        if candidate_ids.contains(&slot.credential_id) {
            return Err(ConfigError::InvalidConfig {
                path: "$.retired_slots".to_string(),
                reason: format!(
                    "retired credential id {} remains referenced by the candidate",
                    slot.credential_id
                ),
            });
        }
    }
    for credential_id in &journal.new_ids {
        if credential_id.lifecycle_nonce_and_tag().is_none() {
            return Err(ConfigError::InvalidConfig {
                path: "$.new_ids".to_string(),
                reason: format!("new credential id is not lifecycle-bound: {credential_id}"),
            });
        }
        if !candidate_ids.contains(credential_id) {
            return Err(ConfigError::InvalidConfig {
                path: "$.new_ids".to_string(),
                reason: format!("candidate does not reference new credential id {credential_id}"),
            });
        }
        if retired_ids.contains(credential_id) {
            return Err(ConfigError::InvalidConfig {
                path: "$.retired_slots".to_string(),
                reason: format!("new credential id is also marked retired: {credential_id}"),
            });
        }
    }
    if !journal.settled_retired_ids.is_subset(&retired_ids) {
        return Err(ConfigError::InvalidConfig {
            path: "$.settled_retired_ids".to_string(),
            reason: "settled ids must be a subset of proven retired slots".to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_credential_generation(
    path: &str,
    generation: &CredentialGeneration,
) -> Result<(), ConfigError> {
    validate_sha256_digest(
        &format!("{path}.raw_digest"),
        &generation.raw_digest,
        "credential generation",
    )?;
    if let Some(migration_digest) = &generation.migration_digest {
        validate_sha256_digest(
            &format!("{path}.migration_digest"),
            migration_digest,
            "credential generation migration",
        )?;
    }
    validate_count(
        &format!("{path}.slots"),
        generation.slots.len(),
        MAX_CREDENTIAL_SLOTS,
    )?;
    let ids = credential_ids_from_slots(&generation.slots);
    if ids.len() != generation.slots.len() {
        return Err(ConfigError::InvalidConfig {
            path: format!("{path}.slots"),
            reason: "credential ids must be unique within a generation".to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_credential_journal_bindings(
    journal: &CredentialTransactionJournal,
    repository_root: &Path,
) -> Result<(), ConfigError> {
    let binding = repository_binding(repository_root)?;
    for (generation_path, generation) in [
        ("$.source_primary", Some(&journal.source_primary)),
        ("$.source_backup", journal.source_backup.as_ref()),
        ("$.candidate", Some(&journal.candidate)),
    ] {
        let Some(generation) = generation else {
            continue;
        };
        for slot in &generation.slots {
            validate_credential_slot_binding(
                generation_path,
                slot,
                generation.migration_digest.as_deref(),
                &binding,
                repository_root,
            )?;
        }
    }
    for slot in &journal.retired_slots {
        validate_credential_slot_binding(
            "$.retired_slots",
            slot,
            journal.source_primary.migration_digest.as_deref(),
            &binding,
            repository_root,
        )?;
    }
    Ok(())
}

pub(super) fn validate_credential_slot_binding(
    path: &str,
    slot: &CredentialSlotRef,
    migration_digest: Option<&str>,
    repository_binding: &[u8],
    repository_root: &Path,
) -> Result<(), ConfigError> {
    validate_string_len(
        &format!("{path}.*.profile_name"),
        &slot.profile_name,
        MAX_LEGACY_NAME_LEN,
    )?;
    let valid = if slot.credential_id.lifecycle_nonce_and_tag().is_some() {
        slot.credential_id.is_bound_lifecycle(
            repository_binding,
            &slot.connection_id,
            &slot.profile_name,
            slot.kind,
        )
    } else {
        migration_digest.is_some_and(|digest| {
            slot.credential_id
                == CredentialId::deterministic(
                    repository_binding,
                    digest,
                    &slot.connection_id,
                    &slot.profile_name,
                    slot.kind,
                )
        })
    };
    if !valid {
        return Err(ConfigError::CredentialTransactionJournalConflict {
            path: repository_root.join(CREDENTIAL_TRANSACTION_JOURNAL_FILENAME),
            reason: format!(
                "retired credential id {} is not bound to its declared repository slot",
                slot.credential_id
            ),
        });
    }
    Ok(())
}

pub(super) fn validate_sha256_digest(
    path: &str,
    digest: &str,
    label: &str,
) -> Result<(), ConfigError> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: format!("{label} digest must use sha256"),
        });
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: format!("{label} digest must contain 64 hexadecimal digits"),
        });
    }
    Ok(())
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    let limit = json_size_limit(path);
    if bytes.len() as u64 > limit {
        return Err(ConfigError::ConfigTooLarge {
            path: path.to_path_buf(),
            max_bytes: limit,
        });
    }
    validate_regular_file_if_exists(path)?;
    let parent = path.parent().ok_or_else(|| ConfigError::Io {
        operation: "resolve config parent",
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"),
    })?;
    fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
        operation: "create config directory",
        path: parent.to_path_buf(),
        source,
    })?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|source| ConfigError::Io {
        operation: "create config temporary file",
        path: parent.to_path_buf(),
        source,
    })?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| ConfigError::Io {
            operation: "sync config temporary file",
            path: temporary.path().to_path_buf(),
            source,
        })?;
    temporary.persist(path).map_err(|error| ConfigError::Io {
        operation: "persist config",
        path: path.to_path_buf(),
        source: error.error,
    })?;
    sync_parent(parent)?;
    Ok(())
}

#[cfg(unix)]
pub(super) fn sync_parent(parent: &Path) -> Result<(), ConfigError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ConfigError::Io {
            operation: "sync config directory",
            path: parent.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
pub(super) fn sync_parent(_parent: &Path) -> Result<(), ConfigError> {
    Ok(())
}
