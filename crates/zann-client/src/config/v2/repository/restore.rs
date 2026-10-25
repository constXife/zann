use super::super::*;

impl ConfigRepository {
    pub fn restore_backup(&self) -> Result<ConfigSnapshot, ConfigError> {
        // Restore can replace the complete credential topology. Serialize it
        // with refresh/login/logout so a server-side token rotation cannot
        // finish against a generation that restore replaces underneath it.
        // Lock order remains auth operation -> config.
        let _auth_operation = LockKind::AuthOperation
            .pending_at(self.paths.root())?
            .acquire_blocking(LOCK_TIMEOUT)?;
        let _credential_operation = self.credential_operation_lock()?;
        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_auth_operation_locked()?;
        if self.pending_credential_transaction_locked()?.is_some() {
            return Err(ConfigError::CredentialRecoveryRequired {
                path: self.paths.credential_transaction_journal(),
            });
        }
        let backup_path = self.paths.backup();
        if !validate_regular_file_if_exists(&backup_path)? {
            return Err(ConfigError::MissingBackup { path: backup_path });
        }
        let backup_bytes = read_file(&backup_path, "read config backup")?;
        let mut restored = parse_config(&backup_path, &backup_bytes)?;
        self.ensure_legacy_unchanged(&restored)?;

        match read_file(&self.paths.config(), "read config") {
            Ok(bytes) => match parse_config(&self.paths.config(), &bytes) {
                Ok(current) => {
                    self.ensure_legacy_unchanged(&current)?;
                    restored.revision = current
                        .revision
                        .max(restored.revision)
                        .checked_add(1)
                        .ok_or(ConfigError::RevisionOverflow)?;
                    let journal = RestoreJournal {
                        journal_version: RESTORE_JOURNAL_VERSION,
                        source_primary_digest: byte_digest(&bytes),
                        source_backup_digest: byte_digest(&backup_bytes),
                        target_primary: restored.clone(),
                        target_backup: current,
                    };
                    let journal_bytes = serialize_restore_journal(&journal)?;
                    atomic_write(&self.paths.restore_journal(), &journal_bytes)?;
                    self.apply_restore_journal_locked(&journal)?;
                    return Ok(ConfigSnapshot { config: restored });
                }
                Err(ConfigError::FutureSchema { found, supported }) => {
                    return Err(ConfigError::FutureSchema { found, supported });
                }
                Err(_) => {
                    restored.revision = restored
                        .revision
                        .checked_add(2)
                        .ok_or(ConfigError::RevisionOverflow)?;
                }
            },
            Err(ConfigError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                restored.revision = restored
                    .revision
                    .checked_add(2)
                    .ok_or(ConfigError::RevisionOverflow)?;
            }
            Err(error) => return Err(error),
        }
        let bytes = serialize_config(&restored)?;
        atomic_write(&self.paths.config(), &bytes)?;
        Ok(ConfigSnapshot { config: restored })
    }

    pub(in crate::config::v2) fn mutate<F>(
        &self,
        expected_revision: Option<u64>,
        update: F,
    ) -> Result<ConfigSnapshot, ConfigError>
    where
        F: FnOnce(&mut ConfigV2) -> Result<(), ConfigError>,
    {
        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_auth_operation_locked()?;
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::MissingConfig { path: primary_path });
        }
        let previous_bytes = read_file(&primary_path, "read config")?;
        let mut config = parse_config(&primary_path, &previous_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        if let Some(expected) = expected_revision {
            if config.revision != expected {
                return Err(ConfigError::RevisionConflict {
                    expected,
                    actual: config.revision,
                });
            }
        }
        update(&mut config)?;
        config.revision = config
            .revision
            .checked_add(1)
            .ok_or(ConfigError::RevisionOverflow)?;
        let next_bytes = serialize_config(&config)?;

        atomic_write(&self.paths.backup(), &previous_bytes)?;
        atomic_write(&primary_path, &next_bytes)?;
        Ok(ConfigSnapshot { config })
    }

    pub(in crate::config::v2) fn reconcile_failed_credential_intent(
        &self,
        credential_store: &dyn CredentialStore,
        intended_ids: &BTreeSet<CredentialId>,
    ) -> Vec<CredentialTransactionWarning> {
        match self.reconcile_credentials_with_operation_lock(credential_store) {
            Ok(outcome) => outcome.warnings,
            Err(error) => vec![CredentialTransactionWarning::CleanupDeferred {
                credential_ids: intended_ids.iter().cloned().collect(),
                reason: error.to_string(),
            }],
        }
    }

    pub(in crate::config::v2) fn durable_referenced_credential_ids_locked(
        &self,
    ) -> Result<BTreeSet<CredentialId>, ConfigError> {
        let primary = self.read_primary()?;
        self.ensure_legacy_unchanged(&primary)?;
        let mut referenced = referenced_credential_ids(&primary);
        if let Some((backup, _)) =
            self.read_optional_durable_config_with_digest(&self.paths.backup())?
        {
            referenced.extend(referenced_credential_ids(&backup));
        }
        let restore_path = self.paths.restore_journal();
        if validate_regular_file_if_exists(&restore_path)? {
            let bytes = read_file(
                &restore_path,
                "read restore journal for credential reachability",
            )?;
            let restore = parse_restore_journal(&restore_path, &bytes)?;
            referenced.extend(referenced_credential_ids(&restore.target_primary));
            referenced.extend(referenced_credential_ids(&restore.target_backup));
        }
        Ok(referenced)
    }

    pub(in crate::config::v2) fn read_optional_durable_config_with_digest(
        &self,
        path: &Path,
    ) -> Result<Option<(ConfigV2, String)>, ConfigError> {
        if !validate_regular_file_if_exists(path)? {
            return Ok(None);
        }
        let bytes = read_file(path, "read durable config generation")?;
        let config = parse_config(path, &bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        Ok(Some((config, byte_digest(&bytes))))
    }

    pub(in crate::config::v2) fn read_primary(&self) -> Result<ConfigV2, ConfigError> {
        let path = self.paths.config();
        if !validate_regular_file_if_exists(&path)? {
            return Err(ConfigError::MissingConfig { path });
        }
        let bytes = read_file(&path, "read config")?;
        parse_config(&path, &bytes)
    }

    pub(in crate::config::v2) fn ensure_legacy_unchanged(
        &self,
        config: &ConfigV2,
    ) -> Result<(), ConfigError> {
        let Some(migration) = &config.migration else {
            return Ok(());
        };
        let actual = LegacyInput::read(&self.paths)?.digest;
        if migration.source_digest != actual {
            return Err(ConfigError::LegacyDiverged {
                expected: migration.source_digest.clone(),
                actual,
            });
        }
        Ok(())
    }

    pub(in crate::config::v2) fn complete_pending_restore_locked(&self) -> Result<(), ConfigError> {
        let journal_path = self.paths.restore_journal();
        if !validate_regular_file_if_exists(&journal_path)? {
            return Ok(());
        }
        let bytes = read_file(&journal_path, "read restore journal")?;
        let journal = parse_restore_journal(&journal_path, &bytes)?;
        self.apply_restore_journal_locked(&journal)
    }

    pub(in crate::config::v2) fn apply_restore_journal_locked(
        &self,
        journal: &RestoreJournal,
    ) -> Result<(), ConfigError> {
        let target_backup = serialize_config(&journal.target_backup)?;
        let target_primary = serialize_config(&journal.target_primary)?;
        let state = self.restore_state(journal, &target_primary, &target_backup)?;
        if state != RestoreState::Complete {
            atomic_write(&self.paths.backup(), &target_backup)?;
            atomic_write(&self.paths.config(), &target_primary)?;
        }
        let journal_path = self.paths.restore_journal();
        validate_regular_file_if_exists(&journal_path)?;
        fs::remove_file(&journal_path).map_err(|source| ConfigError::Io {
            operation: "remove completed restore journal",
            path: journal_path,
            source,
        })?;
        sync_parent(self.paths.root())
    }

    pub(in crate::config::v2) fn restore_state(
        &self,
        journal: &RestoreJournal,
        target_primary: &[u8],
        target_backup: &[u8],
    ) -> Result<RestoreState, ConfigError> {
        let primary_path = self.paths.config();
        let backup_path = self.paths.backup();
        let primary = self.read_restore_component(
            &primary_path,
            "read config for restore replay",
            "primary",
        )?;
        let backup = self.read_restore_component(
            &backup_path,
            "read config backup for restore replay",
            "backup",
        )?;

        if let Err(ConfigError::FutureSchema { found, supported }) =
            parse_config(&primary_path, &primary)
        {
            return Err(ConfigError::FutureSchema { found, supported });
        }
        if let Err(ConfigError::FutureSchema { found, supported }) =
            parse_config(&backup_path, &backup)
        {
            return Err(ConfigError::FutureSchema { found, supported });
        }

        let primary_digest = byte_digest(&primary);
        let backup_digest = byte_digest(&backup);
        let target_primary_digest = byte_digest(target_primary);
        let target_backup_digest = byte_digest(target_backup);
        let state = if primary_digest == journal.source_primary_digest
            && backup_digest == journal.source_backup_digest
        {
            RestoreState::Initial
        } else if primary_digest == journal.source_primary_digest
            && backup_digest == target_backup_digest
        {
            RestoreState::BackupWritten
        } else if primary_digest == target_primary_digest && backup_digest == target_backup_digest {
            RestoreState::Complete
        } else {
            return Err(ConfigError::RestoreJournalConflict {
                path: self.paths.restore_journal(),
                reason: "primary/backup digests do not match an allowed restore state".to_string(),
            });
        };
        Ok(state)
    }

    pub(in crate::config::v2) fn read_restore_component(
        &self,
        path: &Path,
        operation: &'static str,
        component: &'static str,
    ) -> Result<Vec<u8>, ConfigError> {
        match read_file(path, operation) {
            Ok(bytes) => Ok(bytes),
            Err(ConfigError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                Err(ConfigError::RestoreJournalConflict {
                    path: self.paths.restore_journal(),
                    reason: format!("restore {component} is missing"),
                })
            }
            Err(error) => Err(error),
        }
    }
}
