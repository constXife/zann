use super::super::*;

impl ConfigRepository {
    pub(in crate::config::v2) fn exclusive_lock(&self) -> Result<ConfigFileLockGuard, ConfigError> {
        let file = self.exclusive_lock_allow_credential_journal()?;
        if let Some((_, state, _)) = self.pending_credential_transaction_locked()? {
            if matches!(
                state,
                CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten
            ) {
                return Err(ConfigError::CredentialRecoveryRequired {
                    path: self.paths.credential_transaction_journal(),
                });
            }
        }
        Ok(file)
    }

    pub(in crate::config::v2) fn credential_operation_lock(
        &self,
    ) -> Result<FileLockGuard, ConfigError> {
        let operation = LockKind::CredentialOperation
            .pending_at(self.paths.root())?
            .acquire_blocking(LOCK_TIMEOUT)?;
        {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            self.ensure_no_pending_auth_operation_locked()?;
        }
        Ok(operation)
    }

    pub(in crate::config::v2) fn ensure_no_pending_auth_operation_locked(
        &self,
    ) -> Result<(), ConfigError> {
        let path = self.paths.auth_operation_intent();
        if validate_regular_file_if_exists(&path)? {
            return Err(ConfigError::AuthOperationRecoveryRequired { path });
        }
        Ok(())
    }

    pub(in crate::config::v2) fn ensure_no_pending_sync_generation_recovery_locked(
        &self,
    ) -> Result<(), ConfigError> {
        self.ensure_no_pending_auth_operation_locked()?;
        if self
            .pending_credential_transaction_locked()?
            .is_some_and(|(_, state, _)| {
                matches!(
                    state,
                    CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten
                )
            })
        {
            return Err(ConfigError::CredentialRecoveryRequired {
                path: self.paths.credential_transaction_journal(),
            });
        }
        let restore_path = self.paths.restore_journal();
        if validate_regular_file_if_exists(&restore_path)? {
            return Err(ConfigError::RestoreJournalConflict {
                path: restore_path,
                reason: "pending restore blocks sync generation validation".to_string(),
            });
        }
        Ok(())
    }

    pub(in crate::config::v2) fn exclusive_lock_allow_credential_journal(
        &self,
    ) -> Result<ConfigFileLockGuard, ConfigError> {
        let lock = ConfigFileLockGuard::acquire(self.paths.root(), LOCK_TIMEOUT)?;
        let restore_pending = validate_regular_file_if_exists(&self.paths.restore_journal())?;
        if restore_pending && validate_regular_file_if_exists(&self.paths.auth_operation_intent())?
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "restore and authentication intents coexist; automatic replay is blocked"
                    .to_string(),
            });
        }
        if restore_pending
            && validate_regular_file_if_exists(&self.paths.credential_transaction_journal())?
        {
            return Err(ConfigError::CredentialRecoveryRequired {
                path: self.paths.credential_transaction_journal(),
            });
        }
        self.complete_pending_restore_locked()?;
        Ok(lock)
    }

    pub(in crate::config::v2) fn pending_credential_transaction_locked(
        &self,
    ) -> Result<
        Option<(
            CredentialTransactionJournal,
            CredentialTransactionState,
            Vec<u8>,
        )>,
        ConfigError,
    > {
        let journal_path = self.paths.credential_transaction_journal();
        if !validate_regular_file_if_exists(&journal_path)? {
            return Ok(None);
        }
        let journal_bytes = read_file(&journal_path, "read credential transaction journal")?;
        let journal = parse_credential_transaction_journal(&journal_path, &journal_bytes)?;
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::CredentialTransactionJournalConflict {
                path: journal_path,
                reason: "primary config is missing".to_string(),
            });
        }
        let primary_bytes = read_file(
            &primary_path,
            "read primary for credential transaction recovery",
        )?;
        let primary = parse_config(&primary_path, &primary_bytes)?;
        let primary_generation = credential_generation(&primary, byte_digest(&primary_bytes));
        let current_backup = self
            .read_optional_durable_config_with_digest(&self.paths.backup())?
            .map(|(config, digest)| credential_generation(&config, digest));
        let original_backup_matches = current_backup == journal.source_backup;
        let source_backup_written = current_backup.as_ref() == Some(&journal.source_primary);
        let source_exact = primary_generation == journal.source_primary;
        let state = if journal.aborted {
            let cleanup_descendant = primary_generation.revision > journal.source_primary.revision
                && primary_generation.slots == journal.source_primary.slots
                && primary_generation.migration_digest == journal.source_primary.migration_digest;
            if (source_exact && (original_backup_matches || source_backup_written))
                || cleanup_descendant
            {
                CredentialTransactionState::Cleanup
            } else {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: journal_path,
                    reason: "aborted credential intent is not anchored to its source or descendant"
                        .to_string(),
                });
            }
        } else if source_exact {
            if original_backup_matches {
                CredentialTransactionState::Initial
            } else if source_backup_written {
                CredentialTransactionState::BackupWritten
            } else {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: journal_path,
                    reason: "credential source primary has an unexpected backup generation"
                        .to_string(),
                });
            }
        } else {
            let committed_exact = primary_generation == journal.candidate && source_backup_written;
            let committed_descendant = primary_generation.revision > journal.candidate.revision
                && primary_generation.slots == journal.candidate.slots
                && primary_generation.migration_digest == journal.candidate.migration_digest;
            if committed_exact || committed_descendant {
                CredentialTransactionState::Committed
            } else {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: journal_path,
                    reason: "primary/backup do not match source, committed candidate, or a valid descendant"
                        .to_string(),
                });
            }
        };
        Ok(Some((journal, state, journal_bytes)))
    }

    pub(in crate::config::v2) fn pending_auth_operation_intent_locked(
        &self,
    ) -> Result<Option<(AuthOperationIntent, Vec<u8>)>, ConfigError> {
        let path = self.paths.auth_operation_intent();
        if !validate_regular_file_if_exists(&path)? {
            return Ok(None);
        }
        let bytes = read_file(&path, "read authentication operation intent")?;
        let intent = parse_auth_operation_intent(&path, &bytes)?;
        Ok(Some((intent, bytes)))
    }

    pub(in crate::config::v2) fn ensure_owned_auth_operation_intent_locked(
        &self,
        permit: &AuthOperationIntentPermit,
    ) -> Result<(AuthOperationIntent, Vec<u8>), ConfigError> {
        let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "owned authentication intent disappeared".to_string(),
            });
        };
        if byte_digest(&bytes) != permit.journal_bytes_digest
            || intent.operation_id != permit.operation_id
            || intent.operation != permit.operation
            || auth_intent_source_anchor(&intent) != permit.anchor
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "authentication intent ownership proof no longer matches".to_string(),
            });
        }
        Ok((intent, bytes))
    }

    pub(in crate::config::v2) fn ensure_owned_password_login_intent_locked(
        &self,
        permit: &PasswordLoginIntentPermit,
    ) -> Result<(AuthOperationIntent, Vec<u8>), ConfigError> {
        let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "owned password-login intent disappeared".to_string(),
            });
        };
        let reservation_matches = intent.reserved_login.as_ref() == Some(&permit.reservation);
        let source_matches = intent.repository_binding_digest
            == permit.anchor.repository_binding_digest
            && intent.connection_id == permit.anchor.connection_id
            && intent.profile_name == permit.anchor.profile_name
            && intent.endpoint.address == permit.anchor.normalized_address
            && intent.endpoint.server_id == permit.anchor.server_id
            && intent.endpoint.server_fingerprint == permit.anchor.server_fingerprint
            && intent.endpoint.storage_id == permit.anchor.storage_id
            && intent.source.revision == permit.anchor.source_revision
            && intent.source.raw_digest == permit.anchor.source_digest
            && intent.client_id.as_ref() == Some(&permit.anchor.client_id);
        if byte_digest(&bytes) != permit.journal_bytes_digest
            || intent.journal_version != AUTH_OPERATION_INTENT_VERSION
            || intent.operation_id != permit.operation_id
            || intent.operation != AuthOperationKind::PasswordLogin
            || !reservation_matches
            || !source_matches
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login intent ownership proof no longer matches".to_string(),
            });
        }
        Ok((intent, bytes))
    }
}
