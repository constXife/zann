use super::super::*;

impl ConfigRepository {
    pub(in crate::config::v2) fn execute_credential_transaction_plan(
        &self,
        expected_revision: u64,
        bundle: Option<&CredentialBundle>,
        plan: CredentialTransactionPlan,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        self.preflight_credential_transaction_plan(bundle, &plan, credential_store)?;
        {
            let _lock = self.exclusive_lock()?;
            self.install_credential_transaction_intent_locked(expected_revision, &plan)?;
        }
        self.execute_installed_credential_transaction_plan(
            expected_revision,
            bundle,
            plan,
            credential_store,
        )
    }

    pub(in crate::config::v2) fn preflight_credential_transaction_plan(
        &self,
        bundle: Option<&CredentialBundle>,
        plan: &CredentialTransactionPlan,
        credential_store: &dyn CredentialStore,
    ) -> Result<(), ConfigError> {
        if let Some(bundle) = bundle {
            for (kind, secret) in bundle.slots() {
                if let Some(secret) = secret {
                    let credential_id = plan.credential_ids.get(&kind).ok_or_else(|| {
                        ConfigError::InvalidConfig {
                            path: "$.credential_transaction".to_string(),
                            reason: format!("planned {kind:?} credential has no id"),
                        }
                    })?;
                    credential_store
                        .validate(credential_id, secret)
                        .map_err(|source| ConfigError::CredentialValidation { kind, source })?;
                }
            }
            preflight_credential_slots(credential_store, &plan.credential_ids)?;
        }
        Ok(())
    }

    pub(in crate::config::v2) fn install_credential_transaction_intent_locked(
        &self,
        expected_revision: u64,
        plan: &CredentialTransactionPlan,
    ) -> Result<(), ConfigError> {
        let current_predecessor = self.pending_credential_transaction_locked()?;
        match (&plan.predecessor_journal_bytes, current_predecessor) {
            (None, None) => {}
            (Some(expected), Some((_, state, actual)))
                if matches!(
                    state,
                    CredentialTransactionState::Committed | CredentialTransactionState::Cleanup
                ) && expected == &actual => {}
            _ => {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: self.paths.credential_transaction_journal(),
                    reason: "credential cleanup intent changed during backend preflight"
                        .to_string(),
                });
            }
        }
        let current_primary = read_file(
            &self.paths.config(),
            "recheck config before credential intent",
        )?;
        let current_config = parse_config(&self.paths.config(), &current_primary)?;
        self.ensure_legacy_unchanged(&current_config)?;
        if byte_digest(&current_primary) != plan.journal.source_primary.raw_digest {
            let actual = current_config.revision;
            return Err(if actual == expected_revision {
                ConfigError::ConfigContentConflict {
                    revision: expected_revision,
                }
            } else {
                ConfigError::RevisionConflict {
                    expected: expected_revision,
                    actual,
                }
            });
        }
        let current_backup_digest = self
            .read_optional_durable_config_with_digest(&self.paths.backup())?
            .map(|(_, digest)| digest);
        let expected_backup_digest = plan
            .journal
            .source_backup
            .as_ref()
            .map(|generation| generation.raw_digest.clone());
        if current_backup_digest != expected_backup_digest {
            return Err(ConfigError::ConfigContentConflict {
                revision: expected_revision,
            });
        }
        atomic_write(
            &self.paths.credential_transaction_journal(),
            &plan.journal_bytes,
        )
    }

    pub(in crate::config::v2) fn execute_installed_credential_transaction_plan(
        &self,
        expected_revision: u64,
        bundle: Option<&CredentialBundle>,
        plan: CredentialTransactionPlan,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let mut created_ids = BTreeSet::new();
        if let Some(bundle) = bundle {
            if let Err(error) = prepare_credential_slots(
                credential_store,
                bundle,
                &plan.credential_ids,
                &mut created_ids,
            ) {
                let warnings = self
                    .reconcile_failed_credential_intent(credential_store, &plan.journal.new_ids);
                return Err(with_cleanup_warnings(error, warnings));
            }
        }

        let lock = match self.exclusive_lock_allow_credential_journal() {
            Ok(lock) => lock,
            Err(error) => {
                let warnings = self
                    .reconcile_failed_credential_intent(credential_store, &plan.journal.new_ids);
                return Err(with_cleanup_warnings(error, warnings));
            }
        };
        let mut backup_write_attempted = false;
        let mut primary_write_attempted = false;
        let commit_result = (|| {
            let (_, current_state, current_journal_bytes) = self
                .pending_credential_transaction_locked()?
                .ok_or_else(|| ConfigError::CredentialTransactionJournalConflict {
                    path: self.paths.credential_transaction_journal(),
                    reason: "credential transaction journal disappeared".to_string(),
                })?;
            if current_journal_bytes != plan.journal_bytes {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: self.paths.credential_transaction_journal(),
                    reason: "credential transaction journal changed during store I/O".to_string(),
                });
            }
            if !matches!(
                current_state,
                CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten
            ) {
                return Err(ConfigError::CredentialTransactionJournalConflict {
                    path: self.paths.credential_transaction_journal(),
                    reason: "credential intent is no longer in a pre-commit state".to_string(),
                });
            }
            let primary_path = self.paths.config();
            if !validate_regular_file_if_exists(&primary_path)? {
                return Err(ConfigError::MissingConfig { path: primary_path });
            }
            let previous_bytes = read_file(&primary_path, "read config")?;
            let latest = parse_config(&primary_path, &previous_bytes)?;
            self.ensure_legacy_unchanged(&latest)?;
            if latest.revision != expected_revision {
                return Err(ConfigError::RevisionConflict {
                    expected: expected_revision,
                    actual: latest.revision,
                });
            }
            if byte_digest(&previous_bytes) != plan.journal.source_primary.raw_digest {
                return Err(ConfigError::ConfigContentConflict {
                    revision: expected_revision,
                });
            }
            backup_write_attempted = true;
            atomic_write(&self.paths.backup(), &previous_bytes)?;
            primary_write_attempted = true;
            atomic_write(&primary_path, &plan.candidate_bytes)
        })();

        let mut warnings = Vec::new();
        let mut skip_postcommit_cleanup = false;
        if let Err(error) = commit_result {
            let commit_reason = error.to_string();
            let published = if primary_write_attempted {
                match self.resolve_credential_commit_outcome_locked(&plan) {
                    Ok(published) => published,
                    Err(ambiguous) => {
                        drop(lock);
                        return Err(ambiguous);
                    }
                }
            } else {
                if backup_write_attempted {
                    if let Err(ambiguous) = self.repair_aborted_credential_state_locked(&plan) {
                        drop(lock);
                        return Err(ambiguous);
                    }
                }
                false
            };
            if published {
                warnings.push(CredentialTransactionWarning::CommitRecovered {
                    reason: commit_reason,
                });
                let owns_journal = read_file(
                    &self.paths.credential_transaction_journal(),
                    "verify recovered credential intent ownership",
                )
                .is_ok_and(|bytes| bytes == plan.journal_bytes);
                if !owns_journal {
                    skip_postcommit_cleanup = true;
                    warnings.push(CredentialTransactionWarning::CleanupDeferred {
                        credential_ids: credential_ids_from_slots(
                            &plan.journal.retired_slots,
                        )
                        .into_iter()
                        .collect(),
                        reason: "credential commit is published but its cleanup intent changed; preserving it for explicit recovery"
                            .to_string(),
                    });
                }
            } else {
                let owns_precommit_intent =
                    self.pending_credential_transaction_locked()
                        .is_ok_and(|pending| {
                            pending.is_some_and(|(_, state, bytes)| {
                                matches!(
                                    state,
                                    CredentialTransactionState::Initial
                                        | CredentialTransactionState::BackupWritten
                                ) && bytes == plan.journal_bytes
                            })
                        });
                drop(lock);
                let cleanup_warnings = if owns_precommit_intent {
                    self.reconcile_failed_credential_intent(credential_store, &created_ids)
                } else {
                    vec![CredentialTransactionWarning::CleanupDeferred {
                        credential_ids: created_ids.iter().cloned().collect(),
                        reason: "credential intent or config changed before commit; published-id safety requires explicit recovery"
                            .to_string(),
                    }]
                };
                return Err(with_cleanup_warnings(error, cleanup_warnings));
            }
        }
        drop(lock);

        if !skip_postcommit_cleanup {
            match self.reconcile_credentials_with_operation_lock(credential_store) {
                Ok(reconciled) => warnings.extend(reconciled.warnings),
                Err(error) => warnings.push(CredentialTransactionWarning::CleanupDeferred {
                    credential_ids: credential_ids_from_slots(&plan.journal.retired_slots)
                        .into_iter()
                        .collect(),
                    reason: error.to_string(),
                }),
            }
        }
        Ok(CredentialTransactionOutcome {
            snapshot: ConfigSnapshot {
                config: plan.candidate_config,
            },
            warnings,
        })
    }

    pub(in crate::config::v2) fn resolve_credential_commit_outcome_locked(
        &self,
        plan: &CredentialTransactionPlan,
    ) -> Result<bool, ConfigError> {
        let candidate_revision = plan.journal.candidate.revision;
        let primary_bytes = read_file(
            &self.paths.config(),
            "resolve ambiguous credential primary write",
        )
        .map_err(|error| ConfigError::CredentialCommitAmbiguous {
            candidate_revision,
            reason: error.to_string(),
        })?;
        let backup_bytes = read_file(
            &self.paths.backup(),
            "resolve ambiguous credential backup write",
        )
        .map_err(|error| ConfigError::CredentialCommitAmbiguous {
            candidate_revision,
            reason: error.to_string(),
        })?;
        if primary_bytes == plan.candidate_bytes
            && byte_digest(&backup_bytes) == plan.journal.source_primary.raw_digest
        {
            self.repair_published_credential_state_locked(plan)?;
            return Ok(true);
        }

        let primary = parse_config(&self.paths.config(), &primary_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: error.to_string(),
            }
        })?;
        parse_config(&self.paths.backup(), &backup_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: error.to_string(),
            }
        })?;
        if !plan
            .journal
            .new_ids
            .is_disjoint(&referenced_credential_ids(&primary))
        {
            return Err(ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: "live primary references one or more freshly written credential ids"
                    .to_string(),
            });
        }
        Ok(false)
    }

    pub(in crate::config::v2) fn repair_published_credential_state_locked(
        &self,
        plan: &CredentialTransactionPlan,
    ) -> Result<(), ConfigError> {
        let candidate_revision = plan.journal.candidate.revision;
        atomic_write(&self.paths.backup(), &plan.source_primary_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: format!("failed to durably repair committed backup: {error}"),
            }
        })?;
        atomic_write(&self.paths.config(), &plan.candidate_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: format!("failed to durably repair committed primary: {error}"),
            }
        })
    }

    pub(in crate::config::v2) fn repair_aborted_credential_state_locked(
        &self,
        plan: &CredentialTransactionPlan,
    ) -> Result<(), ConfigError> {
        let candidate_revision = plan.journal.candidate.revision;
        atomic_write(&self.paths.config(), &plan.source_primary_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: format!("failed to durably repair aborted primary: {error}"),
            }
        })?;
        atomic_write(&self.paths.backup(), &plan.source_primary_bytes).map_err(|error| {
            ConfigError::CredentialCommitAmbiguous {
                candidate_revision,
                reason: format!("failed to durably repair aborted backup: {error}"),
            }
        })
    }

    pub(in crate::config::v2) fn load_credential_transaction_source(
        &self,
        expected_revision: u64,
    ) -> Result<CredentialTransactionSource, ConfigError> {
        let source = self.load_latest_credential_transaction_source()?;
        if source.config.revision != expected_revision {
            return Err(ConfigError::RevisionConflict {
                expected: expected_revision,
                actual: source.config.revision,
            });
        }
        Ok(source)
    }

    pub(in crate::config::v2) fn load_latest_credential_transaction_source(
        &self,
    ) -> Result<CredentialTransactionSource, ConfigError> {
        let (carried_retired_slots, predecessor_journal_bytes) =
            match self.pending_credential_transaction_locked()? {
                None => (BTreeSet::new(), None),
                Some((
                    journal,
                    CredentialTransactionState::Committed | CredentialTransactionState::Cleanup,
                    bytes,
                )) => {
                    let carried = journal
                        .retired_slots
                        .iter()
                        .filter(|slot| !journal.settled_retired_ids.contains(&slot.credential_id))
                        .cloned()
                        .collect();
                    (carried, Some(bytes))
                }
                Some((
                    _,
                    CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten,
                    _,
                )) => {
                    return Err(ConfigError::CredentialRecoveryRequired {
                        path: self.paths.credential_transaction_journal(),
                    });
                }
            };
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::MissingConfig { path: primary_path });
        }
        let source_primary_bytes = read_file(&primary_path, "read config")?;
        let config = parse_config(&primary_path, &source_primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let source_backup = self.read_optional_durable_config_with_digest(&self.paths.backup())?;
        Ok(CredentialTransactionSource {
            config,
            source_primary_bytes,
            source_backup,
            carried_retired_slots,
            predecessor_journal_bytes,
        })
    }

    pub(in crate::config::v2) fn plan_credential_transaction<F>(
        &self,
        source: CredentialTransactionSource,
        write: Option<&CredentialWriteSpec<'_>>,
        prepared_credential_ids: Option<&BTreeMap<CredentialKind, CredentialId>>,
        mutate: F,
    ) -> Result<CredentialTransactionPlan, ConfigError>
    where
        F: FnOnce(
            &mut ConfigV2,
            &BTreeMap<CredentialKind, CredentialId>,
        ) -> Result<(), ConfigError>,
    {
        let CredentialTransactionSource {
            mut config,
            source_primary_bytes,
            source_backup,
            carried_retired_slots,
            predecessor_journal_bytes,
        } = source;
        let source_primary = config.clone();
        let expected_kinds: BTreeSet<_> = write
            .iter()
            .flat_map(|write| write.bundle.slots())
            .filter_map(|(kind, secret)| secret.is_some().then_some(kind))
            .collect();
        let mut credential_ids = prepared_credential_ids.cloned().unwrap_or_default();
        if prepared_credential_ids.is_some()
            && credential_ids.keys().copied().collect::<BTreeSet<_>>() != expected_kinds
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.credential_transaction.new_ids".to_string(),
                reason: "prepared credential ids must exactly match the bundle slots".to_string(),
            });
        }
        if prepared_credential_ids.is_none() {
            if let Some(write) = write {
                for kind in expected_kinds {
                    credential_ids.insert(
                        kind,
                        CredentialId::fresh(
                            self.paths.root(),
                            write.connection_id,
                            write.profile_name,
                            kind,
                        )?,
                    );
                }
            }
        }
        mutate(&mut config, &credential_ids)?;
        config.revision = config
            .revision
            .checked_add(1)
            .ok_or(ConfigError::RevisionOverflow)?;
        validate_repository_credential_ids(&config, self.paths.root())?;
        let candidate_bytes = serialize_config(&config)?;
        let source_ids = referenced_credential_ids(&source_primary);
        let candidate_ids = referenced_credential_ids(&config);
        let new_ids: BTreeSet<_> = candidate_ids.difference(&source_ids).cloned().collect();
        let expected_new_ids: BTreeSet<_> = credential_ids.values().cloned().collect();
        if new_ids != expected_new_ids {
            return Err(ConfigError::InvalidConfig {
                path: "$.credential_transaction.new_ids".to_string(),
                reason: "credential writes must exactly match candidate refs minus source refs"
                    .to_string(),
            });
        }
        if credential_ids.is_empty() && source_ids.is_subset(&candidate_ids) {
            return Err(ConfigError::InvalidConfig {
                path: "$.credential_transaction".to_string(),
                reason: "a zero-write credential transaction must retire durable references"
                    .to_string(),
            });
        }
        let source_slots = credential_slot_refs(&source_primary);
        let candidate_slots = credential_slot_refs(&config);
        let mut base_retired_slots: BTreeSet<_> =
            source_slots.difference(&candidate_slots).cloned().collect();
        let source_backup = match source_backup {
            Some((backup, digest)) => {
                let backup_slots = credential_slot_refs(&backup);
                base_retired_slots.extend(backup_slots.difference(&source_slots).cloned());
                Some(credential_generation(&backup, digest))
            }
            None => None,
        };
        let carried_retired_slots: BTreeSet<_> = carried_retired_slots
            .difference(&base_retired_slots)
            .cloned()
            .collect();
        let mut retired_slots = base_retired_slots;
        retired_slots.extend(carried_retired_slots.iter().cloned());
        let source_primary_generation =
            credential_generation(&source_primary, byte_digest(&source_primary_bytes));
        let candidate_generation = credential_generation(&config, byte_digest(&candidate_bytes));
        let journal = CredentialTransactionJournal {
            journal_version: CREDENTIAL_TRANSACTION_JOURNAL_VERSION,
            source_primary: source_primary_generation,
            source_backup,
            candidate: candidate_generation,
            new_ids,
            retired_slots,
            carried_retired_slots,
            settled_retired_ids: BTreeSet::new(),
            aborted: false,
            aborted_after_backup_write: false,
        };
        let journal_bytes = serialize_credential_transaction_journal(&journal)?;
        Ok(CredentialTransactionPlan {
            journal,
            journal_bytes,
            candidate_config: config,
            source_primary_bytes,
            candidate_bytes,
            credential_ids,
            predecessor_journal_bytes,
        })
    }
}
