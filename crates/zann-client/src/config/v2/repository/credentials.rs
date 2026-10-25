use super::super::*;

impl ConfigRepository {
    pub fn reconcile_credentials(
        &self,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let _operation = self.credential_operation_lock()?;
        self.reconcile_credentials_with_operation_lock(credential_store)
    }

    pub(crate) fn reconcile_credentials_with_operation_lock(
        &self,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let (_journal, state, journal_bytes, targets, delete_ids) = {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            let Some((journal, state, journal_bytes)) =
                self.pending_credential_transaction_locked()?
            else {
                let config = self.read_primary()?;
                self.ensure_legacy_unchanged(&config)?;
                return Ok(CredentialTransactionOutcome {
                    snapshot: ConfigSnapshot { config },
                    warnings: Vec::new(),
                });
            };
            // A prior atomic replace may have become visible before its directory sync failed.
            // Durably accept the exact state we just classified before deleting any secret or
            // weakening the recovery intent.
            sync_parent(self.paths.root())?;
            let targets = credential_cleanup_targets(&journal, state);
            let durable_refs = self.durable_referenced_credential_ids_locked()?;
            let delete_ids: BTreeSet<_> = targets.difference(&durable_refs).cloned().collect();
            (journal, state, journal_bytes, targets, delete_ids)
        };

        let mut delete_failures = BTreeMap::new();
        for credential_id in &delete_ids {
            if let Err(source) = credential_store.delete(credential_id) {
                delete_failures.insert(credential_id.clone(), source);
            }
        }

        let _lock = self.exclusive_lock_allow_credential_journal()?;
        let Some((mut current, current_state, current_bytes)) =
            self.pending_credential_transaction_locked()?
        else {
            let config = self.read_primary()?;
            self.ensure_legacy_unchanged(&config)?;
            return Ok(CredentialTransactionOutcome {
                snapshot: ConfigSnapshot { config },
                warnings: Vec::new(),
            });
        };
        if current_bytes != journal_bytes || current_state != state {
            return Err(ConfigError::CredentialTransactionJournalConflict {
                path: self.paths.credential_transaction_journal(),
                reason: "credential intent changed while cleanup ran".to_string(),
            });
        }
        sync_parent(self.paths.root())?;
        let durable_refs = self.durable_referenced_credential_ids_locked()?;
        let deleted_successfully: BTreeSet<_> = delete_ids
            .iter()
            .filter(|credential_id| !delete_failures.contains_key(*credential_id))
            .cloned()
            .collect();
        if let Some(republished) = deleted_successfully.intersection(&durable_refs).next() {
            return Err(ConfigError::CredentialTransactionJournalConflict {
                path: self.paths.credential_transaction_journal(),
                reason: format!(
                    "credential {republished} became durable while cleanup was in progress"
                ),
            });
        }

        let mut warnings = Vec::new();
        for (credential_id, source) in delete_failures {
            warnings.push(CredentialTransactionWarning::CredentialDeleteFailed {
                credential_id,
                source,
            });
        }
        let reachable: Vec<_> = targets.intersection(&durable_refs).cloned().collect();
        if !reachable.is_empty() {
            warnings.push(CredentialTransactionWarning::CleanupDeferred {
                credential_ids: reachable,
                reason: "credential ids remain referenced by a durable config generation"
                    .to_string(),
            });
        }

        let mut reconcile_again = false;
        match state {
            CredentialTransactionState::Initial | CredentialTransactionState::BackupWritten => {
                if warnings.iter().any(|warning| {
                    matches!(
                        warning,
                        CredentialTransactionWarning::CredentialDeleteFailed { .. }
                    )
                }) {
                    // The source intent remains the durable cleanup authority for a retry.
                } else {
                    current.aborted = true;
                    current.aborted_after_backup_write =
                        state == CredentialTransactionState::BackupWritten;
                    let mut retained = current.carried_retired_slots.clone();
                    if let Some(old_backup) = &current.source_backup {
                        retained.extend(
                            old_backup
                                .slots
                                .difference(&current.source_primary.slots)
                                .cloned(),
                        );
                    }
                    current.retired_slots = retained;
                    current.settled_retired_ids.retain(|credential_id| {
                        current
                            .retired_slots
                            .iter()
                            .any(|slot| &slot.credential_id == credential_id)
                    });
                    if current.retired_slots.is_empty() {
                        self.remove_credential_transaction_journal_locked()?;
                    } else {
                        let bytes = serialize_credential_transaction_journal(&current)?;
                        atomic_write(&self.paths.credential_transaction_journal(), &bytes)?;
                        reconcile_again = true;
                    }
                }
            }
            CredentialTransactionState::Committed | CredentialTransactionState::Cleanup => {
                current
                    .settled_retired_ids
                    .extend(deleted_successfully.iter().cloned());
                let remaining = credential_cleanup_targets(&current, current_state);
                if remaining.is_empty() {
                    self.remove_credential_transaction_journal_locked()?;
                } else if !deleted_successfully.is_empty() {
                    let bytes = serialize_credential_transaction_journal(&current)?;
                    atomic_write(&self.paths.credential_transaction_journal(), &bytes)?;
                }
            }
        }
        if reconcile_again {
            drop(_lock);
            let mut followup = self.reconcile_credentials_with_operation_lock(credential_store)?;
            warnings.append(&mut followup.warnings);
            return Ok(CredentialTransactionOutcome {
                snapshot: followup.snapshot,
                warnings,
            });
        }
        let config = self.read_primary()?;
        self.ensure_legacy_unchanged(&config)?;
        Ok(CredentialTransactionOutcome {
            snapshot: ConfigSnapshot { config },
            warnings,
        })
    }

    pub(in crate::config::v2) fn execute_credential_transaction<F>(
        &self,
        expected_revision: u64,
        write: Option<CredentialWriteSpec<'_>>,
        credential_store: &dyn CredentialStore,
        mutate: F,
    ) -> Result<CredentialTransactionOutcome, ConfigError>
    where
        F: FnOnce(
            &mut ConfigV2,
            &BTreeMap<CredentialKind, CredentialId>,
        ) -> Result<(), ConfigError>,
    {
        let _operation = self.credential_operation_lock()?;
        let plan = {
            let _lock = self.exclusive_lock()?;
            let source = self.load_credential_transaction_source(expected_revision)?;
            self.plan_credential_transaction(source, write.as_ref(), None, mutate)?
        };
        self.execute_credential_transaction_plan(
            expected_revision,
            write.as_ref().map(|write| write.bundle),
            plan,
            credential_store,
        )
    }

    pub fn replace_credential_bundle(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        profile_name: impl Into<String>,
        bundle: CredentialBundle,
        activation: CredentialActivation,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let profile_name = profile_name.into();
        validate_string_len(
            "$.connections.*.credential_profiles.<name>",
            &profile_name,
            MAX_LEGACY_NAME_LEN,
        )?;
        validate_credential_bundle_input(
            &format!("$.connections.{connection_id}.credential_profiles.{profile_name}"),
            &bundle,
        )?;
        let write = CredentialWriteSpec {
            connection_id,
            profile_name: &profile_name,
            bundle: &bundle,
        };
        self.execute_credential_transaction(
            expected_revision,
            Some(write),
            credential_store,
            |config, credential_ids| {
                apply_credential_bundle_replacement(
                    config,
                    connection_id,
                    &profile_name,
                    bundle.access_expires_at.clone(),
                    credential_ids,
                    activation,
                )
            },
        )
    }

    /// Replaces an explicitly anchored profile after an out-of-lock network operation.
    ///
    /// The global config revision may advance while the caller refreshes a token. This operation
    /// rebases onto the latest source generation when the anchored repository, endpoint trust and
    /// exact profile state still match. Credential ids are preflighted once, then reused when the
    /// candidate is rebuilt under the final config lock; no credential port is called while that
    /// lock is held.
    pub fn replace_credential_bundle_if_profile_matches(
        &self,
        anchor: &CredentialProfileAnchor,
        bundle: CredentialBundle,
        activation: CredentialActivation,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        validate_credential_bundle_input(
            &format!(
                "$.connections.{}.credential_profiles.{}",
                anchor.connection_id, anchor.profile_name
            ),
            &bundle,
        )?;
        let _operation = self.credential_operation_lock()?;
        let access_expires_at = bundle.access_expires_at.clone();
        self.execute_anchored_credential_write_with_operation_lock(
            anchor,
            &bundle,
            credential_store,
            None,
            |config, credential_ids| {
                apply_credential_bundle_replacement(
                    config,
                    &anchor.connection_id,
                    &anchor.profile_name,
                    access_expires_at.clone(),
                    credential_ids,
                    activation,
                )
            },
        )
    }

    /// Rotates only the access/refresh pair for an anchored session profile.
    ///
    /// Any service-account credential in the same profile retains its exact
    /// credential id and secret. This avoids turning a token refresh into a
    /// destructive full-profile replacement.
    pub fn rotate_session_credentials_if_profile_matches(
        &self,
        anchor: &CredentialProfileAnchor,
        access: CredentialSecret,
        refresh: CredentialSecret,
        access_expires_at: String,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let _operation = self.credential_operation_lock()?;
        self.rotate_session_credentials_if_profile_matches_with_operation_lock(
            anchor,
            access,
            refresh,
            access_expires_at,
            credential_store,
        )
    }

    pub(crate) fn rotate_session_credentials_if_profile_matches_with_operation_lock(
        &self,
        anchor: &CredentialProfileAnchor,
        access: CredentialSecret,
        refresh: CredentialSecret,
        access_expires_at: String,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        if !anchor.credentials.contains_key(&CredentialKind::Refresh) {
            return Err(ConfigError::InvalidConfig {
                path: "$.session_refresh".to_string(),
                reason: "session profile has no refresh credential".to_string(),
            });
        }
        let bundle = CredentialBundle::new(Some(access), Some(refresh), None)
            .with_access_expires_at(Some(access_expires_at.clone()));
        validate_credential_bundle_input(
            &format!(
                "$.connections.{}.credential_profiles.{}",
                anchor.connection_id, anchor.profile_name
            ),
            &bundle,
        )?;
        self.execute_anchored_credential_write_with_operation_lock(
            anchor,
            &bundle,
            credential_store,
            None,
            |config, credential_ids| {
                apply_session_credential_rotation(
                    config,
                    &anchor.connection_id,
                    &anchor.profile_name,
                    access_expires_at.clone(),
                    credential_ids,
                )
            },
        )
    }

    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn rotate_session_credentials_after_auth_intent_with_operation_locks(
        &self,
        permit: &mut AuthOperationIntentPermit,
        access: CredentialSecret,
        refresh: CredentialSecret,
        access_expires_at: String,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        if permit.operation != AuthOperationKind::Refresh {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "logout ownership token cannot publish a refresh candidate".to_string(),
            });
        }
        let anchor = permit.anchor.clone();
        let bundle = CredentialBundle::new(Some(access), Some(refresh), None)
            .with_access_expires_at(Some(access_expires_at.clone()));
        validate_credential_bundle_input(
            &format!(
                "$.connections.{}.credential_profiles.{}",
                anchor.connection_id, anchor.profile_name
            ),
            &bundle,
        )?;
        self.execute_anchored_credential_write_with_operation_lock(
            &anchor,
            &bundle,
            credential_store,
            Some(permit),
            |config, credential_ids| {
                apply_session_credential_rotation(
                    config,
                    &anchor.connection_id,
                    &anchor.profile_name,
                    access_expires_at.clone(),
                    credential_ids,
                )
            },
        )
    }
}
