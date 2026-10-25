use super::super::*;

impl ConfigRepository {
    #[allow(dead_code)]
    pub(crate) fn commit_authenticated_session(
        &self,
        expected_revision: u64,
        input: AuthenticatedSessionCommit,
        credential_store: &dyn CredentialStore,
    ) -> Result<AuthenticatedSessionOutcome, ConfigError> {
        let AuthenticatedSessionCommit {
            endpoint,
            storage_id,
            target,
            identity,
            client_id,
            profile_name,
            bundle,
            account_binding,
        } = input;
        if let Some(storage_id) = &storage_id {
            validate_required_metadata("$.authenticated_session.storage_id", storage_id)?;
        }
        validate_string_len(
            "$.authenticated_session.profile_name",
            &profile_name,
            MAX_LEGACY_NAME_LEN,
        )?;
        validate_credential_bundle_input("$.authenticated_session.bundle", &bundle)?;
        let connection_id = match &target {
            AuthenticatedConnectionTarget::Create { connection_name } => {
                validate_string_len(
                    "$.authenticated_session.target.connection_name",
                    connection_name,
                    MAX_LEGACY_NAME_LEN,
                )?;
                ConnectionId::deterministic(connection_name, endpoint.address())
            }
            AuthenticatedConnectionTarget::UseExisting { connection_id, .. }
            | AuthenticatedConnectionTarget::PinExisting { connection_id, .. }
            | AuthenticatedConnectionTarget::ReplaceFingerprint { connection_id, .. }
            | AuthenticatedConnectionTarget::RelocateEndpoint { connection_id, .. } => {
                connection_id.clone()
            }
        };
        let write = CredentialWriteSpec {
            connection_id: &connection_id,
            profile_name: &profile_name,
            bundle: &bundle,
        };
        let transaction = self.execute_credential_transaction(
            expected_revision,
            Some(write),
            credential_store,
            |config, credential_ids| {
                apply_identity_commit(config, &identity)?;
                apply_authenticated_connection_target(
                    config,
                    &connection_id,
                    &target,
                    &endpoint,
                    storage_id.as_deref(),
                )?;
                apply_credential_bundle_replacement(
                    config,
                    &connection_id,
                    &profile_name,
                    bundle.access_expires_at.clone(),
                    credential_ids,
                    CredentialActivation::MakeActive,
                )?;
                if let Some((account_subject, auth_method)) = &account_binding {
                    validate_required_metadata(
                        "$.authenticated_session.account_subject",
                        account_subject,
                    )?;
                    let profile = config
                        .connections
                        .get_mut(&connection_id)
                        .and_then(|connection| {
                            connection.credential_profiles.get_mut(&profile_name)
                        })
                        .ok_or_else(|| ConfigError::MissingCredentialProfile {
                            connection_id: connection_id.clone(),
                            profile_name: profile_name.clone(),
                        })?;
                    profile.account_subject = Some(account_subject.clone());
                    profile.auth_method = Some(*auth_method);
                }
                client_entry(config, &client_id).active_connection = Some(connection_id.clone());
                Ok(())
            },
        )?;
        let actual_storage_id = transaction
            .snapshot()
            .config()
            .connections
            .get(&connection_id)
            .and_then(|connection| connection.metadata.storage_id.clone());
        debug_assert!(
            transaction
                .snapshot()
                .config()
                .connections
                .contains_key(&connection_id),
            "authenticated session candidate must contain its resolved connection"
        );
        Ok(AuthenticatedSessionOutcome {
            transaction,
            connection_id,
            storage_id: actual_storage_id,
            profile_name,
        })
    }

    pub fn remove_credential_profile(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        profile_name: impl Into<String>,
        active_after: ActiveCredentialAfterRemoval,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let profile_name = profile_name.into();
        validate_string_len(
            "$.connections.*.credential_profiles.<name>",
            &profile_name,
            MAX_LEGACY_NAME_LEN,
        )?;
        if let ActiveCredentialAfterRemoval::Activate(fallback) = &active_after {
            validate_string_len(
                "$.credential_removal.active_after",
                fallback,
                MAX_LEGACY_NAME_LEN,
            )?;
        }
        self.execute_credential_transaction(
            expected_revision,
            None,
            credential_store,
            |config, credential_ids| {
                if !credential_ids.is_empty() {
                    return Err(ConfigError::InvalidConfig {
                        path: "$.credential_removal".to_string(),
                        reason: "credential removal must not allocate credential ids".to_string(),
                    });
                }
                apply_credential_profile_removal(
                    config,
                    connection_id,
                    &profile_name,
                    &active_after,
                )
            },
        )
    }

    /// Removes a profile only when its repository-bound refresh anchor still
    /// matches, rebasing over unrelated config revisions.
    ///
    /// This is the inverse of
    /// [`Self::replace_credential_bundle_if_profile_matches`]. It is used for
    /// a definitive refresh rejection so a concurrent update to another
    /// client namespace or active-profile selection cannot either block
    /// revocation or delete a newer credential generation.
    pub fn remove_credential_profile_if_matches(
        &self,
        anchor: &CredentialProfileAnchor,
        active_after: ActiveCredentialAfterRemoval,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let _operation = self.credential_operation_lock()?;
        self.remove_credential_profile_if_matches_with_operation_lock(
            anchor,
            active_after,
            credential_store,
        )
    }

    pub(crate) fn remove_credential_profile_if_matches_with_operation_lock(
        &self,
        anchor: &CredentialProfileAnchor,
        active_after: ActiveCredentialAfterRemoval,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        self.remove_credential_profile_if_matches_with_optional_auth_intent(
            anchor,
            active_after,
            credential_store,
            None,
        )
    }

    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn remove_credential_profile_after_auth_intent_with_operation_locks(
        &self,
        permit: &AuthOperationIntentPermit,
        active_after: ActiveCredentialAfterRemoval,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let anchor = permit.anchor.clone();
        self.remove_credential_profile_if_matches_with_optional_auth_intent(
            &anchor,
            active_after,
            credential_store,
            Some(permit),
        )
    }

    pub(in crate::config::v2) fn remove_credential_profile_if_matches_with_optional_auth_intent(
        &self,
        anchor: &CredentialProfileAnchor,
        active_after: ActiveCredentialAfterRemoval,
        credential_store: &dyn CredentialStore,
        auth_permit: Option<&AuthOperationIntentPermit>,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        if let ActiveCredentialAfterRemoval::Activate(fallback) = &active_after {
            validate_string_len(
                "$.credential_removal.active_after",
                fallback,
                MAX_LEGACY_NAME_LEN,
            )?;
        }
        let (expected_revision, plan) = {
            let _lock = self.exclusive_lock()?;
            if let Some(permit) = auth_permit {
                let (intent, _) = self.ensure_owned_auth_operation_intent_locked(permit)?;
                if !matches!(
                    self.classify_auth_operation_intent_locked(&intent)?,
                    AuthIntentState::Source(current) if *current == *anchor
                ) {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason:
                            "owned authentication intent is not anchored to the exact revoke source"
                                .to_string(),
                    });
                }
            }
            let source = self.load_latest_credential_transaction_source()?;
            ensure_credential_profile_anchor_matches(
                anchor,
                &credential_profile_anchor_repository_binding(self.paths.root())?,
                &source.config,
                &byte_digest(&source.source_primary_bytes),
            )?;
            let expected_revision = source.config.revision;
            let plan =
                self.plan_credential_transaction(source, None, None, |config, credential_ids| {
                    if !credential_ids.is_empty() {
                        return Err(ConfigError::InvalidConfig {
                            path: "$.credential_removal".to_string(),
                            reason: "credential removal must not allocate credential ids"
                                .to_string(),
                        });
                    }
                    apply_credential_profile_removal(
                        config,
                        &anchor.connection_id,
                        &anchor.profile_name,
                        &active_after,
                    )
                })?;
            self.install_credential_transaction_intent_locked(expected_revision, &plan)?;
            (expected_revision, plan)
        };
        let outcome = self.execute_installed_credential_transaction_plan(
            expected_revision,
            None,
            plan,
            credential_store,
        )?;
        if let Some(permit) = auth_permit {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            let (intent, bytes) = self.ensure_owned_auth_operation_intent_locked(permit)?;
            if !matches!(
                self.classify_auth_operation_intent_locked(&intent)?,
                AuthIntentState::TargetRemoved
            ) {
                return Err(ConfigError::AuthOperationIntentConflict {
                    path: self.paths.auth_operation_intent(),
                    reason: "journaled revoke did not remove the intended profile".to_string(),
                });
            }
            self.remove_auth_operation_intent_locked(&bytes)?;
        }
        Ok(outcome)
    }
}
