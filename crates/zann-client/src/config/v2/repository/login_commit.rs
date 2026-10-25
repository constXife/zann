use super::super::*;

impl ConfigRepository {
    /// Publishes the exact password-login candidate represented by a v2 auth
    /// intent. The caller continues to hold auth then credential locks.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_password_login_after_auth_intent_with_operation_locks<F>(
        &self,
        permit: &mut PasswordLoginIntentPermit,
        account_subject: &str,
        authenticated_identity: ConfigIdentity,
        access: CredentialSecret,
        refresh: CredentialSecret,
        access_expires_at: String,
        credential_store: &dyn CredentialStore,
        abort_before_candidate: F,
    ) -> Result<CredentialTransactionOutcome, ConfigError>
    where
        F: Fn() -> bool,
    {
        validate_required_metadata("$.password_login.account_subject", account_subject)?;
        let authenticated_email = authenticated_identity.email.as_deref().ok_or_else(|| {
            ConfigError::AuthenticatedIdentityConflict {
                reason: "authenticated password login identity has no canonical email".to_string(),
            }
        })?;
        if authenticated_email.is_empty() || authenticated_email.trim() != authenticated_email {
            return Err(ConfigError::AuthenticatedIdentityConflict {
                reason: "authenticated password login identity has a noncanonical email"
                    .to_string(),
            });
        }
        validate_string_len("$.password_login.identity.email", authenticated_email, 320)?;
        let anchor = permit.anchor.clone();
        let identity = authenticated_identity;
        let bundle = CredentialBundle::new(Some(access), Some(refresh), None)
            .with_access_expires_at(Some(access_expires_at.clone()));
        validate_credential_bundle_input("$.password_login.bundle", &bundle)?;
        let prepared_ids = BTreeMap::from([
            (
                CredentialKind::Access,
                permit.reservation.access_credential_id.clone(),
            ),
            (
                CredentialKind::Refresh,
                permit.reservation.refresh_credential_id.clone(),
            ),
        ]);
        let apply = |config: &mut ConfigV2,
                     credential_ids: &BTreeMap<CredentialKind, CredentialId>| {
            apply_password_login_candidate(
                config,
                &anchor,
                &identity,
                account_subject,
                &access_expires_at,
                credential_ids,
            )
        };

        let initial_plan = {
            let _lock = self.exclusive_lock()?;
            let (intent, _) = self.ensure_owned_password_login_intent_locked(permit)?;
            if permit.identity.kdf_salt != identity.kdf_salt
                || permit.identity.kdf_params != identity.kdf_params
                || permit.identity.salt_fingerprint != identity.salt_fingerprint
            {
                return Err(ConfigError::AuthenticatedIdentityConflict {
                    reason: "post-authentication KDF identity differs from prelogin".to_string(),
                });
            }
            let source = self.load_latest_credential_transaction_source()?;
            ensure_password_login_transaction_source(&intent, &source)?;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle: &bundle,
            };
            self.plan_credential_transaction(source, Some(&write), Some(&prepared_ids), apply)?
        };
        self.preflight_credential_transaction_plan(Some(&bundle), &initial_plan, credential_store)?;
        if abort_before_candidate() {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password login was cancelled before candidate preparation".to_string(),
            });
        }

        let (expected_revision, plan) = {
            let _lock = self.exclusive_lock()?;
            let (intent, _) = self.ensure_owned_password_login_intent_locked(permit)?;
            let source = self.load_latest_credential_transaction_source()?;
            ensure_password_login_transaction_source(&intent, &source)?;
            let expected_revision = source.config.revision;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle: &bundle,
            };
            let plan = self.plan_credential_transaction(
                source,
                Some(&write),
                Some(&prepared_ids),
                |config, credential_ids| {
                    apply_password_login_candidate(
                        config,
                        &anchor,
                        &identity,
                        account_subject,
                        &access_expires_at,
                        credential_ids,
                    )
                },
            )?;
            if abort_before_candidate() {
                return Err(ConfigError::AuthOperationIntentConflict {
                    path: self.paths.auth_operation_intent(),
                    reason: "password login was cancelled before candidate preparation".to_string(),
                });
            }
            self.install_password_login_candidate_locked(permit, &plan, account_subject)?;
            self.install_credential_transaction_intent_locked(expected_revision, &plan)?;
            (expected_revision, plan)
        };
        let outcome = self.execute_installed_credential_transaction_plan(
            expected_revision,
            Some(&bundle),
            plan,
            credential_store,
        )?;
        let _lock = self.exclusive_lock_allow_credential_journal()?;
        self.accept_owned_password_login_locked(permit)?;
        Ok(outcome)
    }

    /// Proves that a candidate whose intent unlink became visible is the exact
    /// locally published password-login session. This performs no store I/O.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn password_login_candidate_is_published_with_operation_locks(
        &self,
        permit: &PasswordLoginIntentPermit,
    ) -> Result<Option<ConfigSnapshot>, ConfigError> {
        let Some(candidate) = permit.candidate.as_ref() else {
            return Ok(None);
        };
        let _lock = self.exclusive_lock_allow_credential_journal()?;
        if validate_regular_file_if_exists(&self.paths.auth_operation_intent())? {
            return Ok(None);
        }
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "verify password-login candidate")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        if config.revision != candidate.revision
            || byte_digest(&primary_bytes) != candidate.raw_digest
        {
            return Ok(None);
        }
        let Some(connection) = config.connections.get(&permit.anchor.connection_id) else {
            return Ok(None);
        };
        let Some(profile) = connection
            .credential_profiles
            .get(&permit.anchor.profile_name)
        else {
            return Ok(None);
        };
        let mut expected_credentials = permit
            .anchor
            .profile
            .as_ref()
            .map(|profile| profile.credentials.clone())
            .unwrap_or_default();
        expected_credentials.insert(
            CredentialKind::Access,
            candidate.access_credential_id.clone(),
        );
        expected_credentials.insert(
            CredentialKind::Refresh,
            candidate.refresh_credential_id.clone(),
        );
        let normalized_address = normalize_address(
            &connection.metadata.address,
            &format!(
                "$.connections.{}.metadata.address",
                permit.anchor.connection_id
            ),
        )?;
        let published = normalized_address == permit.anchor.normalized_address
            && connection.metadata.server_id.as_deref() == Some(permit.anchor.server_id.as_str())
            && connection.metadata.server_fingerprint.as_deref()
                == Some(permit.anchor.server_fingerprint.as_str())
            && connection.metadata.storage_id == permit.anchor.storage_id
            && connection.active_credential.as_deref() == Some(permit.anchor.profile_name.as_str())
            && config
                .clients
                .get(&permit.anchor.client_id)
                .and_then(|client| client.active_connection.as_ref())
                == Some(&permit.anchor.connection_id)
            && profile.credentials == expected_credentials
            && profile.account_subject.as_deref() == Some(candidate.account_subject.as_str())
            && profile.auth_method == Some(AuthMethod::Password)
            && profile.access_expires_at.as_deref() == Some(candidate.access_expires_at.as_str());
        Ok(published.then_some(ConfigSnapshot { config }))
    }

    #[cfg(test)]
    pub(in crate::config::v2) fn install_auth_rotation_candidate_without_credential_journal_for_test(
        &self,
        permit: &mut AuthOperationIntentPermit,
        access: CredentialSecret,
        refresh: CredentialSecret,
        access_expires_at: String,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionPlan, ConfigError> {
        let anchor = permit.anchor.clone();
        let bundle = CredentialBundle::new(Some(access), Some(refresh), None)
            .with_access_expires_at(Some(access_expires_at.clone()));
        let apply = |config: &mut ConfigV2,
                     credential_ids: &BTreeMap<CredentialKind, CredentialId>| {
            apply_session_credential_rotation(
                config,
                &anchor.connection_id,
                &anchor.profile_name,
                access_expires_at.clone(),
                credential_ids,
            )
        };
        let initial_plan = {
            let _lock = self.exclusive_lock()?;
            self.ensure_owned_auth_operation_intent_locked(permit)?;
            let source = self.load_latest_credential_transaction_source()?;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle: &bundle,
            };
            self.plan_credential_transaction(source, Some(&write), None, apply)?
        };
        self.preflight_credential_transaction_plan(Some(&bundle), &initial_plan, credential_store)?;
        let prepared_ids = initial_plan.credential_ids;
        let plan = {
            let _lock = self.exclusive_lock()?;
            self.ensure_owned_auth_operation_intent_locked(permit)?;
            let source = self.load_latest_credential_transaction_source()?;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle: &bundle,
            };
            let plan =
                self.plan_credential_transaction(source, Some(&write), Some(&prepared_ids), apply)?;
            self.install_auth_rotation_candidate_locked(permit, &plan)?;
            plan
        };
        Ok(plan)
    }

    #[cfg(test)]
    pub(in crate::config::v2) fn install_password_login_candidate_without_credential_journal_for_test(
        &self,
        permit: &mut PasswordLoginIntentPermit,
        account_subject: &str,
        bundle: &CredentialBundle,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionPlan, ConfigError> {
        let anchor = permit.anchor.clone();
        let identity = permit.identity.clone();
        let access_expires_at =
            bundle
                .access_expires_at
                .clone()
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: "$.password_login.bundle.access_expires_at".to_string(),
                    reason: "password-login test candidate requires an expiry".to_string(),
                })?;
        let prepared_ids = BTreeMap::from([
            (
                CredentialKind::Access,
                permit.reservation.access_credential_id.clone(),
            ),
            (
                CredentialKind::Refresh,
                permit.reservation.refresh_credential_id.clone(),
            ),
        ]);
        let initial_plan = {
            let _lock = self.exclusive_lock()?;
            let (intent, _) = self.ensure_owned_password_login_intent_locked(permit)?;
            let source = self.load_latest_credential_transaction_source()?;
            ensure_password_login_transaction_source(&intent, &source)?;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle,
            };
            self.plan_credential_transaction(
                source,
                Some(&write),
                Some(&prepared_ids),
                |config, ids| {
                    apply_password_login_candidate(
                        config,
                        &anchor,
                        &identity,
                        account_subject,
                        &access_expires_at,
                        ids,
                    )
                },
            )?
        };
        self.preflight_credential_transaction_plan(Some(bundle), &initial_plan, credential_store)?;
        let _lock = self.exclusive_lock()?;
        let (intent, _) = self.ensure_owned_password_login_intent_locked(permit)?;
        let source = self.load_latest_credential_transaction_source()?;
        ensure_password_login_transaction_source(&intent, &source)?;
        let write = CredentialWriteSpec {
            connection_id: &anchor.connection_id,
            profile_name: &anchor.profile_name,
            bundle,
        };
        let plan = self.plan_credential_transaction(
            source,
            Some(&write),
            Some(&prepared_ids),
            |config, ids| {
                apply_password_login_candidate(
                    config,
                    &anchor,
                    &identity,
                    account_subject,
                    &access_expires_at,
                    ids,
                )
            },
        )?;
        self.install_password_login_candidate_locked(permit, &plan, account_subject)?;
        Ok(plan)
    }

    pub(in crate::config::v2) fn execute_anchored_credential_write_with_operation_lock<F>(
        &self,
        anchor: &CredentialProfileAnchor,
        bundle: &CredentialBundle,
        credential_store: &dyn CredentialStore,
        mut auth_permit: Option<&mut AuthOperationIntentPermit>,
        apply: F,
    ) -> Result<CredentialTransactionOutcome, ConfigError>
    where
        F: Fn(&mut ConfigV2, &BTreeMap<CredentialKind, CredentialId>) -> Result<(), ConfigError>,
    {
        let initial_plan = {
            let _lock = self.exclusive_lock()?;
            if let Some(permit) = auth_permit.as_deref() {
                self.ensure_owned_auth_operation_intent_locked(permit)?;
            }
            let source = self.load_latest_credential_transaction_source()?;
            ensure_credential_profile_anchor_matches(
                anchor,
                &credential_profile_anchor_repository_binding(self.paths.root())?,
                &source.config,
                &byte_digest(&source.source_primary_bytes),
            )?;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle,
            };
            self.plan_credential_transaction(
                source,
                Some(&write),
                None,
                |config, credential_ids| apply(config, credential_ids),
            )?
        };
        self.preflight_credential_transaction_plan(Some(bundle), &initial_plan, credential_store)?;
        let prepared_credential_ids = initial_plan.credential_ids;

        let (expected_revision, plan) = {
            let _lock = self.exclusive_lock()?;
            if let Some(permit) = auth_permit.as_deref() {
                self.ensure_owned_auth_operation_intent_locked(permit)?;
            }
            let source = self.load_latest_credential_transaction_source()?;
            ensure_credential_profile_anchor_matches(
                anchor,
                &credential_profile_anchor_repository_binding(self.paths.root())?,
                &source.config,
                &byte_digest(&source.source_primary_bytes),
            )?;
            let expected_revision = source.config.revision;
            let write = CredentialWriteSpec {
                connection_id: &anchor.connection_id,
                profile_name: &anchor.profile_name,
                bundle,
            };
            let plan = self.plan_credential_transaction(
                source,
                Some(&write),
                Some(&prepared_credential_ids),
                |config, credential_ids| apply(config, credential_ids),
            )?;
            if let Some(permit) = auth_permit.as_deref_mut() {
                self.install_auth_rotation_candidate_locked(permit, &plan)?;
            }
            self.install_credential_transaction_intent_locked(expected_revision, &plan)?;
            (expected_revision, plan)
        };
        debug_assert_eq!(
            expected_revision.checked_add(1),
            Some(plan.candidate_config.revision)
        );
        let outcome = self.execute_installed_credential_transaction_plan(
            expected_revision,
            Some(bundle),
            plan,
            credential_store,
        )?;
        if let Some(permit) = auth_permit {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            self.accept_owned_auth_rotation_locked(permit)?;
        }
        Ok(outcome)
    }
}
