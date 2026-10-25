use super::super::*;

impl ConfigRepository {
    /// Resolves the existing pinned target for a password-login flow.
    ///
    /// The connection must already exist and be fully pinned. The named
    /// credential profile may be present or absent; this API never creates,
    /// pins, relocates or rebinds a connection.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn resolve_password_login_anchor(
        &self,
        connection_id: &ConnectionId,
        profile_name: impl Into<String>,
        client_id: &ClientId,
    ) -> Result<PasswordLoginAnchor, ConfigError> {
        let profile_name = profile_name.into();
        validate_string_len(
            "$.connections.*.credential_profiles.<name>",
            &profile_name,
            MAX_LEGACY_NAME_LEN,
        )?;
        if profile_name.is_empty() {
            return Err(ConfigError::InvalidConfig {
                path: "$.password_login.profile_name".to_string(),
                reason: "password-login profile name must not be empty".to_string(),
            });
        }
        let _lock = self.exclusive_lock()?;
        self.ensure_no_pending_auth_operation_locked()?;
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "read config for password-login anchor")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        resolve_password_login_anchor_from_config(
            credential_profile_anchor_repository_binding(self.paths.root())?,
            byte_digest(&primary_bytes),
            &config,
            connection_id,
            &profile_name,
            client_id,
        )
    }

    /// Reserves a fresh credential pair and durably arms exactly one password
    /// login dispatch. The caller holds auth then credential operation locks.
    /// No credential-store call occurs while the config lock is held.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn prepare_password_login_intent_with_operation_locks(
        &self,
        anchor: &PasswordLoginAnchor,
        endpoint: &VerifiedEndpointBinding,
        identity: ConfigIdentity,
        operation_id: &str,
        credential_store: &dyn CredentialStore,
    ) -> Result<PasswordLoginIntentPermit, ConfigError> {
        validate_string_len("$.authentication_intent.operation_id", operation_id, 128)?;
        if operation_id.is_empty() {
            return Err(ConfigError::InvalidConfig {
                path: "$.authentication_intent.operation_id".to_string(),
                reason: "authentication operation id must not be empty".to_string(),
            });
        }
        if endpoint.address() != anchor.normalized_address
            || endpoint.server_id() != anchor.server_id
            || endpoint.server_fingerprint() != anchor.server_fingerprint
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "verified endpoint does not match the pinned login target".to_string(),
            });
        }

        let reservation = AuthIntentLoginReservation {
            access_credential_id: CredentialId::fresh(
                self.paths.root(),
                &anchor.connection_id,
                &anchor.profile_name,
                CredentialKind::Access,
            )?,
            refresh_credential_id: CredentialId::fresh(
                self.paths.root(),
                &anchor.connection_id,
                &anchor.profile_name,
                CredentialKind::Refresh,
            )?,
        };
        let reserved_ids = BTreeMap::from([
            (
                CredentialKind::Access,
                reservation.access_credential_id.clone(),
            ),
            (
                CredentialKind::Refresh,
                reservation.refresh_credential_id.clone(),
            ),
        ]);
        preflight_credential_slots(credential_store, &reserved_ids)?;

        let _lock = self.exclusive_lock()?;
        let path = self.paths.auth_operation_intent();
        if validate_regular_file_if_exists(&path)? {
            return Err(ConfigError::AuthOperationRecoveryRequired { path });
        }
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "rebase password-login source")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let repository_binding = credential_profile_anchor_repository_binding(self.paths.root())?;
        ensure_password_login_anchor_matches(
            anchor,
            &repository_binding,
            &config,
            &byte_digest(&primary_bytes),
        )?;
        let source_anchor = resolve_password_login_anchor_from_config(
            repository_binding.clone(),
            byte_digest(&primary_bytes),
            &config,
            &anchor.connection_id,
            &anchor.profile_name,
            &anchor.client_id,
        )?;
        let mut identity_candidate = config.clone();
        apply_identity_commit(
            &mut identity_candidate,
            &IdentityCommit::InitializeOrMatch(identity.clone()),
        )?;
        let source_profile = source_anchor.profile.as_ref();
        let intent = AuthOperationIntent {
            journal_version: AUTH_OPERATION_INTENT_VERSION,
            operation_id: operation_id.to_string(),
            operation: AuthOperationKind::PasswordLogin,
            state: AuthOperationIntentState::Armed,
            repository_binding_digest: repository_binding,
            connection_id: source_anchor.connection_id.clone(),
            profile_name: source_anchor.profile_name.clone(),
            endpoint: AuthIntentEndpoint {
                address: source_anchor.normalized_address.clone(),
                server_id: source_anchor.server_id.clone(),
                server_fingerprint: source_anchor.server_fingerprint.clone(),
                storage_id: source_anchor.storage_id.clone(),
            },
            source: AuthIntentSource {
                revision: source_anchor.source_revision,
                raw_digest: source_anchor.source_digest.clone(),
                account_subject: source_profile.and_then(|profile| profile.account_subject.clone()),
                auth_method: source_profile.and_then(|profile| profile.auth_method),
                access_expires_at: source_profile
                    .and_then(|profile| profile.access_expires_at.clone()),
                credentials: source_profile
                    .map(|profile| profile.credentials.clone())
                    .unwrap_or_default(),
                profile_present: Some(source_profile.is_some()),
                client_present: Some(source_anchor.client_present),
                active_profile: source_anchor.active_profile.clone(),
                client_active_connection: source_anchor.client_active_connection.clone(),
            },
            candidate_rotation: None,
            client_id: Some(source_anchor.client_id.clone()),
            reserved_login: Some(reservation.clone()),
            candidate_login: None,
        };
        let bytes = serialize_auth_operation_intent(&intent, self.paths.root())?;
        atomic_write(&path, &bytes)?;
        Ok(PasswordLoginIntentPermit {
            anchor: source_anchor,
            identity,
            reservation,
            operation_id: operation_id.to_string(),
            journal_bytes_digest: byte_digest(&bytes),
            candidate: None,
        })
    }

    /// Durably records that a refresh or logout may be dispatched next.
    ///
    /// The caller must already hold the repository's authentication and
    /// credential operation locks, in that order. The returned anchor is the
    /// exact source generation captured by the durable intent and must replace
    /// any older, equivalent anchor held by the caller.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn prepare_auth_operation_intent_with_operation_locks(
        &self,
        anchor: &CredentialProfileAnchor,
        operation: AuthOperationKind,
        operation_id: &str,
    ) -> Result<AuthOperationIntentPermit, ConfigError> {
        validate_string_len("$.authentication_intent.operation_id", operation_id, 128)?;
        if operation_id.is_empty() {
            return Err(ConfigError::InvalidConfig {
                path: "$.authentication_intent.operation_id".to_string(),
                reason: "authentication operation id must not be empty".to_string(),
            });
        }
        let _lock = self.exclusive_lock()?;
        let path = self.paths.auth_operation_intent();
        if validate_regular_file_if_exists(&path)? {
            return Err(ConfigError::AuthOperationRecoveryRequired { path });
        }
        let primary_path = self.paths.config();
        let primary_bytes = read_file(&primary_path, "read config for authentication intent")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let source_digest = byte_digest(&primary_bytes);
        ensure_credential_profile_anchor_matches(
            anchor,
            &credential_profile_anchor_repository_binding(self.paths.root())?,
            &config,
            &source_digest,
        )?;
        let source_anchor = resolve_credential_profile_anchor_from_config(
            credential_profile_anchor_repository_binding(self.paths.root())?,
            source_digest.clone(),
            &config,
            &anchor.connection_id,
            &anchor.profile_name,
        )?;
        let server_id =
            source_anchor
                .server_id
                .clone()
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: "$.authentication_intent.endpoint.server_id".to_string(),
                    reason: "authenticated operation requires a pinned server id".to_string(),
                })?;
        let server_fingerprint =
            source_anchor
                .server_fingerprint
                .clone()
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: "$.authentication_intent.endpoint.server_fingerprint".to_string(),
                    reason: "authenticated operation requires a pinned server fingerprint"
                        .to_string(),
                })?;
        if operation == AuthOperationKind::Refresh
            && !source_anchor
                .credentials
                .contains_key(&CredentialKind::Refresh)
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.authentication_intent.source.credentials.refresh".to_string(),
                reason: "refresh operation requires a refresh credential".to_string(),
            });
        }
        let intent = AuthOperationIntent {
            journal_version: AUTH_OPERATION_INTENT_V1,
            operation_id: operation_id.to_string(),
            operation,
            state: AuthOperationIntentState::Armed,
            repository_binding_digest: source_anchor.repository_binding_digest.clone(),
            connection_id: source_anchor.connection_id.clone(),
            profile_name: source_anchor.profile_name.clone(),
            endpoint: AuthIntentEndpoint {
                address: source_anchor.normalized_address.clone(),
                server_id,
                server_fingerprint,
                storage_id: source_anchor.storage_id.clone(),
            },
            source: AuthIntentSource {
                revision: source_anchor.source_revision,
                raw_digest: source_digest,
                account_subject: source_anchor.account_subject.clone(),
                auth_method: source_anchor.auth_method,
                access_expires_at: source_anchor.access_expires_at.clone(),
                credentials: source_anchor.credentials.clone(),
                profile_present: None,
                client_present: None,
                active_profile: None,
                client_active_connection: None,
            },
            candidate_rotation: None,
            client_id: None,
            reserved_login: None,
            candidate_login: None,
        };
        let bytes = serialize_auth_operation_intent(&intent, self.paths.root())?;
        atomic_write(&path, &bytes)?;
        Ok(AuthOperationIntentPermit {
            // The auth-intent wire format intentionally predates the
            // local master-key binding. Normalize the in-process permit to the
            // exact anchor that can be reconstructed from that durable wire
            // document; the master-key binder only accepts freshly resolved
            // public anchors and performs its own exact field check.
            anchor: auth_intent_source_anchor(&intent),
            operation_id: operation_id.to_string(),
            operation,
            journal_bytes_digest: byte_digest(&bytes),
        })
    }

    /// Reconciles a possibly interrupted auth operation while the caller holds
    /// authentication then credential operation locks.
    ///
    /// Credential-journal recovery always runs first. An exact committed
    /// rotation is preserved, an already-removed target is accepted, and an
    /// exact source is revoked through the normal journaled credential path.
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    pub(crate) fn reconcile_auth_operation_with_operation_locks(
        &self,
        credential_store: &dyn CredentialStore,
    ) -> Result<
        (
            CredentialTransactionOutcome,
            AuthOperationRecoveryDisposition,
        ),
        ConfigError,
    > {
        // Validate and repository-bind the auth intent before credential
        // recovery is allowed to touch the store. Malformed, future or copied
        // intents therefore fail closed with zero credential-port calls.
        let preflight_intent_bytes = {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            self.pending_auth_operation_intent_locked()?
                .map(|(_, bytes)| bytes)
        };
        let mut reconciled = self.reconcile_credentials_with_operation_lock(credential_store)?;
        let classification = {
            let _lock = self.exclusive_lock_allow_credential_journal()?;
            let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
                if preflight_intent_bytes.is_some() {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason: "authentication intent disappeared during credential recovery"
                            .to_string(),
                    });
                }
                return Ok((reconciled, AuthOperationRecoveryDisposition::NoIntent));
            };
            if preflight_intent_bytes.as_deref() != Some(bytes.as_slice()) {
                return Err(ConfigError::AuthOperationIntentConflict {
                    path: self.paths.auth_operation_intent(),
                    reason: "authentication intent changed during credential recovery".to_string(),
                });
            }
            self.classify_auth_operation_intent_locked(&intent)?
        };

        match classification {
            AuthIntentState::Source(anchor) => {
                let permit = {
                    let _lock = self.exclusive_lock_allow_credential_journal()?;
                    let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
                        return Ok((reconciled, AuthOperationRecoveryDisposition::NoIntent));
                    };
                    if !matches!(
                        self.classify_auth_operation_intent_locked(&intent)?,
                        AuthIntentState::Source(current) if current == anchor
                    ) {
                        return Err(ConfigError::AuthOperationIntentConflict {
                            path: self.paths.auth_operation_intent(),
                            reason: "authentication source changed during recovery".to_string(),
                        });
                    }
                    AuthOperationIntentPermit {
                        anchor: (*anchor).clone(),
                        operation_id: intent.operation_id,
                        operation: intent.operation,
                        journal_bytes_digest: byte_digest(&bytes),
                    }
                };
                let mut revoked = self
                    .remove_credential_profile_after_auth_intent_with_operation_locks(
                        &permit,
                        ActiveCredentialAfterRemoval::Clear,
                        credential_store,
                    )?;
                let mut warnings = std::mem::take(&mut reconciled.warnings);
                warnings.append(&mut revoked.warnings);
                revoked.warnings = warnings;
                Ok((revoked, AuthOperationRecoveryDisposition::SourceRevoked))
            }
            AuthIntentState::LoginSource => {
                let _lock = self.exclusive_lock_allow_credential_journal()?;
                let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason: "password-login intent disappeared before abandonment".to_string(),
                    });
                };
                if !matches!(
                    self.classify_auth_operation_intent_locked(&intent)?,
                    AuthIntentState::LoginSource
                ) {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason: "password-login source changed during abandonment".to_string(),
                    });
                }
                self.remove_auth_operation_intent_locked(&bytes)?;
                Ok((reconciled, AuthOperationRecoveryDisposition::LoginAbandoned))
            }
            state @ (AuthIntentState::Candidate | AuthIntentState::TargetRemoved) => {
                let disposition = match state {
                    AuthIntentState::Candidate => {
                        AuthOperationRecoveryDisposition::CandidatePreserved
                    }
                    AuthIntentState::TargetRemoved => {
                        AuthOperationRecoveryDisposition::TargetRemoved
                    }
                    AuthIntentState::Source(_) | AuthIntentState::LoginSource => {
                        unreachable!("matched above")
                    }
                };
                let _lock = self.exclusive_lock_allow_credential_journal()?;
                let Some((intent, bytes)) = self.pending_auth_operation_intent_locked()? else {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason: "authentication intent disappeared before durable completion"
                            .to_string(),
                    });
                };
                let current = self.classify_auth_operation_intent_locked(&intent)?;
                if !matches!(
                    current,
                    AuthIntentState::Candidate | AuthIntentState::TargetRemoved
                ) {
                    return Err(ConfigError::AuthOperationIntentConflict {
                        path: self.paths.auth_operation_intent(),
                        reason: "authentication state changed during recovery".to_string(),
                    });
                }
                self.remove_auth_operation_intent_locked(&bytes)?;
                Ok((reconciled, disposition))
            }
        }
    }
}
