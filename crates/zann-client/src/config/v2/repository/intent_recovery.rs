use super::super::*;

impl ConfigRepository {
    pub(in crate::config::v2) fn install_password_login_candidate_locked(
        &self,
        permit: &mut PasswordLoginIntentPermit,
        plan: &CredentialTransactionPlan,
        account_subject: &str,
    ) -> Result<(), ConfigError> {
        let (mut intent, _) = self.ensure_owned_password_login_intent_locked(permit)?;
        if intent.state != AuthOperationIntentState::Armed
            || intent.candidate_rotation.is_some()
            || intent.candidate_login.is_some()
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login intent already has a candidate".to_string(),
            });
        }
        if plan.journal.source_primary.revision != intent.source.revision
            || plan.journal.source_primary.raw_digest != intent.source.raw_digest
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login candidate source differs from the armed source".to_string(),
            });
        }
        let profile = plan
            .candidate_config
            .connections
            .get(&intent.connection_id)
            .and_then(|connection| connection.credential_profiles.get(&intent.profile_name))
            .ok_or_else(|| ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login candidate has no target profile".to_string(),
            })?;
        let reservation = intent.reserved_login.as_ref().ok_or_else(|| {
            ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login candidate has no credential reservation".to_string(),
            }
        })?;
        if profile.account_subject.as_deref() != Some(account_subject)
            || profile.auth_method != Some(AuthMethod::Password)
            || profile.credentials.get(&CredentialKind::Access)
                != Some(&reservation.access_credential_id)
            || profile.credentials.get(&CredentialKind::Refresh)
                != Some(&reservation.refresh_credential_id)
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login candidate binding or credential topology is inconsistent"
                    .to_string(),
            });
        }
        let access_expires_at = profile.access_expires_at.clone().ok_or_else(|| {
            ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "password-login candidate has no access expiry".to_string(),
            }
        })?;
        intent.state = AuthOperationIntentState::CandidatePrepared;
        intent.candidate_login = Some(AuthIntentLoginCandidate {
            revision: plan.candidate_config.revision,
            raw_digest: byte_digest(&plan.candidate_bytes),
            account_subject: account_subject.to_string(),
            auth_method: AuthMethod::Password,
            access_expires_at,
            access_credential_id: reservation.access_credential_id.clone(),
            refresh_credential_id: reservation.refresh_credential_id.clone(),
        });
        let candidate = intent.candidate_login.clone();
        let bytes = serialize_auth_operation_intent(&intent, self.paths.root())?;
        atomic_write(&self.paths.auth_operation_intent(), &bytes)?;
        permit.journal_bytes_digest = byte_digest(&bytes);
        permit.candidate = candidate;
        Ok(())
    }

    pub(in crate::config::v2) fn accept_owned_password_login_locked(
        &self,
        permit: &PasswordLoginIntentPermit,
    ) -> Result<(), ConfigError> {
        let (intent, bytes) = self.ensure_owned_password_login_intent_locked(permit)?;
        if intent.state != AuthOperationIntentState::CandidatePrepared
            || !matches!(
                self.classify_auth_operation_intent_locked(&intent)?,
                AuthIntentState::Candidate
            )
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "owned password login is not the exact durable candidate".to_string(),
            });
        }
        self.remove_auth_operation_intent_locked(&bytes)
    }

    pub(in crate::config::v2) fn install_auth_rotation_candidate_locked(
        &self,
        permit: &mut AuthOperationIntentPermit,
        plan: &CredentialTransactionPlan,
    ) -> Result<(), ConfigError> {
        let (mut intent, _source_intent_bytes) =
            self.ensure_owned_auth_operation_intent_locked(permit)?;
        if intent.state != AuthOperationIntentState::Armed || intent.candidate_rotation.is_some() {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "authentication intent already has a rotation candidate".to_string(),
            });
        }
        if plan.journal.source_primary.revision != intent.source.revision
            || plan.journal.source_primary.raw_digest != intent.source.raw_digest
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "credential transaction source does not match the armed auth intent"
                    .to_string(),
            });
        }
        let profile = plan
            .candidate_config
            .connections
            .get(&intent.connection_id)
            .and_then(|connection| connection.credential_profiles.get(&intent.profile_name))
            .ok_or_else(|| ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "rotation candidate does not contain the intended profile".to_string(),
            })?;
        let access_credential_id = plan
            .credential_ids
            .get(&CredentialKind::Access)
            .cloned()
            .ok_or_else(|| ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "rotation candidate has no new access credential id".to_string(),
            })?;
        let refresh_credential_id = plan
            .credential_ids
            .get(&CredentialKind::Refresh)
            .cloned()
            .ok_or_else(|| ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "rotation candidate has no new refresh credential id".to_string(),
            })?;
        if profile.credentials.get(&CredentialKind::Access) != Some(&access_credential_id)
            || profile.credentials.get(&CredentialKind::Refresh) != Some(&refresh_credential_id)
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "rotation candidate credential topology is inconsistent".to_string(),
            });
        }
        let access_expires_at = profile.access_expires_at.clone().ok_or_else(|| {
            ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "rotation candidate has no access expiry".to_string(),
            }
        })?;
        intent.state = AuthOperationIntentState::CandidatePrepared;
        intent.candidate_rotation = Some(AuthIntentRotationCandidate {
            revision: plan.candidate_config.revision,
            raw_digest: byte_digest(&plan.candidate_bytes),
            access_expires_at,
            access_credential_id,
            refresh_credential_id,
        });
        let bytes = serialize_auth_operation_intent(&intent, self.paths.root())?;
        atomic_write(&self.paths.auth_operation_intent(), &bytes)?;
        permit.journal_bytes_digest = byte_digest(&bytes);
        Ok(())
    }

    pub(in crate::config::v2) fn accept_owned_auth_rotation_locked(
        &self,
        permit: &AuthOperationIntentPermit,
    ) -> Result<(), ConfigError> {
        let (intent, bytes) = self.ensure_owned_auth_operation_intent_locked(permit)?;
        if intent.state != AuthOperationIntentState::CandidatePrepared
            || !matches!(
                self.classify_auth_operation_intent_locked(&intent)?,
                AuthIntentState::Candidate
            )
        {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "owned rotation is not the exact durable candidate".to_string(),
            });
        }
        self.remove_auth_operation_intent_locked(&bytes)
    }

    pub(in crate::config::v2) fn classify_auth_operation_intent_locked(
        &self,
        intent: &AuthOperationIntent,
    ) -> Result<AuthIntentState, ConfigError> {
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Err(ConfigError::AuthOperationIntentConflict {
                path: self.paths.auth_operation_intent(),
                reason: "primary config is missing".to_string(),
            });
        }
        let primary_bytes = read_file(&primary_path, "read config for auth recovery")?;
        let config = parse_config(&primary_path, &primary_bytes)?;
        self.ensure_legacy_unchanged(&config)?;
        let digest = byte_digest(&primary_bytes);
        if config.revision == intent.source.revision && digest == intent.source.raw_digest {
            if intent.operation == AuthOperationKind::PasswordLogin {
                return Ok(AuthIntentState::LoginSource);
            }
            let anchor = auth_intent_source_anchor(intent);
            ensure_credential_profile_anchor_matches(
                &anchor,
                &credential_profile_anchor_repository_binding(self.paths.root())?,
                &config,
                &digest,
            )?;
            return Ok(AuthIntentState::Source(Box::new(anchor)));
        }
        let Some(connection) = config.connections.get(&intent.connection_id) else {
            return Ok(AuthIntentState::TargetRemoved);
        };
        let Some(profile) = connection.credential_profiles.get(&intent.profile_name) else {
            return Ok(AuthIntentState::TargetRemoved);
        };

        if let Some(candidate) = &intent.candidate_login {
            if config.revision == candidate.revision && digest == candidate.raw_digest {
                let normalized_address = normalize_address(
                    &connection.metadata.address,
                    &format!("$.connections.{}.metadata.address", intent.connection_id),
                )?;
                let endpoint_matches = normalized_address == intent.endpoint.address
                    && connection.metadata.server_id.as_deref()
                        == Some(intent.endpoint.server_id.as_str())
                    && connection.metadata.server_fingerprint.as_deref()
                        == Some(intent.endpoint.server_fingerprint.as_str())
                    && connection.metadata.storage_id == intent.endpoint.storage_id;
                let mut expected_credentials = intent.source.credentials.clone();
                expected_credentials.insert(
                    CredentialKind::Access,
                    candidate.access_credential_id.clone(),
                );
                expected_credentials.insert(
                    CredentialKind::Refresh,
                    candidate.refresh_credential_id.clone(),
                );
                let activation_matches = connection.active_credential.as_deref()
                    == Some(intent.profile_name.as_str())
                    && intent.client_id.as_ref().is_some_and(|client_id| {
                        config
                            .clients
                            .get(client_id)
                            .and_then(|client| client.active_connection.as_ref())
                            == Some(&intent.connection_id)
                    });
                if endpoint_matches
                    && activation_matches
                    && profile.credentials == expected_credentials
                    && profile.account_subject.as_deref()
                        == Some(candidate.account_subject.as_str())
                    && profile.auth_method == Some(candidate.auth_method)
                    && profile.access_expires_at.as_deref()
                        == Some(candidate.access_expires_at.as_str())
                {
                    return Ok(AuthIntentState::Candidate);
                }
            }
        }

        if let Some(candidate) = &intent.candidate_rotation {
            if config.revision == candidate.revision && digest == candidate.raw_digest {
                let normalized_address = normalize_address(
                    &connection.metadata.address,
                    &format!("$.connections.{}.metadata.address", intent.connection_id),
                )?;
                let endpoint_matches = normalized_address == intent.endpoint.address
                    && connection.metadata.server_id.as_deref()
                        == Some(intent.endpoint.server_id.as_str())
                    && connection.metadata.server_fingerprint.as_deref()
                        == Some(intent.endpoint.server_fingerprint.as_str())
                    && connection.metadata.storage_id == intent.endpoint.storage_id;
                let mut expected_credentials = intent.source.credentials.clone();
                expected_credentials.insert(
                    CredentialKind::Access,
                    candidate.access_credential_id.clone(),
                );
                expected_credentials.insert(
                    CredentialKind::Refresh,
                    candidate.refresh_credential_id.clone(),
                );
                if endpoint_matches
                    && profile.credentials == expected_credentials
                    && profile.access_expires_at.as_deref()
                        == Some(candidate.access_expires_at.as_str())
                {
                    return Ok(AuthIntentState::Candidate);
                }
            }
        }

        Err(ConfigError::AuthOperationIntentConflict {
            path: self.paths.auth_operation_intent(),
            reason: "primary config is neither the exact source, exact rotation candidate, nor a removed target"
                .to_string(),
        })
    }

    pub(in crate::config::v2) fn remove_auth_operation_intent_locked(
        &self,
        expected_bytes: &[u8],
    ) -> Result<(), ConfigError> {
        let path = self.paths.auth_operation_intent();
        let current = read_file(&path, "read authentication intent before removal")?;
        if current != expected_bytes {
            return Err(ConfigError::AuthOperationIntentConflict {
                path,
                reason: "authentication intent changed before durable removal".to_string(),
            });
        }
        fs::remove_file(&path).map_err(|source| ConfigError::Io {
            operation: "remove authentication operation intent",
            path: path.clone(),
            source,
        })?;
        sync_parent(self.paths.root())
    }

    pub(in crate::config::v2) fn remove_credential_transaction_journal_locked(
        &self,
    ) -> Result<(), ConfigError> {
        let path = self.paths.credential_transaction_journal();
        if !validate_regular_file_if_exists(&path)? {
            return Ok(());
        }
        fs::remove_file(&path).map_err(|source| ConfigError::Io {
            operation: "remove completed credential transaction journal",
            path,
            source,
        })?;
        sync_parent(self.paths.root())
    }
}
