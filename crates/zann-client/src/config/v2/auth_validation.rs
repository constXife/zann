use super::*;

pub(super) fn validate_auth_operation_intent(
    intent: &AuthOperationIntent,
    repository_root: &Path,
) -> Result<(), ConfigError> {
    if intent.journal_version != AUTH_OPERATION_INTENT_V1
        && intent.journal_version != AUTH_OPERATION_INTENT_VERSION
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.journal_version".to_string(),
            reason: format!(
                "expected authentication operation intent version {} or {}, found {}",
                AUTH_OPERATION_INTENT_V1, AUTH_OPERATION_INTENT_VERSION, intent.journal_version
            ),
        });
    }
    let expected_repository_binding =
        credential_profile_anchor_repository_binding(repository_root)?;
    if intent.repository_binding_digest != expected_repository_binding {
        return Err(ConfigError::AuthOperationIntentRepositoryMismatch);
    }
    validate_string_len("$.operation_id", &intent.operation_id, 128)?;
    if intent.operation_id.is_empty() {
        return Err(ConfigError::InvalidConfig {
            path: "$.operation_id".to_string(),
            reason: "authentication operation id must not be empty".to_string(),
        });
    }
    validate_string_len("$.profile_name", &intent.profile_name, MAX_LEGACY_NAME_LEN)?;
    let normalized = normalize_address(&intent.endpoint.address, "$.endpoint.address")?;
    if normalized != intent.endpoint.address {
        return Err(ConfigError::InvalidConfig {
            path: "$.endpoint.address".to_string(),
            reason: "authentication intent endpoint must be canonical".to_string(),
        });
    }
    validate_required_metadata("$.endpoint.server_id", &intent.endpoint.server_id)?;
    validate_required_metadata(
        "$.endpoint.server_fingerprint",
        &intent.endpoint.server_fingerprint,
    )?;
    if let Some(storage_id) = &intent.endpoint.storage_id {
        validate_required_metadata("$.endpoint.storage_id", storage_id)?;
    }
    validate_sha256_digest(
        "$.source.raw_digest",
        &intent.source.raw_digest,
        "authentication intent source",
    )?;
    validate_count("$.source.credentials", intent.source.credentials.len(), 3)?;
    let source_ids: BTreeSet<_> = intent.source.credentials.values().collect();
    if source_ids.len() != intent.source.credentials.len() {
        return Err(ConfigError::InvalidConfig {
            path: "$.source.credentials".to_string(),
            reason: "authentication intent credential ids must be unique".to_string(),
        });
    }
    if intent.operation == AuthOperationKind::Refresh
        && !intent
            .source
            .credentials
            .contains_key(&CredentialKind::Refresh)
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.source.credentials.refresh".to_string(),
            reason: "refresh intent requires a refresh credential".to_string(),
        });
    }
    let repository_binding = repository_binding(repository_root)?;
    if intent.journal_version == AUTH_OPERATION_INTENT_V1 {
        if intent.operation == AuthOperationKind::PasswordLogin
            || intent.client_id.is_some()
            || intent.reserved_login.is_some()
            || intent.candidate_login.is_some()
            || intent.source.profile_present.is_some()
            || intent.source.client_present.is_some()
            || intent.source.active_profile.is_some()
            || intent.source.client_active_connection.is_some()
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.operation".to_string(),
                reason: "authentication intent v1 only supports refresh/logout fields".to_string(),
            });
        }
        if intent.source.credentials.is_empty() {
            return Err(ConfigError::InvalidConfig {
                path: "$.source.credentials".to_string(),
                reason: "authentication intent v1 source must contain a credential profile"
                    .to_string(),
            });
        }
        if (intent.state == AuthOperationIntentState::Armed) != intent.candidate_rotation.is_none()
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.state".to_string(),
                reason: "armed refresh/logout intent must not have a candidate and candidate_prepared must have one"
                    .to_string(),
            });
        }
    } else {
        if intent.operation != AuthOperationKind::PasswordLogin
            || intent.candidate_rotation.is_some()
            || intent.client_id.is_none()
            || intent.reserved_login.is_none()
            || intent.source.profile_present.is_none()
            || intent.source.client_present.is_none()
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.operation".to_string(),
                reason: "authentication intent v2 requires the complete password-login shape"
                    .to_string(),
            });
        }
        let profile_present = intent.source.profile_present.unwrap_or(false);
        if profile_present == intent.source.credentials.is_empty() {
            return Err(ConfigError::InvalidConfig {
                path: "$.source.credentials".to_string(),
                reason: "password-login source credentials must match profile presence".to_string(),
            });
        }
        if !profile_present
            && (intent.source.account_subject.is_some()
                || intent.source.auth_method.is_some()
                || intent.source.access_expires_at.is_some())
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.source".to_string(),
                reason: "an absent password-login source profile cannot carry profile fields"
                    .to_string(),
            });
        }
        if intent.source.client_present == Some(false)
            && intent.source.client_active_connection.is_some()
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.source.client_active_connection".to_string(),
                reason: "an absent source client cannot have an active connection".to_string(),
            });
        }
        if let Some(active_profile) = &intent.source.active_profile {
            validate_string_len(
                "$.source.active_profile",
                active_profile,
                MAX_LEGACY_NAME_LEN,
            )?;
        }
        match (&intent.source.account_subject, intent.source.auth_method) {
            (None, None) => {}
            (Some(subject), Some(_)) => {
                validate_canonical_account_subject("$.source.account_subject", subject)?;
            }
            _ => {
                return Err(ConfigError::InvalidConfig {
                    path: "$.source".to_string(),
                    reason: "password-login source account binding must be a complete pair"
                        .to_string(),
                });
            }
        }
        if (intent.state == AuthOperationIntentState::Armed) != intent.candidate_login.is_none() {
            return Err(ConfigError::InvalidConfig {
                path: "$.state".to_string(),
                reason: "armed password-login intent must not have a candidate and candidate_prepared must have one"
                    .to_string(),
            });
        }
    }
    if let Some(candidate) = &intent.candidate_rotation {
        if intent.operation != AuthOperationKind::Refresh {
            return Err(ConfigError::InvalidConfig {
                path: "$.candidate_rotation".to_string(),
                reason: "logout intent cannot contain a rotation candidate".to_string(),
            });
        }
        if intent.source.revision == u64::MAX || candidate.revision != intent.source.revision + 1 {
            return Err(ConfigError::InvalidConfig {
                path: "$.candidate_rotation.revision".to_string(),
                reason: "rotation candidate must advance the source revision exactly once"
                    .to_string(),
            });
        }
        validate_sha256_digest(
            "$.candidate_rotation.raw_digest",
            &candidate.raw_digest,
            "authentication intent rotation candidate",
        )?;
        validate_required_metadata(
            "$.candidate_rotation.access_expires_at",
            &candidate.access_expires_at,
        )?;
        for (path, kind, credential_id) in [
            (
                "$.candidate_rotation.access_credential_id",
                CredentialKind::Access,
                &candidate.access_credential_id,
            ),
            (
                "$.candidate_rotation.refresh_credential_id",
                CredentialKind::Refresh,
                &candidate.refresh_credential_id,
            ),
        ] {
            if !credential_id.is_bound_lifecycle(
                &repository_binding,
                &intent.connection_id,
                &intent.profile_name,
                kind,
            ) {
                return Err(ConfigError::InvalidConfig {
                    path: path.to_string(),
                    reason: "rotation credential id is not bound to this repository slot"
                        .to_string(),
                });
            }
            if intent
                .source
                .credentials
                .values()
                .any(|source| source == credential_id)
            {
                return Err(ConfigError::InvalidConfig {
                    path: path.to_string(),
                    reason: "rotation credential id must be fresh".to_string(),
                });
            }
        }
        if candidate.access_credential_id == candidate.refresh_credential_id {
            return Err(ConfigError::InvalidConfig {
                path: "$.candidate_rotation".to_string(),
                reason: "access and refresh candidates must use distinct credential ids"
                    .to_string(),
            });
        }
    }
    if let Some(reservation) = &intent.reserved_login {
        for (path, kind, credential_id) in [
            (
                "$.reserved_login.access_credential_id",
                CredentialKind::Access,
                &reservation.access_credential_id,
            ),
            (
                "$.reserved_login.refresh_credential_id",
                CredentialKind::Refresh,
                &reservation.refresh_credential_id,
            ),
        ] {
            if !credential_id.is_bound_lifecycle(
                &repository_binding,
                &intent.connection_id,
                &intent.profile_name,
                kind,
            ) {
                return Err(ConfigError::InvalidConfig {
                    path: path.to_string(),
                    reason: "reserved login credential id is not bound to this repository slot"
                        .to_string(),
                });
            }
            if intent
                .source
                .credentials
                .values()
                .any(|source| source == credential_id)
            {
                return Err(ConfigError::InvalidConfig {
                    path: path.to_string(),
                    reason: "reserved login credential id must be fresh".to_string(),
                });
            }
        }
        if reservation.access_credential_id == reservation.refresh_credential_id {
            return Err(ConfigError::InvalidConfig {
                path: "$.reserved_login".to_string(),
                reason: "reserved access and refresh ids must be distinct".to_string(),
            });
        }
    }
    if let Some(candidate) = &intent.candidate_login {
        let reservation =
            intent
                .reserved_login
                .as_ref()
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: "$.candidate_login".to_string(),
                    reason: "password-login candidate requires a reservation".to_string(),
                })?;
        if intent.source.revision == u64::MAX || candidate.revision != intent.source.revision + 1 {
            return Err(ConfigError::InvalidConfig {
                path: "$.candidate_login.revision".to_string(),
                reason: "password-login candidate must advance the source revision exactly once"
                    .to_string(),
            });
        }
        validate_sha256_digest(
            "$.candidate_login.raw_digest",
            &candidate.raw_digest,
            "authentication intent password-login candidate",
        )?;
        validate_required_metadata(
            "$.candidate_login.account_subject",
            &candidate.account_subject,
        )?;
        validate_canonical_account_subject(
            "$.candidate_login.account_subject",
            &candidate.account_subject,
        )?;
        validate_required_metadata(
            "$.candidate_login.access_expires_at",
            &candidate.access_expires_at,
        )?;
        if candidate.auth_method != AuthMethod::Password
            || candidate.access_credential_id != reservation.access_credential_id
            || candidate.refresh_credential_id != reservation.refresh_credential_id
        {
            return Err(ConfigError::InvalidConfig {
                path: "$.candidate_login".to_string(),
                reason: "password-login candidate must use Password and the exact reservation"
                    .to_string(),
            });
        }
    }
    Ok(())
}
