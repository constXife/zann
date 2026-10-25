use super::*;

pub(super) fn resolve_credential_profile_anchor_from_config(
    repository_binding_digest: String,
    source_digest: String,
    config: &ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
) -> Result<CredentialProfileAnchor, ConfigError> {
    let connection =
        config
            .connections
            .get(connection_id)
            .ok_or_else(|| ConfigError::MissingConnection {
                connection_id: connection_id.clone(),
            })?;
    let profile = connection
        .credential_profiles
        .get(profile_name)
        .ok_or_else(|| ConfigError::MissingCredentialProfile {
            connection_id: connection_id.clone(),
            profile_name: profile_name.to_string(),
        })?;
    let normalized_address = normalize_address(
        &connection.metadata.address,
        &format!("$.connections.{connection_id}.metadata.address"),
    )?;
    Ok(CredentialProfileAnchor {
        repository_binding_digest,
        source_revision: config.revision,
        source_digest,
        connection_id: connection_id.clone(),
        profile_name: profile_name.to_string(),
        normalized_address,
        server_id: connection.metadata.server_id.clone(),
        server_fingerprint: connection.metadata.server_fingerprint.clone(),
        storage_id: connection.metadata.storage_id.clone(),
        expected_master_key_fp: connection.metadata.expected_master_key_fp.clone(),
        master_key_binding_observed: true,
        account_subject: profile.account_subject.clone(),
        auth_method: profile.auth_method,
        access_expires_at: profile.access_expires_at.clone(),
        credentials: profile.credentials.clone(),
    })
}

pub(super) fn resolve_password_login_anchor_from_config(
    repository_binding_digest: String,
    source_digest: String,
    config: &ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
    client_id: &ClientId,
) -> Result<PasswordLoginAnchor, ConfigError> {
    let connection =
        config
            .connections
            .get(connection_id)
            .ok_or_else(|| ConfigError::MissingConnection {
                connection_id: connection_id.clone(),
            })?;
    let normalized_address = normalize_address(
        &connection.metadata.address,
        &format!("$.connections.{connection_id}.metadata.address"),
    )?;
    let server_id =
        connection
            .metadata
            .server_id
            .clone()
            .ok_or_else(|| ConfigError::InvalidConfig {
                path: format!("$.connections.{connection_id}.metadata.server_id"),
                reason: "password login requires an already pinned server id".to_string(),
            })?;
    let server_fingerprint = connection
        .metadata
        .server_fingerprint
        .clone()
        .ok_or_else(|| ConfigError::InvalidConfig {
            path: format!("$.connections.{connection_id}.metadata.server_fingerprint"),
            reason: "password login requires an already pinned server fingerprint".to_string(),
        })?;
    let client = config.clients.get(client_id);
    Ok(PasswordLoginAnchor {
        repository_binding_digest,
        source_revision: config.revision,
        source_digest,
        connection_id: connection_id.clone(),
        profile_name: profile_name.to_string(),
        normalized_address,
        server_id,
        server_fingerprint,
        storage_id: connection.metadata.storage_id.clone(),
        profile: connection.credential_profiles.get(profile_name).cloned(),
        active_profile: connection.active_credential.clone(),
        client_id: client_id.clone(),
        client_present: client.is_some(),
        client_active_connection: client.and_then(|client| client.active_connection.clone()),
        identity: config.identity.clone(),
    })
}

pub(super) fn ensure_password_login_anchor_matches(
    anchor: &PasswordLoginAnchor,
    expected_repository_binding: &str,
    config: &ConfigV2,
    source_digest: &str,
) -> Result<(), ConfigError> {
    let conflict = |field: &'static str| ConfigError::AuthOperationIntentConflict {
        path: PathBuf::from(AUTH_OPERATION_INTENT_FILENAME),
        reason: format!("password-login source field {field} changed"),
    };
    if anchor.repository_binding_digest != expected_repository_binding {
        return Err(ConfigError::AuthOperationIntentRepositoryMismatch);
    }
    if config.revision < anchor.source_revision {
        return Err(ConfigError::RevisionConflict {
            expected: anchor.source_revision,
            actual: config.revision,
        });
    }
    if config.revision == anchor.source_revision && source_digest != anchor.source_digest {
        return Err(ConfigError::ConfigContentConflict {
            revision: anchor.source_revision,
        });
    }
    let connection = config
        .connections
        .get(&anchor.connection_id)
        .ok_or_else(|| conflict("connection"))?;
    let normalized_address = normalize_address(
        &connection.metadata.address,
        &format!("$.connections.{}.metadata.address", anchor.connection_id),
    )?;
    if normalized_address != anchor.normalized_address {
        return Err(conflict("address"));
    }
    if connection.metadata.server_id.as_deref() != Some(anchor.server_id.as_str()) {
        return Err(conflict("server_id"));
    }
    if connection.metadata.server_fingerprint.as_deref() != Some(anchor.server_fingerprint.as_str())
    {
        return Err(conflict("server_fingerprint"));
    }
    if connection.metadata.storage_id != anchor.storage_id {
        return Err(conflict("storage_id"));
    }
    if connection.credential_profiles.get(&anchor.profile_name) != anchor.profile.as_ref() {
        return Err(conflict("profile"));
    }
    if connection.active_credential != anchor.active_profile {
        return Err(conflict("active_profile"));
    }
    let client = config.clients.get(&anchor.client_id);
    if client.is_some() != anchor.client_present
        || client.and_then(|client| client.active_connection.as_ref())
            != anchor.client_active_connection.as_ref()
    {
        return Err(conflict("client_active_connection"));
    }
    if config.identity != anchor.identity {
        return Err(conflict("identity"));
    }
    Ok(())
}

pub(super) fn auth_intent_source_anchor(intent: &AuthOperationIntent) -> CredentialProfileAnchor {
    CredentialProfileAnchor {
        repository_binding_digest: intent.repository_binding_digest.clone(),
        source_revision: intent.source.revision,
        source_digest: intent.source.raw_digest.clone(),
        connection_id: intent.connection_id.clone(),
        profile_name: intent.profile_name.clone(),
        normalized_address: intent.endpoint.address.clone(),
        server_id: Some(intent.endpoint.server_id.clone()),
        server_fingerprint: Some(intent.endpoint.server_fingerprint.clone()),
        storage_id: intent.endpoint.storage_id.clone(),
        // Auth intent v1/v2 deliberately does not carry this local
        // cache binding. Reconstructed auth anchors are never accepted by the
        // master-key binder; that method requires a freshly resolved anchor.
        expected_master_key_fp: None,
        master_key_binding_observed: false,
        account_subject: intent.source.account_subject.clone(),
        auth_method: intent.source.auth_method,
        access_expires_at: intent.source.access_expires_at.clone(),
        credentials: intent.source.credentials.clone(),
    }
}

pub(super) fn credential_profile_anchor_conflict(
    anchor: &CredentialProfileAnchor,
    field: &'static str,
) -> ConfigError {
    ConfigError::CredentialProfileAnchorConflict {
        connection_id: anchor.connection_id.clone(),
        profile_name: anchor.profile_name.clone(),
        field,
    }
}

pub(super) fn ensure_credential_profile_anchor_matches(
    anchor: &CredentialProfileAnchor,
    repository_binding_digest: &str,
    config: &ConfigV2,
    source_digest: &str,
) -> Result<(), ConfigError> {
    if anchor.repository_binding_digest != repository_binding_digest {
        return Err(ConfigError::CredentialProfileAnchorRepositoryMismatch);
    }
    if config.revision < anchor.source_revision {
        return Err(ConfigError::RevisionConflict {
            expected: anchor.source_revision,
            actual: config.revision,
        });
    }
    if config.revision == anchor.source_revision && source_digest != anchor.source_digest {
        return Err(ConfigError::ConfigContentConflict {
            revision: anchor.source_revision,
        });
    }
    let connection = config
        .connections
        .get(&anchor.connection_id)
        .ok_or_else(|| credential_profile_anchor_conflict(anchor, "connection"))?;
    let normalized_address = normalize_address(
        &connection.metadata.address,
        &format!("$.connections.{}.metadata.address", anchor.connection_id),
    )?;
    if normalized_address != anchor.normalized_address {
        return Err(credential_profile_anchor_conflict(anchor, "address"));
    }
    if connection.metadata.server_id != anchor.server_id {
        return Err(credential_profile_anchor_conflict(anchor, "server_id"));
    }
    if connection.metadata.server_fingerprint != anchor.server_fingerprint {
        return Err(credential_profile_anchor_conflict(
            anchor,
            "server_fingerprint",
        ));
    }
    if connection.metadata.storage_id != anchor.storage_id {
        return Err(credential_profile_anchor_conflict(anchor, "storage_id"));
    }
    let profile = connection
        .credential_profiles
        .get(&anchor.profile_name)
        .ok_or_else(|| credential_profile_anchor_conflict(anchor, "profile"))?;
    if profile.credentials != anchor.credentials {
        return Err(credential_profile_anchor_conflict(anchor, "credentials"));
    }
    if profile.account_subject != anchor.account_subject {
        return Err(credential_profile_anchor_conflict(
            anchor,
            "account_subject",
        ));
    }
    if profile.auth_method != anchor.auth_method {
        return Err(credential_profile_anchor_conflict(anchor, "auth_method"));
    }
    if profile.access_expires_at != anchor.access_expires_at {
        return Err(credential_profile_anchor_conflict(
            anchor,
            "access_expires_at",
        ));
    }
    Ok(())
}

pub(super) fn apply_credential_bundle_replacement(
    config: &mut ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
    access_expires_at: Option<String>,
    credential_ids: &BTreeMap<CredentialKind, CredentialId>,
    activation: CredentialActivation,
) -> Result<(), ConfigError> {
    let connection = config.connections.get_mut(connection_id).ok_or_else(|| {
        ConfigError::MissingConnection {
            connection_id: connection_id.clone(),
        }
    })?;
    connection.credential_profiles.insert(
        profile_name.to_string(),
        CredentialProfile {
            account_subject: None,
            auth_method: None,
            access_expires_at,
            credentials: credential_ids.clone(),
        },
    );
    if activation == CredentialActivation::MakeActive {
        connection.active_credential = Some(profile_name.to_string());
    }
    Ok(())
}

pub(super) fn apply_session_credential_rotation(
    config: &mut ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
    access_expires_at: String,
    credential_ids: &BTreeMap<CredentialKind, CredentialId>,
) -> Result<(), ConfigError> {
    if credential_ids.len() != 2
        || !credential_ids.contains_key(&CredentialKind::Access)
        || !credential_ids.contains_key(&CredentialKind::Refresh)
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.session_refresh".to_string(),
            reason: "session rotation must allocate exactly access and refresh credentials"
                .to_string(),
        });
    }
    let connection = config.connections.get_mut(connection_id).ok_or_else(|| {
        ConfigError::MissingConnection {
            connection_id: connection_id.clone(),
        }
    })?;
    let profile = connection
        .credential_profiles
        .get_mut(profile_name)
        .ok_or_else(|| ConfigError::MissingCredentialProfile {
            connection_id: connection_id.clone(),
            profile_name: profile_name.to_string(),
        })?;
    for (kind, credential_id) in credential_ids {
        profile.credentials.insert(*kind, credential_id.clone());
    }
    profile.access_expires_at = Some(access_expires_at);
    Ok(())
}

pub(super) fn apply_password_login_candidate(
    config: &mut ConfigV2,
    anchor: &PasswordLoginAnchor,
    identity: &ConfigIdentity,
    account_subject: &str,
    access_expires_at: &str,
    credential_ids: &BTreeMap<CredentialKind, CredentialId>,
) -> Result<(), ConfigError> {
    if credential_ids.len() != 2
        || !credential_ids.contains_key(&CredentialKind::Access)
        || !credential_ids.contains_key(&CredentialKind::Refresh)
    {
        return Err(ConfigError::InvalidConfig {
            path: "$.password_login.credentials".to_string(),
            reason: "password login must allocate exactly access and refresh credentials"
                .to_string(),
        });
    }
    validate_required_metadata("$.password_login.account_subject", account_subject)?;
    validate_required_metadata("$.password_login.access_expires_at", access_expires_at)?;
    apply_identity_commit(config, &IdentityCommit::InitializeOrMatch(identity.clone()))?;
    let connection = config
        .connections
        .get_mut(&anchor.connection_id)
        .ok_or_else(|| ConfigError::MissingConnection {
            connection_id: anchor.connection_id.clone(),
        })?;
    let mut credentials = anchor
        .profile
        .as_ref()
        .map(|profile| profile.credentials.clone())
        .unwrap_or_default();
    credentials.insert(
        CredentialKind::Access,
        credential_ids[&CredentialKind::Access].clone(),
    );
    credentials.insert(
        CredentialKind::Refresh,
        credential_ids[&CredentialKind::Refresh].clone(),
    );
    connection.credential_profiles.insert(
        anchor.profile_name.clone(),
        CredentialProfile {
            account_subject: Some(account_subject.to_string()),
            auth_method: Some(AuthMethod::Password),
            access_expires_at: Some(access_expires_at.to_string()),
            credentials,
        },
    );
    connection.active_credential = Some(anchor.profile_name.clone());
    client_entry(config, &anchor.client_id).active_connection = Some(anchor.connection_id.clone());
    Ok(())
}

pub(super) fn apply_credential_profile_removal(
    config: &mut ConfigV2,
    connection_id: &ConnectionId,
    profile_name: &str,
    active_after: &ActiveCredentialAfterRemoval,
) -> Result<(), ConfigError> {
    let connection = config.connections.get_mut(connection_id).ok_or_else(|| {
        ConfigError::MissingConnection {
            connection_id: connection_id.clone(),
        }
    })?;
    if !connection.credential_profiles.contains_key(profile_name) {
        return Err(ConfigError::MissingCredentialProfile {
            connection_id: connection_id.clone(),
            profile_name: profile_name.to_string(),
        });
    }
    match active_after {
        ActiveCredentialAfterRemoval::RequireInactive => {
            if connection.active_credential.as_deref() == Some(profile_name) {
                return Err(ConfigError::ActiveCredentialRemoval {
                    connection_id: connection_id.clone(),
                    profile_name: profile_name.to_string(),
                });
            }
        }
        ActiveCredentialAfterRemoval::Clear => {
            // A profile selection is intentionally not part of the refresh
            // anchor. If the user selected a different profile while a
            // refresh was in flight, revoking the stale target must preserve
            // that newer selection.
            if connection.active_credential.as_deref() == Some(profile_name) {
                connection.active_credential = None;
            }
        }
        ActiveCredentialAfterRemoval::Activate(fallback) => {
            if fallback == profile_name || !connection.credential_profiles.contains_key(fallback) {
                return Err(ConfigError::MissingFallbackCredentialProfile {
                    connection_id: connection_id.clone(),
                    profile_name: fallback.clone(),
                });
            }
            connection.active_credential = Some(fallback.clone());
        }
    }
    connection.credential_profiles.remove(profile_name);
    Ok(())
}
