use super::*;

pub(super) fn validate_repository_credential_ids(
    config: &ConfigV2,
    repository_root: &Path,
) -> Result<(), ConfigError> {
    let repository_binding = repository_binding(repository_root)?;
    for (connection_id, connection) in &config.connections {
        for (profile_name, profile) in &connection.credential_profiles {
            for (kind, credential_id) in &profile.credentials {
                let valid = if credential_id.lifecycle_nonce_and_tag().is_some() {
                    credential_id.is_bound_lifecycle(
                        &repository_binding,
                        connection_id,
                        profile_name,
                        *kind,
                    )
                } else {
                    config.migration.as_ref().is_some_and(|migration| {
                        *credential_id
                            == CredentialId::deterministic(
                                &repository_binding,
                                &migration.source_digest,
                                connection_id,
                                profile_name,
                                *kind,
                            )
                    })
                };
                if !valid {
                    return Err(ConfigError::InvalidConfig {
                        path: format!(
                            "$.connections.{connection_id}.credential_profiles.{profile_name}.credentials.{kind:?}"
                        ),
                        reason: "credential id is not bound to this repository slot".to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_kdf_params(params: &ConfigKdfParams, path: &str) -> Result<(), ConfigError> {
    KdfParams {
        algorithm: params.algorithm.clone(),
        iterations: params.iterations,
        memory_kb: params.memory_kb,
        parallelism: params.parallelism,
    }
    .validate_policy()
    .map_err(|reason| ConfigError::InvalidConfig {
        path: path.to_string(),
        reason: reason.to_string(),
    })
}

pub(super) fn validate_count(path: &str, actual: usize, maximum: usize) -> Result<(), ConfigError> {
    if actual > maximum {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: format!("contains {actual} entries; maximum is {maximum}"),
        });
    }
    Ok(())
}

pub(super) fn validate_string_len(
    path: &str,
    value: &str,
    maximum: usize,
) -> Result<(), ConfigError> {
    if value.is_empty() || value.len() > maximum {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: format!("string length must be between 1 and {maximum} bytes"),
        });
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) fn validate_required_metadata(path: &str, value: &str) -> Result<(), ConfigError> {
    validate_string_len(path, value, MAX_METADATA_VALUE_LEN)
}

pub(super) fn validate_canonical_account_subject(
    path: &str,
    value: &str,
) -> Result<(), ConfigError> {
    validate_required_metadata(path, value)?;
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| ConfigError::InvalidConfig {
        path: path.to_string(),
        reason: "authenticated account subject must be a UUID".to_string(),
    })?;
    if parsed.to_string() != value {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "authenticated account subject must use canonical UUID form".to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_credential_bundle_input(
    path: &str,
    bundle: &CredentialBundle,
) -> Result<(), ConfigError> {
    if bundle.slots().iter().all(|(_, secret)| secret.is_none()) {
        return Err(ConfigError::InvalidConfig {
            path: path.to_string(),
            reason: "credential bundle must contain at least one secret".to_string(),
        });
    }
    if bundle.access.is_none() && bundle.access_expires_at.is_some() {
        return Err(ConfigError::InvalidConfig {
            path: format!("{path}.access_expires_at"),
            reason: "access expiry requires an access credential".to_string(),
        });
    }
    if let Some(expires_at) = &bundle.access_expires_at {
        validate_string_len(
            &format!("{path}.access_expires_at"),
            expires_at,
            MAX_LEGACY_NAME_LEN,
        )?;
    }
    Ok(())
}

pub(super) fn client_config_for(client_id: &ClientId) -> ClientConfig {
    let namespace = match client_id.as_str() {
        "cli" => ClientNamespace::CliV1(CliNamespace::default()),
        "desktop" => ClientNamespace::DesktopV1(DesktopNamespace::default()),
        _ => ClientNamespace::Empty,
    };
    ClientConfig {
        active_connection: None,
        namespace,
    }
}

pub(super) fn client_entry<'a>(
    config: &'a mut ConfigV2,
    client_id: &ClientId,
) -> &'a mut ClientConfig {
    config
        .clients
        .entry(client_id.clone())
        .or_insert_with(|| client_config_for(client_id))
}
