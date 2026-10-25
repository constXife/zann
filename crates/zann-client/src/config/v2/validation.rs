use super::*;

pub(super) fn validate_config(config: &ConfigV2) -> Result<(), ConfigError> {
    if config.schema_version != CONFIG_SCHEMA_VERSION {
        return Err(ConfigError::InvalidConfig {
            path: "$.schema_version".to_string(),
            reason: format!(
                "expected schema {}, found {}",
                CONFIG_SCHEMA_VERSION, config.schema_version
            ),
        });
    }
    if let Some(identity) = &config.identity {
        validate_kdf_params(&identity.kdf_params, "$.identity.kdf_params")?;
        validate_string_len(
            "$.identity.kdf_salt",
            &identity.kdf_salt,
            MAX_METADATA_VALUE_LEN,
        )?;
        for (field, value, maximum) in [
            (
                "salt_fingerprint",
                identity.salt_fingerprint.as_deref(),
                MAX_METADATA_VALUE_LEN,
            ),
            (
                "first_seen_at",
                identity.first_seen_at.as_deref(),
                MAX_LEGACY_NAME_LEN,
            ),
            ("email", identity.email.as_deref(), 320),
        ] {
            if let Some(value) = value {
                validate_string_len(&format!("$.identity.{field}"), value, maximum)?;
            }
        }
    }
    validate_count("$.connections", config.connections.len(), MAX_CONNECTIONS)?;
    validate_count("$.clients", config.clients.len(), MAX_CLIENTS)?;
    validate_count(
        "$.legacy_known_hosts",
        config.legacy_known_hosts.len(),
        MAX_KNOWN_HOSTS,
    )?;
    if let Some(migration) = &config.migration {
        validate_count(
            "$.migration.claimed_clients",
            migration.claimed_clients.len(),
            MAX_CLIENTS,
        )?;
        validate_count(
            "$.migration.deferred_legacy_fields",
            migration.deferred_legacy_fields.len(),
            MAX_DEFERRED_FIELDS,
        )?;
        validate_string_len(
            "$.migration.source_format",
            &migration.source_format,
            MAX_LEGACY_NAME_LEN,
        )?;
        validate_string_len(
            "$.migration.source_digest",
            &migration.source_digest,
            MAX_LEGACY_NAME_LEN,
        )?;
        for path in &migration.deferred_legacy_fields {
            validate_string_len(
                "$.migration.deferred_legacy_fields.*",
                path,
                MAX_DEFERRED_PATH_LEN,
            )?;
        }
    }
    for (address, fingerprint) in &config.legacy_known_hosts {
        validate_string_len("$.legacy_known_hosts.<address>", address, MAX_ADDRESS_LEN)?;
        validate_string_len(
            "$.legacy_known_hosts.<fingerprint>",
            fingerprint,
            MAX_METADATA_VALUE_LEN,
        )?;
    }
    let mut known_hosts_by_address: BTreeMap<String, (&str, &str)> = BTreeMap::new();
    for (address, fingerprint) in &config.legacy_known_hosts {
        let normalized = normalize_address(address, &format!("$.legacy_known_hosts.{address}"))?;
        if let Some((previous_address, previous_fingerprint)) =
            known_hosts_by_address.insert(normalized.clone(), (address, fingerprint))
        {
            if previous_fingerprint != fingerprint {
                return Err(ConfigError::InvalidConfig {
                    path: format!("$.legacy_known_hosts.{address}"),
                    reason: format!(
                        "normalized address {normalized} conflicts with {previous_address}"
                    ),
                });
            }
        }
    }

    let mut trust_by_address: BTreeMap<String, (Option<String>, Option<String>, ConnectionId)> =
        BTreeMap::new();
    for (connection_id, connection) in &config.connections {
        let metadata = &connection.metadata;
        let normalized = normalize_address(
            &metadata.address,
            &format!("$.connections.{connection_id}.metadata.address"),
        )?;
        if let Some((server_id, fingerprint, previous_id)) = trust_by_address.get(&normalized) {
            if server_id.as_deref() != metadata.server_id.as_deref() {
                return Err(ConfigError::InvalidConfig {
                    path: format!("$.connections.{connection_id}.metadata.server_id"),
                    reason: format!(
                        "must match connection {previous_id} for normalized address {normalized}"
                    ),
                });
            }
            if fingerprint.as_deref() != metadata.server_fingerprint.as_deref() {
                return Err(ConfigError::InvalidConfig {
                    path: format!("$.connections.{connection_id}.metadata.server_fingerprint"),
                    reason: format!(
                        "must match connection {previous_id} for normalized address {normalized}"
                    ),
                });
            }
        } else {
            trust_by_address.insert(
                normalized.clone(),
                (
                    metadata.server_id.clone(),
                    metadata.server_fingerprint.clone(),
                    connection_id.clone(),
                ),
            );
        }
        if let Some((known_address, known_fingerprint)) = known_hosts_by_address.get(&normalized) {
            if metadata.server_fingerprint.as_deref() != Some(*known_fingerprint) {
                return Err(ConfigError::InvalidConfig {
                    path: format!("$.connections.{connection_id}.metadata.server_fingerprint"),
                    reason: format!(
                        "must match retained known-host fingerprint for {known_address}"
                    ),
                });
            }
        }
    }
    for (client_id, client) in &config.clients {
        let path = format!("$.clients.{client_id}");
        let namespace_matches = matches!(
            (client_id.as_str(), &client.namespace),
            ("cli", ClientNamespace::CliV1(_)) | ("desktop", ClientNamespace::DesktopV1(_))
        ) || (client_id.as_str() != "cli"
            && client_id.as_str() != "desktop"
            && matches!(&client.namespace, ClientNamespace::Empty));
        if !namespace_matches {
            return Err(ConfigError::InvalidConfig {
                path: format!("{path}.namespace"),
                reason: format!("namespace variant does not match client {client_id}"),
            });
        }
        if let ClientNamespace::CliV1(namespace) = &client.namespace {
            for connection_id in namespace.default_vault_by_connection.keys() {
                if !config.connections.contains_key(connection_id) {
                    return Err(ConfigError::InvalidConfig {
                        path: format!(
                            "{path}.namespace.settings.default_vault_by_connection.{connection_id}"
                        ),
                        reason: "default vault references a missing connection".to_string(),
                    });
                }
            }
            for (connection_id, vault) in &namespace.default_vault_by_connection {
                validate_string_len(
                    &format!(
                        "{path}.namespace.settings.default_vault_by_connection.{connection_id}"
                    ),
                    vault,
                    MAX_LEGACY_NAME_LEN,
                )?;
            }
        }
        if let ClientNamespace::DesktopV1(namespace) = &client.namespace {
            if let Some(backup) = &namespace.backup {
                if let Some(backup_dir) = &backup.backup_dir {
                    validate_string_len(
                        &format!("{path}.namespace.settings.backup.backup_dir"),
                        backup_dir,
                        MAX_ADDRESS_LEN,
                    )?;
                }
            }
        }
        if let Some(connection_id) = &client.active_connection {
            if !config.connections.contains_key(connection_id) {
                return Err(ConfigError::InvalidConfig {
                    path: format!("{path}.active_connection"),
                    reason: format!("connection does not exist: {connection_id}"),
                });
            }
        }
    }
    let mut credential_locations: BTreeMap<CredentialId, String> = BTreeMap::new();
    let mut storage_locations: BTreeMap<String, ConnectionId> = BTreeMap::new();
    let mut profile_count = 0usize;
    let mut credential_slot_count = 0usize;
    for (connection_id, connection) in &config.connections {
        let path = format!("$.connections.{connection_id}");
        validate_string_len(
            &format!("{path}.metadata.name"),
            &connection.metadata.name,
            MAX_LEGACY_NAME_LEN,
        )?;
        validate_string_len(
            &format!("{path}.metadata.address"),
            &connection.metadata.address,
            MAX_ADDRESS_LEN,
        )?;
        for (field, value) in [
            ("server_id", connection.metadata.server_id.as_deref()),
            (
                "server_fingerprint",
                connection.metadata.server_fingerprint.as_deref(),
            ),
            (
                "expected_master_key_fp",
                connection.metadata.expected_master_key_fp.as_deref(),
            ),
            ("storage_id", connection.metadata.storage_id.as_deref()),
        ] {
            if let Some(value) = value {
                validate_string_len(
                    &format!("{path}.metadata.{field}"),
                    value,
                    MAX_METADATA_VALUE_LEN,
                )?;
            }
        }
        if let Some(storage_id) = &connection.metadata.storage_id {
            if let Some(previous) =
                storage_locations.insert(storage_id.clone(), connection_id.clone())
            {
                return Err(ConfigError::InvalidConfig {
                    path: format!("{path}.metadata.storage_id"),
                    reason: format!(
                        "storage id {storage_id} is already bound to connection {previous}"
                    ),
                });
            }
        }
        if let Some(active_credential) = &connection.active_credential {
            validate_string_len(
                &format!("{path}.active_credential"),
                active_credential,
                MAX_LEGACY_NAME_LEN,
            )?;
            if !connection
                .credential_profiles
                .contains_key(active_credential)
            {
                return Err(ConfigError::InvalidConfig {
                    path: format!("{path}.active_credential"),
                    reason: format!("credential profile does not exist: {active_credential}"),
                });
            }
        }
        for (profile_name, profile) in &connection.credential_profiles {
            profile_count =
                profile_count
                    .checked_add(1)
                    .ok_or_else(|| ConfigError::InvalidConfig {
                        path: "$.connections".to_string(),
                        reason: "credential profile count overflow".to_string(),
                    })?;
            validate_count(
                "$.connections.*.credential_profiles",
                profile_count,
                MAX_PROFILES_TOTAL,
            )?;
            let profile_path = format!("{path}.credential_profiles.{profile_name}");
            if profile_name.is_empty() {
                return Err(ConfigError::InvalidConfig {
                    path: profile_path,
                    reason: "credential profile name must not be empty".to_string(),
                });
            }
            if profile.credentials.is_empty() {
                return Err(ConfigError::InvalidConfig {
                    path: profile_path,
                    reason: "credential profile must reference at least one credential".to_string(),
                });
            }
            validate_string_len(&profile_path, profile_name, MAX_LEGACY_NAME_LEN)?;
            match (&profile.account_subject, profile.auth_method) {
                (None, None) => {}
                (Some(subject), Some(_)) => {
                    validate_canonical_account_subject(
                        &format!("{profile_path}.account_subject"),
                        subject,
                    )?;
                }
                _ => {
                    return Err(ConfigError::InvalidConfig {
                        path: profile_path,
                        reason:
                            "account_subject and auth_method must be both absent or both present"
                                .to_string(),
                    });
                }
            }
            if let Some(expires_at) = &profile.access_expires_at {
                validate_string_len(
                    &format!("{profile_path}.access_expires_at"),
                    expires_at,
                    MAX_LEGACY_NAME_LEN,
                )?;
            }
            for (kind, credential_id) in &profile.credentials {
                credential_slot_count = credential_slot_count.checked_add(1).ok_or_else(|| {
                    ConfigError::InvalidConfig {
                        path: "$.connections".to_string(),
                        reason: "credential slot count overflow".to_string(),
                    }
                })?;
                validate_count(
                    "$.connections.*.credential_profiles.*.credentials",
                    credential_slot_count,
                    MAX_CREDENTIAL_SLOTS,
                )?;
                let location = format!("{profile_path}.credentials.{kind:?}");
                if credential_id.lifecycle_nonce_and_tag().is_none() {
                    config
                        .migration
                        .as_ref()
                        .ok_or_else(|| ConfigError::InvalidConfig {
                            path: location.clone(),
                            reason: "legacy credential references require a migration stamp"
                                .to_string(),
                        })?;
                }
                if let Some(previous) =
                    credential_locations.insert(credential_id.clone(), location.clone())
                {
                    return Err(ConfigError::InvalidConfig {
                        path: location,
                        reason: format!(
                            "credential id {credential_id} is already referenced at {previous}"
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}
