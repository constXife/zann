use super::*;

pub(super) fn migrate_legacy(
    input: &LegacyInput,
    legacy_client: &ClientId,
    credential_store: &dyn CredentialStore,
    legacy_credentials: &dyn LegacyCredentialSource,
    paths: &ClientPaths,
) -> Result<ConfigV2, ConfigError> {
    let (mut legacy, legacy_unknown) = match input.config_bytes.as_deref() {
        Some(bytes) => {
            validate_json_shape(bytes, JSON_NODE_LIMIT).map_err(|source| {
                ConfigError::Malformed {
                    path: paths.legacy_config(),
                    source,
                }
            })?;
            let unknown =
                scan_legacy_unknown_fields(bytes).map_err(|source| ConfigError::Malformed {
                    path: paths.legacy_config(),
                    source,
                })?;
            let legacy = serde_json::from_slice::<LegacyConfig>(bytes).map_err(|source| {
                ConfigError::Malformed {
                    path: paths.legacy_config(),
                    source,
                }
            })?;
            (legacy, unknown)
        }
        None => (LegacyConfig::default(), LegacyUnknownFields::default()),
    };
    let known_hosts = match input.known_hosts_bytes.as_deref() {
        Some(bytes) => {
            validate_json_shape(bytes, JSON_NODE_LIMIT).map_err(|source| {
                ConfigError::Malformed {
                    path: paths.legacy_known_hosts(),
                    source,
                }
            })?;
            serde_json::from_slice::<BTreeMap<String, String>>(bytes).map_err(|source| {
                ConfigError::Malformed {
                    path: paths.legacy_known_hosts(),
                    source,
                }
            })?
        }
        None => BTreeMap::new(),
    };

    if let Some(path) = &legacy_unknown.credential_profile {
        return Err(ConfigError::UnknownLegacyCredentialField { path: path.clone() });
    }
    validate_legacy_references(&legacy)?;
    validate_legacy_budgets(&legacy, &known_hosts, &legacy_unknown.deferred)?;
    validate_legacy_keyring_accounts(&legacy, legacy_credentials)?;
    let normalized_known_hosts = normalize_known_hosts(&known_hosts)?;
    backfill_legacy_bindings(&mut legacy, &normalized_known_hosts)?;
    let credential_repository_binding = repository_binding(paths.root())?;
    let mut config = build_provisional_legacy_config(
        &legacy,
        legacy_client,
        &credential_repository_binding,
        &input.digest,
        &known_hosts,
        &normalized_known_hosts,
        legacy_unknown.deferred,
    )?;
    let provisional_bytes = serialize_config(&config)?;
    drop(provisional_bytes);

    let pending_credentials = resolve_legacy_credentials(
        &mut config,
        &legacy,
        &credential_repository_binding,
        &input.digest,
        legacy_credentials,
    )?;
    validate_config(&config)?;
    let candidate_bytes = serialize_config(&config)?;
    drop(candidate_bytes);
    store_legacy_credentials(credential_store, &pending_credentials)?;
    Ok(config)
}

pub(super) fn validate_legacy_keyring_accounts(
    legacy: &LegacyConfig,
    legacy_credentials: &dyn LegacyCredentialSource,
) -> Result<(), ConfigError> {
    let semantics = legacy_credentials.account_semantics();
    let mut locators = Vec::new();
    for (connection_name, connection) in &legacy.contexts {
        for (profile_name, profile) in &connection.tokens {
            let ambiguous = connection_name.contains("::") || profile_name.contains("::");
            if ambiguous {
                if profile.access_token.is_none()
                    && profile.refresh_token.is_none()
                    && profile.service_account_token.is_none()
                {
                    return Err(ConfigError::AmbiguousLegacyCredentialAccount {
                        locator: LegacyCredentialLocator {
                            connection_name: connection_name.clone(),
                            profile_name: profile_name.clone(),
                            kind: CredentialKind::Access,
                        },
                    });
                }
                continue;
            }
            for (kind, inline) in [
                (CredentialKind::Access, profile.access_token.as_ref()),
                (
                    CredentialKind::ServiceAccount,
                    profile.service_account_token.as_ref(),
                ),
            ] {
                let locator = LegacyCredentialLocator {
                    connection_name: connection_name.clone(),
                    profile_name: profile_name.clone(),
                    kind,
                };
                let account = locator.cli_keyring_account().ok_or_else(|| {
                    ConfigError::AmbiguousLegacyCredentialAccount {
                        locator: locator.clone(),
                    }
                })?;
                let queries_source =
                    semantics == LegacyCredentialAccountSemantics::Exact || inline.is_none();
                locators.push((locator, account, queries_source));
            }
        }
    }

    // A completely inline Windows migration never consults the historical
    // case-insensitive namespace, so aliases there are irrelevant to the v2
    // result. If any lookup is needed, every logical account participates in
    // collision analysis so an inline `Prod` cannot hide an external `prod`.
    if semantics == LegacyCredentialAccountSemantics::WindowsCaseInsensitive
        && !locators.iter().any(|(_, _, queries)| *queries)
    {
        return Ok(());
    }

    let mut accounts = BTreeMap::new();
    for (locator, account, _) in &locators {
        let identity = legacy_account_identity(account, locator, semantics)?;
        if let Some(first) = accounts.insert(identity, locator.clone()) {
            if first != *locator {
                return Err(ConfigError::LegacyCredentialAccountConflict {
                    account: account.clone(),
                    first: Box::new(first),
                    second: Box::new(locator.clone()),
                });
            }
        }
    }

    for (locator, _, queries_source) in locators {
        if queries_source {
            if semantics == LegacyCredentialAccountSemantics::WindowsCaseInsensitive
                && !legacy_credentials.verifies_exact_account_identity()
            {
                return Err(ConfigError::AmbiguousLegacyCredentialAccount { locator });
            }
            legacy_credentials.validate(&locator).map_err(|source| {
                ConfigError::CredentialSource {
                    locator: locator.clone(),
                    source,
                }
            })?;
        }
    }
    Ok(())
}

pub(super) fn legacy_account_identity(
    account: &str,
    locator: &LegacyCredentialLocator,
    semantics: LegacyCredentialAccountSemantics,
) -> Result<String, ConfigError> {
    match semantics {
        LegacyCredentialAccountSemantics::Exact => Ok(account.to_string()),
        LegacyCredentialAccountSemantics::WindowsCaseInsensitive => {
            if !account.is_ascii() {
                return Err(ConfigError::AmbiguousLegacyCredentialAccount {
                    locator: locator.clone(),
                });
            }
            Ok(account.to_ascii_lowercase())
        }
    }
}

pub(super) fn build_provisional_legacy_config(
    legacy: &LegacyConfig,
    legacy_client: &ClientId,
    repository_binding: &[u8],
    source_digest: &str,
    known_hosts: &BTreeMap<String, String>,
    normalized_known_hosts: &BTreeMap<String, (String, String)>,
    deferred_legacy_fields: BTreeSet<String>,
) -> Result<ConfigV2, ConfigError> {
    let mut config = ConfigV2::empty();
    config.identity = legacy.identity.as_ref().map(|identity| ConfigIdentity {
        kdf_salt: identity.kdf_salt.clone(),
        kdf_params: identity.kdf_params.clone(),
        salt_fingerprint: identity.salt_fingerprint.clone(),
        first_seen_at: identity.first_seen_at.clone(),
        email: identity.email.clone(),
    });
    if let Some(storage) = &legacy.storage {
        let desktop_id = ClientId("desktop".to_string());
        let desktop = client_entry(&mut config, &desktop_id);
        if let ClientNamespace::DesktopV1(namespace) = &mut desktop.namespace {
            namespace.backup = Some(DesktopBackupSettings {
                backup_dir: storage.backup_dir.clone(),
                backup_retention_days: storage.backup_retention_days,
                backup_max_count: storage.backup_max_count,
            });
        }
    }
    let mut consumed_known_hosts = BTreeSet::new();
    let mut trust_by_address: BTreeMap<String, String> = BTreeMap::new();
    let mut ids_by_name = BTreeMap::new();
    let mut default_vault_by_connection = BTreeMap::new();

    for (name, legacy_connection) in &legacy.contexts {
        let normalized_address =
            normalize_address(&legacy_connection.addr, &format!("$.contexts.{name}.addr"))?;
        let known_host_fingerprint = normalized_known_hosts.get(&normalized_address);
        if let Some((original, fingerprint)) = known_host_fingerprint {
            consumed_known_hosts.insert(original.clone());
            if let Some(config_fingerprint) = &legacy_connection.server_fingerprint {
                if config_fingerprint != fingerprint {
                    return Err(ConfigError::TrustConflict {
                        address: legacy_connection.addr.clone(),
                        config_fingerprint: config_fingerprint.clone(),
                        known_hosts_fingerprint: fingerprint.clone(),
                    });
                }
            }
        }
        let fingerprint = legacy_connection
            .server_fingerprint
            .clone()
            .or_else(|| known_host_fingerprint.map(|(_, fingerprint)| fingerprint.clone()));
        if let Some(candidate) = &fingerprint {
            if let Some(existing) = trust_by_address.insert(normalized_address, candidate.clone()) {
                if existing != *candidate {
                    return Err(ConfigError::TrustConflict {
                        address: legacy_connection.addr.clone(),
                        config_fingerprint: existing,
                        known_hosts_fingerprint: candidate.clone(),
                    });
                }
            }
        }

        let connection_id = ConnectionId::deterministic(name, &legacy_connection.addr);
        let mut connection = ConnectionConfig {
            metadata: ConnectionMetadata {
                name: name.clone(),
                address: legacy_connection.addr.clone(),
                needs_salt_update: legacy_connection.needs_salt_update,
                server_id: legacy_connection.server_id.clone(),
                server_fingerprint: fingerprint,
                expected_master_key_fp: legacy_connection.expected_master_key_fp.clone(),
                storage_id: legacy_connection.storage_id.clone(),
            },
            credential_profiles: BTreeMap::new(),
            active_credential: legacy_connection.current_token.clone(),
        };
        if let Some(vault) = &legacy_connection.vault {
            default_vault_by_connection.insert(connection_id.clone(), vault.clone());
        }

        for (profile_name, legacy_profile) in &legacy_connection.tokens {
            let mut credentials = BTreeMap::new();
            for kind in [
                CredentialKind::Access,
                CredentialKind::Refresh,
                CredentialKind::ServiceAccount,
            ] {
                credentials.insert(
                    kind,
                    CredentialId::deterministic(
                        repository_binding,
                        source_digest,
                        &connection_id,
                        profile_name,
                        kind,
                    ),
                );
            }
            connection.credential_profiles.insert(
                profile_name.clone(),
                CredentialProfile {
                    account_subject: None,
                    auth_method: None,
                    access_expires_at: legacy_profile.access_expires_at.clone(),
                    credentials,
                },
            );
        }
        ids_by_name.insert(name.clone(), connection_id.clone());
        config.connections.insert(connection_id, connection);
    }

    if let Some(current_context) = &legacy.current_context {
        let active_connection = ids_by_name.get(current_context).cloned().ok_or_else(|| {
            ConfigError::MissingConnection {
                connection_id: ConnectionId::deterministic(current_context, "missing"),
            }
        })?;
        client_entry(&mut config, legacy_client).active_connection = Some(active_connection);
    }
    if !default_vault_by_connection.is_empty() {
        let cli_id = ClientId("cli".to_string());
        let cli = client_entry(&mut config, &cli_id);
        if let ClientNamespace::CliV1(namespace) = &mut cli.namespace {
            namespace.default_vault_by_connection = default_vault_by_connection;
        }
    }

    let unmatched_known_hosts: BTreeMap<_, _> = known_hosts
        .iter()
        .filter(|(address, _)| !consumed_known_hosts.contains(*address))
        .map(|(address, fingerprint)| (address.clone(), fingerprint.clone()))
        .collect();
    if !unmatched_known_hosts.is_empty() {
        config.legacy_known_hosts = unmatched_known_hosts;
    }
    config.migration = Some(MigrationStamp {
        source_format: "legacy-v1".to_string(),
        source_digest: source_digest.to_string(),
        claimed_clients: BTreeSet::from([legacy_client.clone()]),
        deferred_legacy_fields,
    });
    validate_config(&config)?;
    Ok(config)
}
