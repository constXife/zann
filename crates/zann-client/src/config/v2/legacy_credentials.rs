use super::*;

pub(super) fn resolve_legacy_credentials(
    config: &mut ConfigV2,
    legacy: &LegacyConfig,
    repository_binding: &[u8],
    source_digest: &str,
    legacy_credentials: &dyn LegacyCredentialSource,
) -> Result<Vec<(CredentialKind, CredentialId, CredentialSecret)>, ConfigError> {
    let mut pending_credentials = Vec::new();
    for (connection_name, legacy_connection) in &legacy.contexts {
        let connection_id = ConnectionId::deterministic(connection_name, &legacy_connection.addr);
        for (profile_name, legacy_profile) in &legacy_connection.tokens {
            let mut credentials = BTreeMap::new();
            for (kind, inline) in [
                (CredentialKind::Access, legacy_profile.access_token.as_ref()),
                (
                    CredentialKind::Refresh,
                    legacy_profile.refresh_token.as_ref(),
                ),
                (
                    CredentialKind::ServiceAccount,
                    legacy_profile.service_account_token.as_ref(),
                ),
            ] {
                if let Some((kind, credential_id, secret)) = resolve_credential(
                    repository_binding,
                    source_digest,
                    &connection_id,
                    LegacyCredentialLocator {
                        connection_name: connection_name.clone(),
                        profile_name: profile_name.clone(),
                        kind,
                    },
                    inline,
                    legacy_credentials,
                )? {
                    credentials.insert(kind, credential_id.clone());
                    pending_credentials.push((kind, credential_id, secret));
                }
            }
            if credentials.is_empty() {
                return Err(ConfigError::MissingCredential {
                    connection_name: connection_name.clone(),
                    profile_name: profile_name.clone(),
                });
            }
            let connection = config.connections.get_mut(&connection_id).ok_or_else(|| {
                ConfigError::MissingConnection {
                    connection_id: connection_id.clone(),
                }
            })?;
            let profile = connection
                .credential_profiles
                .get_mut(profile_name)
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: format!(
                        "$.connections.{connection_id}.credential_profiles.{profile_name}"
                    ),
                    reason: "provisional credential profile is missing".to_string(),
                })?;
            profile.credentials = credentials;
        }
    }
    Ok(pending_credentials)
}

pub(super) fn resolve_credential(
    repository_binding: &[u8],
    source_digest: &str,
    connection_id: &ConnectionId,
    locator: LegacyCredentialLocator,
    inline: Option<&LegacySecret>,
    legacy_credentials: &dyn LegacyCredentialSource,
) -> Result<Option<(CredentialKind, CredentialId, CredentialSecret)>, ConfigError> {
    let kind = locator.kind;
    let unrepresentable_cli_account = locator.cli_keyring_account().is_none();
    let skip_case_insensitive_inline_lookup = inline.is_some()
        && legacy_credentials.account_semantics()
            == LegacyCredentialAccountSemantics::WindowsCaseInsensitive;
    let external = if unrepresentable_cli_account || skip_case_insensitive_inline_lookup {
        None
    } else {
        legacy_credentials
            .get(&locator)
            .map_err(|source| ConfigError::CredentialSource {
                locator: locator.clone(),
                source,
            })?
    };
    let selected =
        match (inline, external) {
            (Some(inline), Some(external)) => {
                if inline.expose_secret() != external.expose_secret() {
                    return Err(ConfigError::CredentialConflict { locator });
                }
                CredentialSecret::new(inline.expose_secret().to_string()).map_err(|source| {
                    ConfigError::InvalidCredentialSecret {
                        locator: locator.clone(),
                        source,
                    }
                })?
            }
            (Some(inline), None) => CredentialSecret::new(inline.expose_secret().to_string())
                .map_err(|source| ConfigError::InvalidCredentialSecret {
                    locator: locator.clone(),
                    source,
                })?,
            (None, Some(external)) => external,
            (None, None) => return Ok(None),
        };
    let credential_id = CredentialId::deterministic(
        repository_binding,
        source_digest,
        connection_id,
        &locator.profile_name,
        kind,
    );
    Ok(Some((kind, credential_id, selected)))
}

pub(super) fn store_legacy_credentials(
    store: &dyn CredentialStore,
    pending: &[(CredentialKind, CredentialId, CredentialSecret)],
) -> Result<(), ConfigError> {
    for (kind, credential_id, secret) in pending {
        store.validate(credential_id, secret).map_err(|source| {
            ConfigError::CredentialValidation {
                kind: *kind,
                source,
            }
        })?;
    }

    let mut missing = BTreeSet::new();
    for (_, credential_id, secret) in pending {
        let existing = store
            .get(credential_id)
            .map_err(|source| ConfigError::CredentialStore {
                operation: "preflight read",
                credential_id: credential_id.clone(),
                source,
            })?;
        match existing {
            Some(existing) if existing.expose_secret() != secret.expose_secret() => {
                return Err(ConfigError::CredentialIdConflict {
                    credential_id: credential_id.clone(),
                });
            }
            Some(_) => {}
            None => {
                missing.insert(credential_id.clone());
            }
        }
    }

    for (_, credential_id, secret) in pending {
        if missing.contains(credential_id) {
            store
                .put(credential_id, secret)
                .map_err(|source| ConfigError::CredentialStore {
                    operation: "write",
                    credential_id: credential_id.clone(),
                    source,
                })?;
        }
    }

    for (_, credential_id, secret) in pending {
        let verified = store
            .get(credential_id)
            .map_err(|source| ConfigError::CredentialStore {
                operation: "verify",
                credential_id: credential_id.clone(),
                source,
            })?;
        if verified
            .as_ref()
            .is_none_or(|stored| stored.expose_secret() != secret.expose_secret())
        {
            return Err(ConfigError::CredentialVerification {
                credential_id: credential_id.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn backfill_legacy_bindings(
    legacy: &mut LegacyConfig,
    known_hosts: &BTreeMap<String, (String, String)>,
) -> Result<(), ConfigError> {
    let mut bindings: BTreeMap<String, (Option<String>, Option<String>, String)> = BTreeMap::new();
    for (name, connection) in &legacy.contexts {
        let path = format!("$.contexts.{name}.addr");
        let normalized = normalize_address(&connection.addr, &path)?;
        let known_fingerprint = known_hosts
            .get(&normalized)
            .map(|(_, fingerprint)| fingerprint);
        if let (Some(config_fingerprint), Some(known_fingerprint)) =
            (&connection.server_fingerprint, known_fingerprint)
        {
            if config_fingerprint != known_fingerprint {
                return Err(ConfigError::TrustConflict {
                    address: connection.addr.clone(),
                    config_fingerprint: config_fingerprint.clone(),
                    known_hosts_fingerprint: known_fingerprint.clone(),
                });
            }
        }
        let candidate_fingerprint = connection
            .server_fingerprint
            .clone()
            .or_else(|| known_fingerprint.cloned());
        match bindings.get_mut(&normalized) {
            Some((server_id, fingerprint, previous_name)) => {
                if let (Some(previous), Some(current)) =
                    (server_id.as_ref(), connection.server_id.as_ref())
                {
                    if previous != current {
                        return Err(ConfigError::InvalidConfig {
                            path: format!("$.contexts.{name}.server_id"),
                            reason: format!(
                                "conflicts with context {previous_name} for endpoint {normalized}"
                            ),
                        });
                    }
                } else if server_id.is_none() {
                    *server_id = connection.server_id.clone();
                }
                if let (Some(previous), Some(current)) =
                    (fingerprint.as_ref(), candidate_fingerprint.as_ref())
                {
                    if previous != current {
                        return Err(ConfigError::TrustConflict {
                            address: connection.addr.clone(),
                            config_fingerprint: previous.clone(),
                            known_hosts_fingerprint: current.clone(),
                        });
                    }
                } else if fingerprint.is_none() {
                    *fingerprint = candidate_fingerprint;
                }
            }
            None => {
                bindings.insert(
                    normalized,
                    (
                        connection.server_id.clone(),
                        candidate_fingerprint,
                        name.clone(),
                    ),
                );
            }
        }
    }
    for (name, connection) in &mut legacy.contexts {
        let normalized = normalize_address(&connection.addr, &format!("$.contexts.{name}.addr"))?;
        let (server_id, fingerprint, _) =
            bindings
                .get(&normalized)
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: format!("$.contexts.{name}"),
                    reason: "missing normalized endpoint binding".to_string(),
                })?;
        connection.server_id = server_id.clone();
        connection.server_fingerprint = fingerprint.clone();
    }
    Ok(())
}

pub(super) fn normalize_known_hosts(
    known_hosts: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, (String, String)>, ConfigError> {
    let mut normalized: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (address, fingerprint) in known_hosts {
        let key = normalize_address(address, &format!("$.known_hosts.{address}"))?;
        if let Some((_, existing)) = normalized.get(&key) {
            if existing != fingerprint {
                return Err(ConfigError::TrustConflict {
                    address: address.clone(),
                    config_fingerprint: existing.clone(),
                    known_hosts_fingerprint: fingerprint.clone(),
                });
            }
        }
        normalized.insert(key, (address.clone(), fingerprint.clone()));
    }
    Ok(normalized)
}
