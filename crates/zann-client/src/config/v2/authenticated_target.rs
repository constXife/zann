use super::*;

pub(super) fn changed_binding_field(
    previous: &ConnectionMetadata,
    next: &ConnectionMetadata,
) -> Option<&'static str> {
    if previous.address != next.address {
        Some("address")
    } else if previous.server_id != next.server_id {
        Some("server_id")
    } else if previous.server_fingerprint != next.server_fingerprint {
        Some("server_fingerprint")
    } else if previous.expected_master_key_fp != next.expected_master_key_fp {
        Some("expected_master_key_fp")
    } else if previous.storage_id != next.storage_id {
        Some("storage_id")
    } else {
        None
    }
}

pub(super) fn validate_master_key_fingerprint(target: &str) -> Result<(), ConfigError> {
    if target.len() == 12
        && target
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ConfigError::InvalidMasterKeyFingerprint)
    }
}

#[allow(dead_code)]
pub(super) fn apply_identity_commit(
    config: &mut ConfigV2,
    commit: &IdentityCommit,
) -> Result<(), ConfigError> {
    match commit {
        IdentityCommit::InitializeOrMatch(observed) => match config.identity.as_mut() {
            None => config.identity = Some(observed.clone()),
            Some(stored) => {
                if stored.kdf_salt != observed.kdf_salt || stored.kdf_params != observed.kdf_params
                {
                    return Err(ConfigError::AuthenticatedIdentityConflict {
                        reason: "KDF identity does not match the stored identity".to_string(),
                    });
                }
                enrich_identity_field(
                    "salt_fingerprint",
                    &mut stored.salt_fingerprint,
                    &observed.salt_fingerprint,
                )?;
                enrich_identity_field(
                    "first_seen_at",
                    &mut stored.first_seen_at,
                    &observed.first_seen_at,
                )?;
                enrich_identity_field("email", &mut stored.email, &observed.email)?;
            }
        },
        IdentityCommit::ReplaceExact {
            expected,
            replacement,
        } => {
            let stored = config.identity.as_ref().ok_or_else(|| {
                ConfigError::AuthenticatedIdentityConflict {
                    reason: "cannot replace a missing identity".to_string(),
                }
            })?;
            if stored != expected {
                return Err(ConfigError::AuthenticatedIdentityConflict {
                    reason: "stored identity does not match the expected replacement source"
                        .to_string(),
                });
            }
            config.identity = Some(replacement.clone());
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) fn enrich_identity_field(
    field: &'static str,
    stored: &mut Option<String>,
    observed: &Option<String>,
) -> Result<(), ConfigError> {
    match (stored.as_ref(), observed.as_ref()) {
        (Some(stored), Some(observed)) if stored != observed => {
            Err(ConfigError::AuthenticatedIdentityConflict {
                reason: format!("identity field {field} does not match"),
            })
        }
        (None, Some(observed)) => {
            *stored = Some(observed.clone());
            Ok(())
        }
        _ => Ok(()),
    }
}

#[allow(dead_code)]
pub(super) fn apply_authenticated_connection_target(
    config: &mut ConfigV2,
    resolved_connection_id: &ConnectionId,
    target: &AuthenticatedConnectionTarget,
    endpoint: &VerifiedEndpointBinding,
    storage_id: Option<&str>,
) -> Result<(), ConfigError> {
    match target {
        AuthenticatedConnectionTarget::ReplaceFingerprint { expected, .. } => {
            ensure_authenticated_known_host_fingerprint(
                config,
                resolved_connection_id,
                endpoint.address(),
                expected.server_fingerprint(),
            )?;
        }
        _ => ensure_authenticated_known_host_fingerprint(
            config,
            resolved_connection_id,
            endpoint.address(),
            Some(endpoint.server_fingerprint()),
        )?,
    }
    match target {
        AuthenticatedConnectionTarget::Create { connection_name } => {
            ensure_authenticated_endpoint_unique(config, None, endpoint)?;
            if let Some(storage_id) = storage_id {
                ensure_storage_unique(config, None, storage_id)?;
            }
            if config.connections.contains_key(resolved_connection_id) {
                return Err(ConfigError::AuthenticatedEndpointAlias {
                    connection_id: resolved_connection_id.clone(),
                    field: "connection_id",
                });
            }
            let mut metadata = ConnectionMetadata::new(connection_name, endpoint.address());
            metadata.server_id = Some(endpoint.server_id().to_string());
            metadata.server_fingerprint = Some(endpoint.server_fingerprint().to_string());
            metadata.storage_id = storage_id.map(str::to_string);
            config.connections.insert(
                resolved_connection_id.clone(),
                ConnectionConfig::from_metadata(metadata),
            );
            consume_authenticated_known_hosts(config, endpoint.address())?;
            return Ok(());
        }
        AuthenticatedConnectionTarget::UseExisting {
            connection_id,
            expected,
        }
        | AuthenticatedConnectionTarget::PinExisting {
            connection_id,
            expected,
        }
        | AuthenticatedConnectionTarget::ReplaceFingerprint {
            connection_id,
            expected,
        }
        | AuthenticatedConnectionTarget::RelocateEndpoint {
            connection_id,
            expected,
        } => {
            if connection_id != resolved_connection_id {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "resolved connection id changed during planning".to_string(),
                });
            }
            let connection = config.connections.get(connection_id).ok_or_else(|| {
                ConfigError::MissingConnection {
                    connection_id: connection_id.clone(),
                }
            })?;
            if StoredConnectionBinding::from_metadata(&connection.metadata) != *expected {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: connection_id.clone(),
                    reason: "stored binding does not match the expected binding".to_string(),
                });
            }
        }
    }

    ensure_authenticated_endpoint_unique(config, Some(resolved_connection_id), endpoint)?;
    if let Some(storage_id) = storage_id {
        ensure_storage_unique(config, Some(resolved_connection_id), storage_id)?;
    }
    let connection = config
        .connections
        .get_mut(resolved_connection_id)
        .ok_or_else(|| ConfigError::MissingConnection {
            connection_id: resolved_connection_id.clone(),
        })?;
    let metadata = &mut connection.metadata;
    let stored_address = normalize_address(
        &metadata.address,
        &format!("$.connections.{resolved_connection_id}.metadata.address"),
    )?;

    match target {
        AuthenticatedConnectionTarget::Create { .. } => unreachable!("create returned above"),
        AuthenticatedConnectionTarget::UseExisting { .. } => {
            require_authenticated_address(resolved_connection_id, &stored_address, endpoint)?;
            require_authenticated_server_id(resolved_connection_id, metadata, endpoint)?;
            if metadata.server_fingerprint.as_deref() != Some(endpoint.server_fingerprint()) {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "verified fingerprint does not exactly match the stored fingerprint"
                        .to_string(),
                });
            }
        }
        AuthenticatedConnectionTarget::PinExisting { .. } => {
            require_authenticated_address(resolved_connection_id, &stored_address, endpoint)?;
            if let Some(server_id) = metadata.server_id.as_deref() {
                if server_id != endpoint.server_id() {
                    return Err(ConfigError::AuthenticatedBindingConflict {
                        connection_id: resolved_connection_id.clone(),
                        reason: "pinning cannot replace server_id".to_string(),
                    });
                }
            } else {
                metadata.server_id = Some(endpoint.server_id().to_string());
            }
            if metadata.server_fingerprint.is_some() {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "pinning requires a missing stored fingerprint".to_string(),
                });
            }
            metadata.server_fingerprint = Some(endpoint.server_fingerprint().to_string());
        }
        AuthenticatedConnectionTarget::ReplaceFingerprint { .. } => {
            require_authenticated_address(resolved_connection_id, &stored_address, endpoint)?;
            require_authenticated_server_id(resolved_connection_id, metadata, endpoint)?;
            if metadata.server_fingerprint.is_none() {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "fingerprint replacement requires an existing fingerprint".to_string(),
                });
            }
            metadata.server_fingerprint = Some(endpoint.server_fingerprint().to_string());
        }
        AuthenticatedConnectionTarget::RelocateEndpoint { .. } => {
            require_authenticated_server_id(resolved_connection_id, metadata, endpoint)?;
            if stored_address == endpoint.address() {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "endpoint relocation requires a different canonical address"
                        .to_string(),
                });
            }
            metadata.address = endpoint.address().to_string();
            metadata.server_fingerprint = Some(endpoint.server_fingerprint().to_string());
        }
    }

    if let Some(storage_id) = storage_id {
        match metadata.storage_id.as_deref() {
            None => metadata.storage_id = Some(storage_id.to_string()),
            Some(stored) if stored == storage_id => {}
            Some(_) => {
                return Err(ConfigError::AuthenticatedBindingConflict {
                    connection_id: resolved_connection_id.clone(),
                    reason: "authenticated storage id does not match the stored binding"
                        .to_string(),
                });
            }
        }
    }
    consume_authenticated_known_hosts(config, endpoint.address())?;
    Ok(())
}

#[allow(dead_code)]
pub(super) fn require_authenticated_address(
    connection_id: &ConnectionId,
    stored_address: &str,
    endpoint: &VerifiedEndpointBinding,
) -> Result<(), ConfigError> {
    if stored_address != endpoint.address() {
        return Err(ConfigError::AuthenticatedBindingConflict {
            connection_id: connection_id.clone(),
            reason: "verified endpoint address does not match the stored address".to_string(),
        });
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) fn require_authenticated_server_id(
    connection_id: &ConnectionId,
    metadata: &ConnectionMetadata,
    endpoint: &VerifiedEndpointBinding,
) -> Result<(), ConfigError> {
    if metadata.server_id.as_deref() != Some(endpoint.server_id()) {
        return Err(ConfigError::AuthenticatedBindingConflict {
            connection_id: connection_id.clone(),
            reason: "verified server_id does not exactly match the stored server_id".to_string(),
        });
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) fn ensure_authenticated_endpoint_unique(
    config: &ConfigV2,
    except: Option<&ConnectionId>,
    endpoint: &VerifiedEndpointBinding,
) -> Result<(), ConfigError> {
    for (connection_id, connection) in &config.connections {
        if except == Some(connection_id) {
            continue;
        }
        let normalized = normalize_address(
            &connection.metadata.address,
            &format!("$.connections.{connection_id}.metadata.address"),
        )?;
        if normalized == endpoint.address() {
            return Err(ConfigError::AuthenticatedEndpointAlias {
                connection_id: connection_id.clone(),
                field: "address",
            });
        }
        if connection.metadata.server_id.as_deref() == Some(endpoint.server_id()) {
            return Err(ConfigError::AuthenticatedEndpointAlias {
                connection_id: connection_id.clone(),
                field: "server_id",
            });
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) fn ensure_storage_unique(
    config: &ConfigV2,
    except: Option<&ConnectionId>,
    storage_id: &str,
) -> Result<(), ConfigError> {
    for (connection_id, connection) in &config.connections {
        if except != Some(connection_id)
            && connection.metadata.storage_id.as_deref() == Some(storage_id)
        {
            return Err(ConfigError::StorageBindingConflict {
                storage_id: storage_id.to_string(),
                connection_id: connection_id.clone(),
            });
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) fn ensure_authenticated_known_host_fingerprint(
    config: &ConfigV2,
    connection_id: &ConnectionId,
    endpoint_address: &str,
    expected_fingerprint: Option<&str>,
) -> Result<(), ConfigError> {
    for (address, fingerprint) in &config.legacy_known_hosts {
        let normalized = normalize_address(address, &format!("$.legacy_known_hosts.{address}"))?;
        if normalized == endpoint_address && Some(fingerprint.as_str()) != expected_fingerprint {
            return Err(ConfigError::AuthenticatedBindingConflict {
                connection_id: connection_id.clone(),
                reason: "authenticated trust CAS conflicts with the retained known-host pin"
                    .to_string(),
            });
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) fn consume_authenticated_known_hosts(
    config: &mut ConfigV2,
    endpoint_address: &str,
) -> Result<(), ConfigError> {
    let matching: Vec<_> = config
        .legacy_known_hosts
        .keys()
        .map(|address| {
            normalize_address(address, &format!("$.legacy_known_hosts.{address}"))
                .map(|normalized| (address.clone(), normalized))
        })
        .collect::<Result<_, _>>()?;
    for (address, normalized) in matching {
        if normalized == endpoint_address {
            config.legacy_known_hosts.remove(&address);
        }
    }
    Ok(())
}
