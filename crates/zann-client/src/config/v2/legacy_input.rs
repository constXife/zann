use super::*;

pub(super) struct LegacyInput {
    pub(super) config_bytes: Option<Zeroizing<Vec<u8>>>,
    pub(super) known_hosts_bytes: Option<Zeroizing<Vec<u8>>>,
    pub(super) digest: String,
}

impl LegacyInput {
    pub(super) fn read(paths: &ClientPaths) -> Result<Self, ConfigError> {
        let config_bytes = read_optional_secret_file(&paths.legacy_config())?;
        let known_hosts_bytes = read_optional_secret_file(&paths.legacy_known_hosts())?;
        let digest = legacy_digest(
            config_bytes.as_ref().map(|bytes| bytes.as_slice()),
            known_hosts_bytes.as_ref().map(|bytes| bytes.as_slice()),
        );
        Ok(Self {
            config_bytes,
            known_hosts_bytes,
            digest,
        })
    }

    pub(super) fn has_sources(&self) -> bool {
        self.config_bytes.is_some() || self.known_hosts_bytes.is_some()
    }

    pub(super) fn active_connection_id(
        &self,
        paths: &ClientPaths,
    ) -> Result<Option<ConnectionId>, ConfigError> {
        let Some(bytes) = self.config_bytes.as_deref() else {
            return Ok(None);
        };
        validate_json_shape(bytes, JSON_NODE_LIMIT).map_err(|source| ConfigError::Malformed {
            path: paths.legacy_config(),
            source,
        })?;
        let claim: LegacyClientClaim =
            serde_json::from_slice(bytes).map_err(|source| ConfigError::Malformed {
                path: paths.legacy_config(),
                source,
            })?;
        let Some(current_context) = claim.current_context else {
            return Ok(None);
        };
        let connection =
            claim
                .contexts
                .get(&current_context)
                .ok_or_else(|| ConfigError::InvalidConfig {
                    path: "$.current_context".to_string(),
                    reason: format!("context does not exist: {current_context}"),
                })?;
        Ok(Some(ConnectionId::deterministic(
            &current_context,
            &connection.addr,
        )))
    }
}

pub(super) fn read_optional_secret_file(
    path: &Path,
) -> Result<Option<Zeroizing<Vec<u8>>>, ConfigError> {
    match read_file(path, "read legacy config") {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(ConfigError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn legacy_digest(config: Option<&[u8]>, known_hosts: Option<&[u8]>) -> String {
    let mut hasher = Sha256::new();
    hash_optional_source(&mut hasher, b"config", config);
    hash_optional_source(&mut hasher, b"known_hosts", known_hosts);
    format!("sha256:{}", HEXLOWER.encode(&hasher.finalize()))
}

pub(super) fn hash_optional_source(hasher: &mut Sha256, label: &[u8], source: Option<&[u8]>) {
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    match source {
        Some(bytes) => {
            hasher.update([1]);
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        None => hasher.update([0]),
    }
}

pub(super) fn validate_legacy_budgets(
    legacy: &LegacyConfig,
    known_hosts: &BTreeMap<String, String>,
    deferred: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    validate_count("$.contexts", legacy.contexts.len(), MAX_CONNECTIONS)?;
    validate_count("$.known_hosts", known_hosts.len(), MAX_KNOWN_HOSTS)?;
    validate_count("$.deferred", deferred.len(), MAX_DEFERRED_FIELDS)?;
    for path in deferred {
        validate_string_len("$.deferred.*", path, MAX_DEFERRED_PATH_LEN)?;
    }
    if let Some(current_context) = &legacy.current_context {
        validate_string_len("$.current_context", current_context, MAX_LEGACY_NAME_LEN)?;
    }
    if let Some(identity) = &legacy.identity {
        validate_string_len(
            "$.identity.kdf_salt",
            &identity.kdf_salt,
            MAX_METADATA_VALUE_LEN,
        )?;
        validate_kdf_params(&identity.kdf_params, "$.identity.kdf_params")?;
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
    if let Some(storage) = &legacy.storage {
        if let Some(backup_dir) = &storage.backup_dir {
            validate_string_len("$.storage.backup_dir", backup_dir, MAX_ADDRESS_LEN)?;
        }
    }

    let mut profile_count = 0usize;
    for (connection_name, connection) in &legacy.contexts {
        let base = legacy_path("$.contexts", connection_name);
        validate_string_len(&base, connection_name, MAX_LEGACY_NAME_LEN)?;
        validate_string_len(&format!("{base}.addr"), &connection.addr, MAX_ADDRESS_LEN)?;
        for (field, value) in [
            ("server_id", connection.server_id.as_deref()),
            (
                "server_fingerprint",
                connection.server_fingerprint.as_deref(),
            ),
            (
                "expected_master_key_fp",
                connection.expected_master_key_fp.as_deref(),
            ),
            ("storage_id", connection.storage_id.as_deref()),
            ("vault", connection.vault.as_deref()),
        ] {
            if let Some(value) = value {
                validate_string_len(&format!("{base}.{field}"), value, MAX_METADATA_VALUE_LEN)?;
            }
        }
        if let Some(current_token) = &connection.current_token {
            validate_string_len(
                &format!("{base}.current_token"),
                current_token,
                MAX_LEGACY_NAME_LEN,
            )?;
        }
        for (profile_name, profile) in &connection.tokens {
            profile_count =
                profile_count
                    .checked_add(1)
                    .ok_or_else(|| ConfigError::InvalidConfig {
                        path: "$.contexts.*.tokens".to_string(),
                        reason: "credential profile count overflow".to_string(),
                    })?;
            validate_count("$.contexts.*.tokens", profile_count, MAX_PROFILES_TOTAL)?;
            validate_string_len(
                &legacy_path(&format!("{base}.tokens"), profile_name),
                profile_name,
                MAX_LEGACY_NAME_LEN,
            )?;
            if let Some(expires_at) = &profile.access_expires_at {
                validate_string_len(
                    &format!("{base}.tokens.{profile_name}.access_expires_at"),
                    expires_at,
                    MAX_LEGACY_NAME_LEN,
                )?;
            }
            for (field, secret) in [
                ("access_token", profile.access_token.as_ref()),
                ("refresh_token", profile.refresh_token.as_ref()),
                (
                    "service_account_token",
                    profile.service_account_token.as_ref(),
                ),
            ] {
                if let Some(secret) = secret {
                    validate_string_len(
                        &format!("{base}.tokens.{profile_name}.{field}"),
                        secret.expose_secret(),
                        MAX_CREDENTIAL_SECRET_LEN,
                    )?;
                }
            }
        }
    }
    let potential_slots =
        profile_count
            .checked_mul(3)
            .ok_or_else(|| ConfigError::InvalidConfig {
                path: "$.contexts.*.tokens".to_string(),
                reason: "credential slot count overflow".to_string(),
            })?;
    validate_count(
        "$.contexts.*.tokens.*",
        potential_slots,
        MAX_CREDENTIAL_SLOTS,
    )?;
    for (address, fingerprint) in known_hosts {
        validate_string_len("$.known_hosts.<address>", address, MAX_ADDRESS_LEN)?;
        validate_string_len(
            "$.known_hosts.<fingerprint>",
            fingerprint,
            MAX_METADATA_VALUE_LEN,
        )?;
    }
    Ok(())
}
