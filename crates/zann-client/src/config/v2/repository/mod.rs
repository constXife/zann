use super::*;

impl ConfigRepository {
    pub fn new(paths: ClientPaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &ClientPaths {
        &self.paths
    }

    pub fn initialize(
        &self,
        legacy_client: &ClientId,
        credential_store: &dyn CredentialStore,
        legacy_credentials: &dyn LegacyCredentialSource,
    ) -> Result<ConfigSnapshot, ConfigError> {
        ensure_config_root(self.paths.root())?;
        if validate_regular_file_if_exists(&self.paths.credential_transaction_journal())? {
            let _recovery = self.reconcile_credentials(credential_store)?;
        }
        // Initialization may migrate and publish credentials. Serialize that
        // entire read/port/publish window with every other credential writer;
        // the post-acquire auth-intent barrier is enforced by this helper.
        let _credential_operation = self.credential_operation_lock()?;
        let config_path = self.paths.config();
        let legacy = {
            let _lock = self.exclusive_lock()?;
            if let Some(snapshot) = self.existing_snapshot_for_client(legacy_client)? {
                return Ok(snapshot);
            }
            self.ensure_no_pending_auth_operation_locked()?;
            self.ensure_no_unrecovered_backup()?;
            LegacyInput::read(&self.paths)?
        };

        // Credential backends may prompt the user or cross a process boundary. Do that work
        // without holding the filesystem lock. Deterministic credential ids make an interrupted
        // attempt safe to retry; the v2 file is not published until every secret is read back.
        let mut config = if legacy.has_sources() {
            migrate_legacy(
                &legacy,
                legacy_client,
                credential_store,
                legacy_credentials,
                &self.paths,
            )?
        } else {
            let mut config = ConfigV2::empty();
            config.migration = Some(MigrationStamp {
                source_format: "legacy-v1".to_string(),
                source_digest: legacy.digest.clone(),
                claimed_clients: BTreeSet::from([legacy_client.clone()]),
                deferred_legacy_fields: BTreeSet::new(),
            });
            config
        };

        let _lock = self.exclusive_lock()?;
        if let Some(snapshot) = self.existing_snapshot_for_client(legacy_client)? {
            return Ok(snapshot);
        }
        self.ensure_no_pending_auth_operation_locked()?;
        self.ensure_no_unrecovered_backup()?;
        let actual_digest = LegacyInput::read(&self.paths)?.digest;
        if legacy.digest != actual_digest {
            return Err(ConfigError::LegacyDiverged {
                expected: legacy.digest,
                actual: actual_digest,
            });
        }

        config.revision = 0;
        let bytes = serialize_config(&config)?;
        atomic_write(&config_path, &bytes)?;
        Ok(ConfigSnapshot { config })
    }

    pub(in crate::config::v2) fn existing_snapshot_for_client(
        &self,
        legacy_client: &ClientId,
    ) -> Result<Option<ConfigSnapshot>, ConfigError> {
        let primary_path = self.paths.config();
        if !validate_regular_file_if_exists(&primary_path)? {
            return Ok(None);
        }
        let previous_bytes = read_file(&primary_path, "read config")?;
        let mut config = parse_config(&primary_path, &previous_bytes)?;
        let should_claim = config
            .migration
            .as_ref()
            .is_some_and(|migration| !migration.claimed_clients.contains(legacy_client));
        if !should_claim {
            self.ensure_legacy_unchanged(&config)?;
            return Ok(Some(ConfigSnapshot { config }));
        }
        self.ensure_no_pending_auth_operation_locked()?;

        let legacy = LegacyInput::read(&self.paths)?;
        let expected_digest = config
            .migration
            .as_ref()
            .map(|migration| migration.source_digest.clone())
            .ok_or_else(|| ConfigError::InvalidConfig {
                path: "$.migration".to_string(),
                reason: "migration stamp disappeared during client claim".to_string(),
            })?;
        if expected_digest != legacy.digest {
            return Err(ConfigError::LegacyDiverged {
                expected: expected_digest,
                actual: legacy.digest,
            });
        }

        if config
            .clients
            .get(legacy_client)
            .and_then(|client| client.active_connection.as_ref())
            .is_none()
        {
            if let Some(active_connection) = legacy.active_connection_id(&self.paths)? {
                if !config.connections.contains_key(&active_connection) {
                    return Err(ConfigError::MissingConnection {
                        connection_id: active_connection,
                    });
                }
                client_entry(&mut config, legacy_client).active_connection =
                    Some(active_connection);
            }
        }
        if let Some(migration) = config.migration.as_mut() {
            migration.claimed_clients.insert(legacy_client.clone());
        }
        config.revision = config
            .revision
            .checked_add(1)
            .ok_or(ConfigError::RevisionOverflow)?;
        let next_bytes = serialize_config(&config)?;
        atomic_write(&self.paths.backup(), &previous_bytes)?;
        atomic_write(&primary_path, &next_bytes)?;
        Ok(Some(ConfigSnapshot { config }))
    }

    pub(in crate::config::v2) fn ensure_no_unrecovered_backup(&self) -> Result<(), ConfigError> {
        let backup_path = self.paths.backup();
        if !validate_regular_file_if_exists(&backup_path)? {
            return Ok(());
        }
        let bytes = read_file(&backup_path, "read config backup")?;
        let backup = parse_config(&backup_path, &bytes)?;
        Err(ConfigError::RecoveryRequired {
            path: backup_path,
            revision: backup.revision,
        })
    }

    pub fn snapshot(&self) -> Result<ConfigSnapshot, ConfigError> {
        let _lock = self.exclusive_lock()?;
        let config = self.read_primary()?;
        self.ensure_legacy_unchanged(&config)?;
        Ok(ConfigSnapshot { config })
    }
}

mod auth_intent;
mod connections;
mod credential_remove;
mod credential_transaction;
mod credentials;
mod generation;
mod intent_recovery;
mod locks;
mod login_commit;
mod restore;
