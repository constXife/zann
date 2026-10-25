use super::super::*;

impl ConfigRepository {
    pub fn upsert_connection(
        &self,
        connection_id: ConnectionId,
        metadata: ConnectionMetadata,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.upsert_connection_checked(None, connection_id, metadata)
    }

    /// Installs a server identity verified by the crate-owned signed probe.
    /// Existing bindings may only be completed, never silently replaced.
    #[cfg(feature = "remote")]
    pub(crate) fn pin_verified_connection(
        &self,
        expected_revision: u64,
        connection_id: ConnectionId,
        name: String,
        endpoint: &VerifiedEndpointBinding,
        storage_id: Option<String>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        if let Some(storage_id) = storage_id.as_deref() {
            validate_required_metadata("$.verified_connection.storage_id", storage_id)?;
        }
        self.mutate(Some(expected_revision), move |config| {
            match config.connections.get_mut(&connection_id) {
                Some(connection) => {
                    let metadata = &mut connection.metadata;
                    let normalized = normalize_address(
                        &metadata.address,
                        &format!("$.connections.{connection_id}.metadata.address"),
                    )?;
                    if normalized != endpoint.address
                        || metadata
                            .server_id
                            .as_deref()
                            .is_some_and(|value| value != endpoint.server_id)
                        || metadata
                            .server_fingerprint
                            .as_deref()
                            .is_some_and(|value| value != endpoint.server_fingerprint)
                        || metadata.storage_id.as_deref().is_some_and(|value| {
                            storage_id
                                .as_deref()
                                .is_some_and(|expected| value != expected)
                        })
                    {
                        return Err(ConfigError::BindingChangeRequiresRebind {
                            connection_id,
                            field: "verified_endpoint",
                        });
                    }
                    metadata.name = name;
                    metadata.server_id = Some(endpoint.server_id.clone());
                    metadata.server_fingerprint = Some(endpoint.server_fingerprint.clone());
                    if let Some(storage_id) = storage_id {
                        metadata.storage_id = Some(storage_id);
                    }
                }
                None => {
                    let mut metadata = ConnectionMetadata::new(name, endpoint.address.clone());
                    metadata.server_id = Some(endpoint.server_id.clone());
                    metadata.server_fingerprint = Some(endpoint.server_fingerprint.clone());
                    metadata.storage_id = storage_id;
                    config
                        .connections
                        .insert(connection_id, ConnectionConfig::from_metadata(metadata));
                }
            }
            Ok(())
        })
    }

    /// Replaces exactly one user-confirmed fingerprint while preserving the
    /// endpoint, server id, storage binding and every credential profile.
    #[cfg(feature = "remote")]
    pub(crate) fn replace_verified_fingerprint(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        expected_old: &str,
        endpoint: &VerifiedEndpointBinding,
    ) -> Result<ConfigSnapshot, ConfigError> {
        let connection_id = connection_id.clone();
        let expected_old = expected_old.to_string();
        let endpoint = endpoint.clone();
        self.mutate(Some(expected_revision), move |config| {
            let connection = config.connections.get_mut(&connection_id).ok_or_else(|| {
                ConfigError::MissingConnection {
                    connection_id: connection_id.clone(),
                }
            })?;
            let normalized = normalize_address(
                &connection.metadata.address,
                &format!("$.connections.{connection_id}.metadata.address"),
            )?;
            if normalized != endpoint.address
                || connection.metadata.server_id.as_deref() != Some(endpoint.server_id())
                || connection.metadata.server_fingerprint.as_deref() != Some(expected_old.as_str())
            {
                return Err(ConfigError::BindingChangeRequiresRebind {
                    connection_id,
                    field: "server_fingerprint",
                });
            }
            connection.metadata.server_fingerprint = Some(endpoint.server_fingerprint);
            Ok(())
        })
    }

    pub fn upsert_connection_if_revision(
        &self,
        expected_revision: u64,
        connection_id: ConnectionId,
        metadata: ConnectionMetadata,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.upsert_connection_checked(Some(expected_revision), connection_id, metadata)
    }

    pub(in crate::config::v2) fn upsert_connection_checked(
        &self,
        expected_revision: Option<u64>,
        connection_id: ConnectionId,
        metadata: ConnectionMetadata,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.mutate(expected_revision, move |config| {
            match config.connections.get_mut(&connection_id) {
                Some(connection) => {
                    if let Some(field) = changed_binding_field(&connection.metadata, &metadata) {
                        return Err(ConfigError::BindingChangeRequiresRebind {
                            connection_id,
                            field,
                        });
                    }
                    connection.metadata = metadata;
                }
                None => {
                    config
                        .connections
                        .insert(connection_id, ConnectionConfig::from_metadata(metadata));
                }
            }
            Ok(())
        })
    }

    pub fn update_connection<F>(
        &self,
        connection_id: &ConnectionId,
        update: F,
    ) -> Result<ConfigSnapshot, ConfigError>
    where
        F: FnOnce(&mut ConnectionMetadata) -> Result<(), ConfigError>,
    {
        self.update_connection_checked(None, connection_id, update)
    }

    pub fn update_connection_if_revision<F>(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        update: F,
    ) -> Result<ConfigSnapshot, ConfigError>
    where
        F: FnOnce(&mut ConnectionMetadata) -> Result<(), ConfigError>,
    {
        self.update_connection_checked(Some(expected_revision), connection_id, update)
    }

    pub(in crate::config::v2) fn update_connection_checked<F>(
        &self,
        expected_revision: Option<u64>,
        connection_id: &ConnectionId,
        update: F,
    ) -> Result<ConfigSnapshot, ConfigError>
    where
        F: FnOnce(&mut ConnectionMetadata) -> Result<(), ConfigError>,
    {
        let connection_id = connection_id.clone();
        self.mutate(expected_revision, move |config| {
            let connection = config.connections.get_mut(&connection_id).ok_or_else(|| {
                ConfigError::MissingConnection {
                    connection_id: connection_id.clone(),
                }
            })?;
            let previous = connection.metadata.clone();
            update(&mut connection.metadata)?;
            if let Some(field) = changed_binding_field(&previous, &connection.metadata) {
                return Err(ConfigError::BindingChangeRequiresRebind {
                    connection_id,
                    field,
                });
            }
            Ok(())
        })
    }

    pub fn set_active_connection(
        &self,
        client_id: &ClientId,
        connection_id: Option<ConnectionId>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_active_connection_checked(None, client_id, connection_id)
    }

    pub fn set_active_connection_if_revision(
        &self,
        expected_revision: u64,
        client_id: &ClientId,
        connection_id: Option<ConnectionId>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_active_connection_checked(Some(expected_revision), client_id, connection_id)
    }

    pub(in crate::config::v2) fn set_active_connection_checked(
        &self,
        expected_revision: Option<u64>,
        client_id: &ClientId,
        connection_id: Option<ConnectionId>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        let client_id = client_id.clone();
        self.mutate(expected_revision, move |config| {
            if let Some(candidate) = &connection_id {
                if !config.connections.contains_key(candidate) {
                    return Err(ConfigError::MissingConnection {
                        connection_id: candidate.clone(),
                    });
                }
            }
            client_entry(config, &client_id).active_connection = connection_id;
            Ok(())
        })
    }

    pub fn set_cli_default_vault(
        &self,
        connection_id: &ConnectionId,
        vault: String,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_cli_default_vault_checked(None, connection_id, Some(vault))
    }

    pub fn set_cli_default_vault_if_revision(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        vault: String,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_cli_default_vault_checked(Some(expected_revision), connection_id, Some(vault))
    }

    pub fn remove_cli_default_vault(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_cli_default_vault_checked(None, connection_id, None)
    }

    pub(in crate::config::v2) fn set_cli_default_vault_checked(
        &self,
        expected_revision: Option<u64>,
        connection_id: &ConnectionId,
        vault: Option<String>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        let connection_id = connection_id.clone();
        self.mutate(expected_revision, move |config| {
            if !config.connections.contains_key(&connection_id) {
                return Err(ConfigError::MissingConnection {
                    connection_id: connection_id.clone(),
                });
            }
            let cli_id = ClientId("cli".to_string());
            let client = client_entry(config, &cli_id);
            let ClientNamespace::CliV1(namespace) = &mut client.namespace else {
                return Err(ConfigError::InvalidConfig {
                    path: "$.clients.cli.namespace".to_string(),
                    reason: "CLI namespace has the wrong schema".to_string(),
                });
            };
            match vault {
                Some(vault) => {
                    namespace
                        .default_vault_by_connection
                        .insert(connection_id, vault);
                }
                None => {
                    namespace.default_vault_by_connection.remove(&connection_id);
                }
            }
            Ok(())
        })
    }

    pub fn set_desktop_backup_settings(
        &self,
        settings: Option<DesktopBackupSettings>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_desktop_backup_settings_checked(None, settings)
    }

    pub fn set_desktop_backup_settings_if_revision(
        &self,
        expected_revision: u64,
        settings: Option<DesktopBackupSettings>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.set_desktop_backup_settings_checked(Some(expected_revision), settings)
    }

    pub(in crate::config::v2) fn set_desktop_backup_settings_checked(
        &self,
        expected_revision: Option<u64>,
        settings: Option<DesktopBackupSettings>,
    ) -> Result<ConfigSnapshot, ConfigError> {
        self.mutate(expected_revision, move |config| {
            let desktop_id = ClientId("desktop".to_string());
            let client = client_entry(config, &desktop_id);
            let ClientNamespace::DesktopV1(namespace) = &mut client.namespace else {
                return Err(ConfigError::InvalidConfig {
                    path: "$.clients.desktop.namespace".to_string(),
                    reason: "desktop namespace has the wrong schema".to_string(),
                });
            };
            namespace.backup = settings;
            Ok(())
        })
    }
}

impl ConfigRepository {
    /// Select an existing credential profile without rewriting its secrets.
    pub fn set_active_credential_profile(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        profile_name: &str,
    ) -> Result<ConfigSnapshot, ConfigError> {
        let id = connection_id.clone();
        let name = profile_name.to_string();
        self.mutate(Some(expected_revision), move |config| {
            let connection =
                config
                    .connections
                    .get_mut(&id)
                    .ok_or_else(|| ConfigError::MissingConnection {
                        connection_id: id.clone(),
                    })?;
            if !connection.credential_profiles.contains_key(&name) {
                return Err(ConfigError::MissingCredentialProfile {
                    connection_id: id.clone(),
                    profile_name: name.clone(),
                });
            }
            connection.active_credential = Some(name);
            Ok(())
        })
    }
}
