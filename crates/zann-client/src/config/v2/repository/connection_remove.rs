use super::super::*;

impl ConfigRepository {
    /// Forgets one connection: its pinned server identity, every credential
    /// profile and every client selection or CLI default that points at it,
    /// in one config generation. Stored credentials the connection held are
    /// retired through the credential journal: they are deleted once no
    /// durable generation (including the backup) references them, and a
    /// crash after the commit still deletes them on a later reconcile.
    ///
    /// This is purely local. It never contacts the server, which is what
    /// makes it the recovery path for a server whose identity changed.
    pub fn remove_connection(
        &self,
        expected_revision: u64,
        connection_id: &ConnectionId,
        credential_store: &dyn CredentialStore,
    ) -> Result<CredentialTransactionOutcome, ConfigError> {
        let snapshot = self.snapshot()?;
        if snapshot.revision() != expected_revision {
            return Err(ConfigError::RevisionConflict {
                expected: expected_revision,
                actual: snapshot.revision(),
            });
        }
        let connection = snapshot
            .config()
            .connections
            .get(connection_id)
            .ok_or_else(|| ConfigError::MissingConnection {
                connection_id: connection_id.clone(),
            })?;
        let holds_credentials = connection
            .credential_profiles
            .values()
            .any(|profile| !profile.credentials.is_empty());
        // Both branches re-check `expected_revision` under the exclusive
        // lock, so a credential written since this snapshot fails the call
        // instead of escaping retirement.
        if holds_credentials {
            self.execute_credential_transaction(
                expected_revision,
                None,
                credential_store,
                |config, credential_ids| {
                    if !credential_ids.is_empty() {
                        return Err(ConfigError::InvalidConfig {
                            path: "$.connection_removal".to_string(),
                            reason: "connection removal must not allocate credential ids"
                                .to_string(),
                        });
                    }
                    apply_connection_removal(config, connection_id)
                },
            )
        } else {
            let snapshot = self.mutate(Some(expected_revision), |config| {
                apply_connection_removal(config, connection_id)
            })?;
            Ok(CredentialTransactionOutcome {
                snapshot,
                warnings: Vec::new(),
            })
        }
    }
}

fn apply_connection_removal(
    config: &mut ConfigV2,
    connection_id: &ConnectionId,
) -> Result<(), ConfigError> {
    if config.connections.remove(connection_id).is_none() {
        return Err(ConfigError::MissingConnection {
            connection_id: connection_id.clone(),
        });
    }
    for client in config.clients.values_mut() {
        if client.active_connection.as_ref() == Some(connection_id) {
            client.active_connection = None;
        }
        if let ClientNamespace::CliV1(namespace) = &mut client.namespace {
            namespace.default_vault_by_connection.remove(connection_id);
        }
    }
    Ok(())
}
