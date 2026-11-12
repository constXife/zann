//! Forgetting a pinned connection: the explicit recovery from a server whose
//! identity changed.

use super::{AppClient, SessionError, SessionErrorKind, SessionOperationId};
use crate::config::{ConfigError, ConnectionId};

/// What [`AppClient::remove_connection`] did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionRemoval {
    /// The connection is gone from the config. `cleanup_deferred` means some
    /// of its stored credentials are retired in the credential journal but
    /// still in the store, typically because the config backup keeps the
    /// previous generation restorable; a later credential reconcile deletes
    /// them, exactly as after a logout.
    Removed { cleanup_deferred: bool },
    /// No connection was configured for this endpoint and name.
    AlreadyAbsent,
}

impl AppClient {
    /// Forgets the connection that `prepare_connection` keys by this endpoint
    /// and name: its pinned server identity, credential profiles and stored
    /// credentials. This is the explicit recovery from
    /// [`SessionErrorKind::ServerIdentityChanged`]; the next
    /// `prepare_connection` then pins whatever server answers, as on first
    /// use. Nothing is sent to the server, and the local sync projection is
    /// left to [`Self::reset_sync`].
    ///
    /// Repeating the call after it succeeded returns
    /// [`ConnectionRemoval::AlreadyAbsent`].
    pub fn remove_connection(
        &self,
        endpoint: &str,
        connection_name: &str,
    ) -> Result<ConnectionRemoval, SessionError> {
        let snapshot = self
            .repository
            .snapshot()
            .map_err(connection_removal_error)?;
        let connection_id = ConnectionId::deterministic(connection_name, endpoint);
        self.remove_pinned_connection(&snapshot, connection_id)
    }

    /// Forgets the connection that syncs `storage_id`, the one
    /// [`Self::configured_target`] resolves for it, exactly as
    /// [`Self::remove_connection`] does. It is the same recovery for a shell
    /// that knows the storage it syncs rather than the address it typed.
    ///
    /// Returns the forgotten address, so the shell can offer to connect there
    /// again, or `None` when no connection syncs this storage (also after a
    /// repeated call).
    pub fn remove_storage_connection(
        &self,
        storage_id: &str,
    ) -> Result<Option<String>, SessionError> {
        let snapshot = self
            .repository
            .snapshot()
            .map_err(connection_removal_error)?;
        let Some(connection_id) = storage_connection(snapshot.config(), storage_id)
            .map_err(|kind| SessionError::for_app(SessionOperationId::new(), kind))?
        else {
            return Ok(None);
        };
        let address = snapshot.config().connections[&connection_id]
            .metadata()
            .address
            .clone();
        Ok(
            match self.remove_pinned_connection(&snapshot, connection_id)? {
                ConnectionRemoval::Removed { .. } => Some(address),
                ConnectionRemoval::AlreadyAbsent => None,
            },
        )
    }

    fn remove_pinned_connection(
        &self,
        snapshot: &crate::config::ConfigSnapshot,
        connection_id: ConnectionId,
    ) -> Result<ConnectionRemoval, SessionError> {
        if !snapshot.config().connections.contains_key(&connection_id) {
            return Ok(ConnectionRemoval::AlreadyAbsent);
        }
        let outcome = self
            .repository
            .remove_connection(
                snapshot.revision(),
                &connection_id,
                self.credential_store.as_ref(),
            )
            .map_err(connection_removal_error)?;
        Ok(ConnectionRemoval::Removed {
            cleanup_deferred: !outcome.warnings().is_empty(),
        })
    }
}

fn connection_removal_error(error: ConfigError) -> SessionError {
    let kind = match error {
        ConfigError::RevisionConflict { .. } => SessionErrorKind::ConcurrentSessionChange,
        error => crate::session::local_config_error_kind(&error),
    };
    SessionError::for_app(SessionOperationId::new(), kind)
}

/// The one connection whose pinned storage is `storage_id`. Two connections
/// pinning the same storage are a configuration error, never a guess.
pub(super) fn storage_connection(
    config: &crate::config::ConfigV2,
    storage_id: &str,
) -> Result<Option<ConnectionId>, SessionErrorKind> {
    let mut matches = config
        .connections
        .iter()
        .filter(|(_, connection)| connection.metadata().storage_id.as_deref() == Some(storage_id));
    let selected = matches.next().map(|(id, _)| id.clone());
    if matches.next().is_some() {
        return Err(SessionErrorKind::Configuration);
    }
    Ok(selected)
}
