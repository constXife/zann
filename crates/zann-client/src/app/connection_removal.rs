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
    /// No connection was configured for this endpoint.
    AlreadyAbsent,
}

impl AppClient {
    /// Forgets the canonical trust owner for this normalized endpoint: its pinned server identity, credential profiles and stored
    /// credentials. This is the explicit recovery from
    /// [`SessionErrorKind::ServerIdentityChanged`]; the next
    /// `prepare_connection` then pins whatever server answers, as on first
    /// use. Nothing is sent to the server, and the local sync projection is
    /// left to [`Self::reset_sync`].
    ///
    /// Repeating the call after it succeeded returns
    /// [`ConnectionRemoval::AlreadyAbsent`].
    pub fn remove_connection(&self, endpoint: &str) -> Result<ConnectionRemoval, SessionError> {
        let snapshot = self
            .repository
            .snapshot()
            .map_err(connection_removal_error)?;
        let Some(connection_id) = snapshot
            .config()
            .connection_for_address(endpoint)
            .map_err(connection_removal_error)?
        else {
            return Ok(ConnectionRemoval::AlreadyAbsent);
        };
        self.remove_pinned_connection(&snapshot, connection_id)
    }

    /// Whether a connection syncs `storage_id`: the one
    /// [`Self::configured_target`] resolves for it. A storage loses it when
    /// [`Self::remove_storage_connection`] forgets its server.
    pub fn syncs_storage(&self, storage_id: &str) -> Result<bool, SessionError> {
        let snapshot = self
            .repository
            .snapshot()
            .map_err(connection_removal_error)?;
        storage_connection(snapshot.config(), storage_id)
            .map(|connection| connection.is_some())
            .map_err(|kind| SessionError::for_app(SessionOperationId::new(), kind))
    }

    /// Disconnect exactly one account replica. Retain the endpoint trust record,
    /// other profiles, keyring entries and cached data. Return its address once.
    pub fn remove_storage_connection(
        &self,
        storage_id: &str,
    ) -> Result<Option<String>, SessionError> {
        let plan = self
            .prepare_account_removal(storage_id)
            .map_err(connection_removal_error)?;
        let Some((connection, _)) = plan.profile.as_ref() else {
            return Ok(None);
        };
        let address = plan.snapshot.config().connections[connection]
            .metadata()
            .address
            .clone();
        self.commit_account_removal(plan)
            .map_err(connection_removal_error)?;
        Ok(Some(address))
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
    let kind = match &error {
        ConfigError::RevisionConflict { .. } => SessionErrorKind::ConcurrentSessionChange,
        error => crate::session::local_config_error_kind(error),
    };
    SessionError::for_app(SessionOperationId::new(), kind).with_source(error)
}

/// The one connection whose pinned storage is `storage_id`. Two connections
/// pinning the same storage are a configuration error, never a guess.
pub(super) fn storage_connection(
    config: &crate::config::ConfigV2,
    storage_id: &str,
) -> Result<Option<ConnectionId>, SessionErrorKind> {
    config
        .replica_profile(storage_id)
        .map(|profile| profile.map(|(id, _)| id))
        .map_err(|_| SessionErrorKind::Configuration)
}

/// Exact Config source for removing one account profile while retaining endpoint trust.
pub struct AccountRemovalPlan {
    root: std::path::PathBuf,
    snapshot: crate::config::ConfigSnapshot,
    profile: Option<(ConnectionId, String)>,
}
impl AccountRemovalPlan {
    pub fn is_configured(&self) -> bool {
        self.profile.is_some()
    }
}
impl AppClient {
    pub fn prepare_account_removal(
        &self,
        storage: &str,
    ) -> Result<AccountRemovalPlan, ConfigError> {
        let snapshot = self.repository.snapshot()?;
        let profile = snapshot.config().replica_profile(storage)?;
        Ok(AccountRemovalPlan {
            root: self.paths.root().to_path_buf(),
            snapshot,
            profile,
        })
    }
    pub fn commit_account_removal(&self, plan: AccountRemovalPlan) -> Result<(), ConfigError> {
        if plan.root != self.paths.root() {
            return Err(ConfigError::IdentityChanged);
        }
        if let Some((connection, profile)) = plan.profile {
            self.repository.remove_credential_profile(
                plan.snapshot.revision(),
                &connection,
                profile,
                crate::config::ActiveCredentialAfterRemoval::Clear,
                self.credential_store.as_ref(),
            )?;
        } else if self.repository.snapshot()?.revision() != plan.snapshot.revision() {
            return Err(ConfigError::IdentityChanged);
        }
        Ok(())
    }
}
