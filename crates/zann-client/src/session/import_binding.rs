//! Resolve imported sessions by canonical endpoint and explicit profile/replica.
use super::*;

pub(super) struct BoundImportSession {
    pub(super) connection_id: ConnectionId,
    pub(super) endpoint: String,
    pub(super) storage_id: Option<String>,
    pub(super) server_fingerprint: String,
    pub(super) account_subject: String,
    pub(super) auth_method: AuthMethod,
}

pub(super) fn import_connection<'a>(
    config: &'a ConfigV2,
    endpoint: &str,
    storage_id: Option<&str>,
) -> Result<Option<(ConnectionId, &'a ConnectionConfig)>, ConfigError> {
    if let Some(storage) = storage_id {
        if let Some((id, _)) = config.replica_profile(storage)? {
            return Ok(Some((id.clone(), &config.connections[&id])));
        }
    }
    Ok(config
        .connection_for_address(endpoint)?
        .map(|id| (id.clone(), &config.connections[&id])))
}

pub(super) fn bound_import_session(
    config: &ConfigV2,
    endpoint: &str,
    storage_id: Option<&str>,
    profile_name: &str,
) -> Result<Option<BoundImportSession>, ConfigError> {
    let Some((id, connection)) = import_connection(config, endpoint, storage_id)? else {
        return Ok(None);
    };
    let address = ConfigV2::canonical_address(&connection.metadata().address)?;
    if ConfigV2::canonical_address(endpoint)? != address {
        return Err(ConfigError::BindingChangeRequiresRebind {
            connection_id: id,
            field: "address",
        });
    }
    let Some(profile) = connection.credential_profiles().get(profile_name) else {
        return Ok(None);
    };
    if let (Some(requested), Some(stored)) = (storage_id, profile.storage_id()) {
        if requested != stored {
            return Err(ConfigError::BindingChangeRequiresRebind {
                connection_id: id,
                field: "profile.storage_id",
            });
        }
    }
    // Filling a remote-only profile's replica requires live authentication and
    // an atomic Config commit; an idempotent read cannot invent that binding.
    if storage_id.is_some() && profile.storage_id().is_none() {
        return Ok(None);
    }
    let (Some(subject), Some(method)) = (profile.account_subject(), profile.auth_method()) else {
        return Ok(None);
    };
    let fingerprint = connection
        .metadata()
        .server_fingerprint
        .clone()
        .ok_or(ConfigError::IdentityChanged)?;
    if connection.metadata().server_id.is_none() {
        return Err(ConfigError::IdentityChanged);
    }
    Ok(Some(BoundImportSession {
        connection_id: id,
        endpoint: address,
        storage_id: profile.storage_id().map(str::to_owned),
        server_fingerprint: fingerprint,
        account_subject: subject.into(),
        auth_method: method,
    }))
}
