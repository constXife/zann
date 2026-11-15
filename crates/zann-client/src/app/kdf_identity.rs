//! Account identities belong to the authenticated connection/profile, never the device password.
use super::{AppClient, SessionTarget};
use crate::config::{ConfigError, ConfigIdentity};

impl AppClient {
    pub fn account_identity(&self, target: &SessionTarget) -> Result<ConfigIdentity, ConfigError> {
        let snapshot = self.repository.snapshot()?;
        snapshot
            .config()
            .account_identities
            .get(&crate::config::v2::identity_slot(
                target.connection_id(),
                target.profile_name(),
            ))
            .cloned()
            .ok_or(ConfigError::IdentityChanged)
    }
}

impl AppClient {
    /// An exact binding from the authenticated profile; never inferred from email or active UI selection.
    pub fn account_key_binding(
        &self,
        target: &SessionTarget,
    ) -> Result<(String, String, String), ConfigError> {
        let snapshot = self.repository.snapshot()?;
        let connection = snapshot
            .config()
            .connections
            .get(target.connection_id())
            .ok_or(ConfigError::IdentityChanged)?;
        let metadata = connection.metadata();
        let subject = connection
            .credential_profiles()
            .get(target.profile_name())
            .and_then(|p| p.account_subject())
            .ok_or(ConfigError::IdentityChanged)?;
        Ok((
            connection
                .profile_storage_id(target.profile_name())
                .map(str::to_owned)
                .ok_or(ConfigError::IdentityChanged)?,
            metadata
                .server_id
                .clone()
                .ok_or(ConfigError::IdentityChanged)?,
            subject.to_owned(),
        ))
    }
}

impl AppClient {
    /// Configured account locations survive a reset of local keys/cache.
    pub fn account_locations(&self) -> Result<Vec<super::local::AccountLocation>, ConfigError> {
        let snapshot = match self.repository.snapshot() {
            Ok(snapshot) => snapshot,
            Err(ConfigError::MissingConfig { .. }) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut accounts = Vec::new();
        for connection in snapshot.config().connections.values() {
            for profile in connection.credential_profiles().values() {
                let (Some(storage_id), Some(subject)) =
                    (profile.storage_id(), profile.account_subject())
                else {
                    continue;
                };
                let server = connection
                    .metadata()
                    .server_id
                    .clone()
                    .ok_or(ConfigError::IdentityChanged)?;
                let account_name = profile.account_email().map(str::to_owned);
                accounts.push(super::local::AccountLocation {
                    storage_id: storage_id.to_owned(),
                    name: connection.metadata().name.clone(),
                    server_url: connection.metadata().address.clone(),
                    account_name,
                    key_binding: Some((server, subject.to_owned())),
                });
            }
        }
        Ok(accounts)
    }
}
