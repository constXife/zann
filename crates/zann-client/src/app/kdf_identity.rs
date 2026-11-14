//! Account identities belong to the authenticated connection/profile, never the device password.
use super::{AppClient, SessionTarget};
use crate::config::{ConfigError, ConfigIdentity};

impl AppClient {
    pub fn account_identity(&self, target: &SessionTarget) -> Result<ConfigIdentity, ConfigError> {
        let snapshot = self.repository.snapshot()?;
        snapshot
            .config()
            .account_identities
            .get(&format!(
                "{}/{}",
                target.connection_id(),
                target.profile_name()
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
            metadata
                .storage_id
                .clone()
                .ok_or(ConfigError::IdentityChanged)?,
            metadata
                .server_id
                .clone()
                .ok_or(ConfigError::IdentityChanged)?,
            subject.to_owned(),
        ))
    }
}
