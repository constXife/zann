//! The single KDF identity personal-vault master keys derive from.

use super::AppClient;
use crate::config::{ConfigError, ConfigIdentity};

impl AppClient {
    /// The committed KDF identity: the server's after a login, or the one a
    /// local-only vault was created with. `None` until either happened.
    pub fn kdf_identity(&self) -> Result<Option<ConfigIdentity>, ConfigError> {
        Ok(self.repository.snapshot()?.config().identity.clone())
    }

    /// Commit a locally generated or restored identity, provided the stored
    /// one is still `expected`.
    pub fn replace_kdf_identity_if_matches(
        &self,
        expected: Option<&ConfigIdentity>,
        replacement: ConfigIdentity,
    ) -> Result<(), ConfigError> {
        self.repository
            .replace_identity_if_matches(expected, replacement)
            .map(|_| ())
    }
}
