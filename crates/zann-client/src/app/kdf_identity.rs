//! The single KDF identity personal-vault master keys derive from.

use super::AppClient;
use crate::config::{ConfigError, ConfigIdentity};

impl AppClient {
    /// The account KDF identity committed by authentication or snapshot restore.
    /// `None` until an identity has been committed.
    pub fn kdf_identity(&self) -> Result<Option<ConfigIdentity>, ConfigError> {
        Ok(self.repository.snapshot()?.config().identity.clone())
    }

    /// Commit a restored identity or an explicit test fixture, provided the stored
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
