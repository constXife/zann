use super::*;

impl ConfigRepository {
    /// Commit the KDF identity a local vault was created or restored under.
    ///
    /// Compare-and-swap on the whole identity: `expected` is what the caller
    /// read, so a login that committed the server's identity in between is
    /// never overwritten by a locally generated one.
    pub fn replace_identity_if_matches(
        &self,
        expected: Option<&ConfigIdentity>,
        replacement: ConfigIdentity,
    ) -> Result<ConfigSnapshot, ConfigError> {
        let expected = expected.cloned();
        self.mutate(None, move |config| {
            if config.identity != expected {
                return Err(ConfigError::IdentityChanged);
            }
            config.identity = Some(replacement);
            Ok(())
        })
    }
}
