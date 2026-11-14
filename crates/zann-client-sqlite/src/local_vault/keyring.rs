//! SQLite custody of the encrypted keyring, shared atomically with snapshots.
use super::unlock::keyring_error;
use super::*;

impl LocalVault {
    pub(super) fn device_unlock_optional(
        &self,
    ) -> LocalResult<Option<zann_client::app::unlock::DeviceUnlock>> {
        let pool = self.pool();
        self.runtime
            .block_on(
                zann_db::local::MetadataRepo::new(&pool)
                    .get_value_bounded("device_keyring", 1024 * 1024),
            )
            .map_err(keyring_error)?
            .map(|value| {
                zann_client::app::unlock::DeviceUnlock::decode(&value).map_err(keyring_error)
            })
            .transpose()
    }

    pub(super) fn device_unlock(&self) -> LocalResult<zann_client::app::unlock::DeviceUnlock> {
        self.device_unlock_optional()?
            .ok_or_else(|| LocalError::InvalidArgument("set a Zann unlock password first".into()))
    }

    pub(super) fn commit_device_unlock(
        &self,
        expected: Option<&zann_client::app::unlock::DeviceUnlock>,
        replacement: &zann_client::app::unlock::DeviceUnlock,
    ) -> LocalResult<()> {
        let replacement = serde_json::to_string(replacement).map_err(keyring_error)?;
        zann_client::app::unlock::DeviceUnlock::decode(&replacement).map_err(keyring_error)?;
        let pool = self.pool();
        let source = self
            .runtime
            .block_on(
                zann_db::local::MetadataRepo::new(&pool)
                    .get_value_bounded("device_keyring", 1024 * 1024),
            )
            .map_err(keyring_error)?;
        let current = source
            .as_deref()
            .map(zann_client::app::unlock::DeviceUnlock::decode)
            .transpose()
            .map_err(keyring_error)?;
        if current.as_ref() != expected {
            return Err(keyring_error(
                zann_client::config::ConfigError::IdentityChanged,
            ));
        }
        if !self
            .runtime
            .block_on(
                zann_db::local::MetadataRepo::new(&pool).compare_exchange_value(
                    "device_keyring",
                    source.as_deref(),
                    &replacement,
                ),
            )
            .map_err(keyring_error)?
        {
            return Err(keyring_error(
                zann_client::config::ConfigError::IdentityChanged,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_invalid_candidate_never_replaces_the_readable_keyring() {
        let (_dir, core, _, _) = super::super::context_tests::fixture();
        let source = core.device_unlock().expect("source");
        let mut invalid = source.clone();
        invalid
            .accounts
            .values_mut()
            .next()
            .expect("account")
            .account_subject = "x".repeat(513);
        assert!(core.commit_device_unlock(Some(&source), &invalid).is_err());
        assert_eq!(core.device_unlock().expect("still readable"), source);
    }
}
