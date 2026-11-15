//! Authenticated account proof before releasing a selected SQLite generation claim.
use super::*;

impl AppClient {
    pub(super) async fn finish_account_authentication(
        &self,
        access: SessionAccess,
    ) -> Result<SessionAccess, SessionError> {
        let Some(storage) = access.storage_id() else {
            return Ok(access);
        };
        let failure =
            || SessionError::for_app(access.operation_id(), SessionErrorKind::Configuration);
        let storage = Uuid::parse_str(storage).map_err(|e| failure().with_source(e))?;
        let lease = self
            .active_account_key_lease(access.target())
            .await
            .map_err(|e| failure().with_source(e))?;
        let generation = lease.generation();
        for (field, matches) in [
            ("storage", generation.storage_id() == access.storage_id()),
            (
                "subject",
                generation.account_subject() == access.account_subject(),
            ),
            ("method", generation.auth_method() == access.auth_method()),
            ("endpoint", generation.address() == access.endpoint()),
            (
                "pin",
                generation.server_fingerprint() == Some(access.server_fingerprint()),
            ),
        ] {
            if !matches {
                return Err(
                    failure().with_source(crate::config::ConfigError::InvalidConfig {
                        path: format!("$.authenticated_access.{field}"),
                        reason:
                            "authenticated access no longer matches the exact account generation"
                                .into(),
                    }),
                );
            }
        }
        if let Some(replica) = self
            .sync_store_factory
            .clone()
            .replica_at(self.paths.clone(), storage)
            .await
            .map_err(|e| failure().with_source(e))?
        {
            // The current pin was verified by authentication under this exact
            // lease. A changed pin can reach here only after explicit trust.
            if Some(replica.account_subject.as_str()) != access.account_subject()
                || replica.address != access.endpoint()
            {
                return Err(failure());
            }
            self.sync_store_factory
                .clone()
                .release_storage(self.paths.clone(), storage)
                .await
                .map_err(|e| failure().with_source(e))?;
        }
        drop(lease);
        Ok(access)
    }
}
