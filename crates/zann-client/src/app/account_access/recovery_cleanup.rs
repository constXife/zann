//! Completion cleanup is gated by fresh ordinary authority and proven local key.
use super::*;
impl AppClient {
    pub async fn acknowledge_account_recovery(
        &self,
        target: &SessionTarget,
        root: &SecretKey,
        keyring: &unlock::DeviceUnlock,
        operation: SessionOperation,
    ) -> Result<(), SessionError> {
        if !self
            .repository
            .pending_recoveries()
            .map_err(|e| {
                SessionError::for_app(operation.operation_id(), SessionErrorKind::Configuration)
                    .with_source(e)
            })?
            .iter()
            .any(|intent| {
                intent.phase == crate::config::v2::recovery::RecoveryIntentPhase::Completed
            })
        {
            return Ok(());
        }
        let api = AccountApi::new(self, target, &operation)?;
        let access = api.access().await?;
        let failure =
            || SessionError::for_app(operation.operation_id(), SessionErrorKind::Protocol);
        if access.auth_method() != Some(AuthMethod::Passkey) {
            return Err(failure());
        }
        let entry = keyring.accounts.get(&api.storage).ok_or_else(failure)?;
        if entry.server_id != api.server || entry.account_subject != api.subject {
            return Err(failure());
        }
        let (key, origin) = keyring
            .account_key(root, &api.storage)
            .map_err(|e| failure().with_source(e))?;
        if access.personal_vaults_enabled()
            && (origin != AccountKeyOrigin::AccountPassword
                || self
                    .verify_account_key(target, &key, operation.detached_copy())
                    .await
                    .map_err(|e| failure().with_source(e))?
                    != AccountKeyCheck::Matches)
        {
            return Err(failure());
        }
        let endpoint = self.recovery_endpoint(target, &operation).await?;
        let user = Uuid::parse_str(&api.subject).map_err(|e| failure().with_source(e))?;
        self.repository
            .acknowledge_recovery_key_publication(&endpoint, user, self.credential_store.as_ref())
            .map_err(|e| failure().with_source(e))
    }
}
