//! One-use local step-up proofs. Shells never authorize a plaintext writer.
use super::*;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;
mod policy;

#[cfg(test)]
mod tests;

pub(super) struct AuthorizedExport {
    token: Zeroizing<String>,
    pub(super) root: Arc<SecretKey>,
    pub(super) generation: u64,
    pub(super) expires: Instant,
    pub(super) operation: Arc<SessionOperation>,
    keyring: zann_client::app::unlock::DeviceUnlock,
    policy: ExportPolicy,
}
impl AuthorizedExport {
    pub(super) fn check_persisted(&self, core: &LocalVault) -> LocalResult<()> {
        self.check(core)?;
        core.verify_database()?;
        if core.export_source(&self.operation)? != (self.keyring.clone(), self.policy) {
            return Err(ExportError::AuthorizationChanged.into());
        }
        Ok(())
    }
    /// Context lease held; no nested runtime/SQLite work in writer callbacks.
    pub(super) fn check(&self, core: &LocalVault) -> LocalResult<()> {
        if self.operation.is_cancelled() {
            return Err(LocalError::Cancelled);
        }
        if Instant::now() >= self.expires {
            return Err(ExportError::AuthorizationExpired.into());
        }
        if core.context_generation.load(Ordering::SeqCst) != self.generation
            || !core
                .device_key
                .lock()
                .expect("device key")
                .as_ref()
                .is_some_and(|key| Arc::ptr_eq(key, &self.root))
        {
            return Err(ExportError::AuthorizationChanged.into());
        }
        Ok(())
    }
}
impl LocalVault {
    // SQLite waits never hold the session gate: cancellation/lock can release
    // key copies even when all connections are occupied.
    fn export_source(
        &self,
        operation: &SessionOperation,
    ) -> LocalResult<(zann_client::app::unlock::DeviceUnlock, ExportPolicy)> {
        let pool = self.pool();
        self.runtime.block_on(async {
            tokio::select! {
                biased;
                _ = operation.cancelled() => Err(LocalError::Cancelled),
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(operation.deadline())) => Err(LocalError::DeadlineExceeded),
                result = async {
                    let repo = zann_db::local::MetadataRepo::new(&pool);
                    let keyring = repo.get_value_bounded("device_keyring", 1024*1024).await.map_err(unlock::keyring_error)?.ok_or(ExportError::AuthorizationChanged)?;
                    let policy = repo.get_value_bounded(policy::POLICY_KEY,64).await.map_err(unlock::keyring_error)?.ok_or(ExportError::InvalidPolicy)?;
                    Ok((zann_client::app::unlock::DeviceUnlock::decode(&keyring).map_err(unlock::keyring_error)?, ExportPolicy::parse(&policy)?))
                } => result,
            }
        })
    }
    pub fn authorize_export(
        &self,
        proof: ExportStepUp,
        operation: SessionOperation,
    ) -> LocalResult<ExportAuthorization> {
        if operation.is_cancelled() {
            return Err(LocalError::Cancelled);
        }
        if Instant::now() >= operation.deadline() {
            return Err(LocalError::DeadlineExceeded);
        }
        let expires = (Instant::now() + Duration::from_secs(EXPORT_AUTHORIZATION_SECONDS))
            .min(operation.deadline());
        let _active = self
            .syncs
            .register(operation.operation_id(), operation.cancellation_handle());
        let (root, generation) = {
            let _context = self.context_gate.read().expect("context");
            (
                self.root_key()?,
                self.context_generation.load(Ordering::SeqCst),
            )
        };
        let (keyring, policy) = self.export_source(&operation)?;
        if policy == ExportPolicy::PasswordAndHardwareOrBiometric {
            if proof.password.is_none() {
                return Err(ExportError::PasswordRequired.into());
            }
            if matches!(proof.factor, ExportFactor::DevicePassword) {
                return Err(ExportError::SecondFactorRequired.into());
            }
        }
        if let Some(password) = &proof.password {
            let opened = keyring.open(password).map_err(unlock::keyring_error)?;
            if !zann_crypto::secret_bytes_equal(opened.as_bytes(), root.as_bytes()) {
                return Err(ExportError::AuthorizationChanged.into());
            }
        }
        let verified = match &proof.factor {
            ExportFactor::DevicePassword => {
                if proof.password.is_none() {
                    return Err(ExportError::PasswordRequired.into());
                }
                None
            }
            ExportFactor::HardwareKey { pin } => {
                let remembered = self.load_remembered()?;
                let verification = match pin.as_deref() {
                    Some(pin) => zann_keystore::HardwareVerification::Pin(pin),
                    None => zann_keystore::HardwareVerification::Presence,
                };
                Some(Zeroizing::new(
                    remembered
                        .unlock_with_hardware_key(self.authenticator.as_ref(), verification)
                        .map_err(unlock_error)?,
                ))
            }
            ExportFactor::Biometric => {
                let remembered = self.load_remembered()?;
                if !self.keystore.status().biometrics_available
                    || remembered.wrapped_master_key.is_none()
                {
                    return Err(ExportError::BiometricUnavailable.into());
                }
                Some(Zeroizing::new(
                    remembered
                        .unlock_with_keystore(self.keystore.as_ref())
                        .map_err(unlock_error)?,
                ))
            }
        };
        if verified
            .as_ref()
            .is_some_and(|key| !zann_crypto::secret_bytes_equal(key.as_ref(), root.as_bytes()))
        {
            return Err(ExportError::AuthorizationChanged.into());
        }
        let token = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            zann_crypto::ipc_signatures::random_nonce(),
        );
        let record = AuthorizedExport {
            token: Zeroizing::new(token.clone()),
            root,
            generation,
            expires,
            operation: Arc::new(operation),
            keyring,
            policy,
        };
        record.check(self)?;
        if self.device_unlock()? != record.keyring || self.export_policy()? != policy {
            return Err(ExportError::AuthorizationChanged.into());
        }
        *self
            .export_authorization
            .lock()
            .expect("export authorization") = Some(record);
        Ok(ExportAuthorization::from_token(token))
    }
    /// Consume before touching the destination. Accepted handles burn on every exit.
    pub(super) fn consume_export(
        &self,
        authorization: ExportAuthorization,
    ) -> LocalResult<(AuthorizedExport, in_flight::InFlightOperation<'_>)> {
        let (record, active) = {
            let _context = self.context_gate.read().expect("context");
            let mut pending = self
                .export_authorization
                .lock()
                .expect("export authorization");
            if !pending.as_ref().is_some_and(|record| {
                zann_crypto::secret_bytes_equal(
                    record.token.as_bytes(),
                    authorization.token().as_bytes(),
                )
            }) {
                return Err(ExportError::AuthorizationRequired.into());
            }
            let record = pending.take().expect("matched proof");
            let active = self.syncs.register(
                record.operation.operation_id(),
                record.operation.cancellation_handle(),
            );
            (record, active)
        };
        record.check_persisted(self)?;
        Ok((record, active))
    }
}
