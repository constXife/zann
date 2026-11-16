//! Persisted export policy and guarded factor removal.
use super::*;
pub(super) const POLICY_KEY: &str = "export_step_up_policy";
impl LocalVault {
    pub fn export_security(&self) -> LocalResult<ExportSecurity> {
        let remembered = self.load_remembered()?;
        Ok(ExportSecurity {
            policy: self.export_policy()?,
            hardware_available: !remembered.hardware_keys.is_empty()
                && self.authenticator.supported(),
            biometric_available: remembered.wrapped_master_key.is_some()
                && self.keystore.status().biometrics_available,
        })
    }
    pub fn export_policy(&self) -> LocalResult<ExportPolicy> {
        let value = self
            .runtime
            .block_on(
                zann_db::local::MetadataRepo::new(&self.pool()).get_value_bounded(POLICY_KEY, 64),
            )
            .map_err(unlock::keyring_error)?
            .ok_or(ExportError::InvalidPolicy)?;
        ExportPolicy::parse(&value).map_err(Into::into)
    }
    pub fn set_export_policy(
        &self,
        policy: ExportPolicy,
        authorization: ExportAuthorization,
    ) -> LocalResult<()> {
        let (record, _active) = self.consume_export(authorization)?;
        record.check_persisted(self)?;
        let _context = self.context_gate.write().expect("context");
        record.check(self)?;
        let remembered = self.load_remembered()?;
        if policy == ExportPolicy::PasswordAndHardwareOrBiometric
            && remembered.hardware_keys.is_empty()
            && !(remembered.wrapped_master_key.is_some()
                && self.keystore.status().biometrics_available)
        {
            return Err(ExportError::SecondFactorRequired.into());
        }
        if !self
            .runtime
            .block_on(
                zann_db::local::MetadataRepo::new(&self.pool()).compare_exchange_value(
                    POLICY_KEY,
                    Some(record.policy.as_str()),
                    policy.as_str(),
                ),
            )
            .map_err(unlock::keyring_error)?
        {
            return Err(ExportError::AuthorizationChanged.into());
        }
        self.context_generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    pub(in crate::local_vault) fn check_export_factor_removal(
        &self,
        remove_hardware: Option<&str>,
        remove_biometric: bool,
    ) -> LocalResult<()> {
        if self.export_policy()? != ExportPolicy::PasswordAndHardwareOrBiometric {
            return Ok(());
        }
        let remembered = self.load_remembered()?;
        let hardware = remembered
            .hardware_keys
            .iter()
            .any(|key| Some(key.credential_id.as_str()) != remove_hardware);
        let biometric = !remove_biometric
            && remembered.wrapped_master_key.is_some()
            && self.keystore.status().biometrics_available;
        if !hardware && !biometric {
            return Err(ExportError::LastFactor.into());
        }
        Ok(())
    }
}
