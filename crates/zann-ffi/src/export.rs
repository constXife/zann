//! Opaque step-up proof; Swift never reconstructs or persists authorization.
use crate::{BackupExportReport, CoreError, CoreFacade, CoreResult, SessionOperationFfi};
use std::sync::{Arc, Mutex};
use zann_client::app::local as native;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ExportPolicyFfi {
    AnyConfiguredFactor,
    PasswordAndHardwareOrBiometric,
}

impl From<native::ExportPolicy> for ExportPolicyFfi {
    fn from(value: native::ExportPolicy) -> Self {
        match value {
            native::ExportPolicy::AnyConfiguredFactor => Self::AnyConfiguredFactor,
            native::ExportPolicy::PasswordAndHardwareOrBiometric => {
                Self::PasswordAndHardwareOrBiometric
            }
        }
    }
}
impl From<ExportPolicyFfi> for native::ExportPolicy {
    fn from(value: ExportPolicyFfi) -> Self {
        match value {
            ExportPolicyFfi::AnyConfiguredFactor => Self::AnyConfiguredFactor,
            ExportPolicyFfi::PasswordAndHardwareOrBiometric => Self::PasswordAndHardwareOrBiometric,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ExportFactorFfi {
    DevicePassword,
    HardwareKey,
    Biometric,
}

#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct ExportSecurityFfi {
    pub policy: ExportPolicyFfi,
    pub hardware_available: bool,
    pub biometric_available: bool,
}

#[derive(uniffi::Record)]
pub struct ExportStepUpFfi {
    pub password: Option<String>,
    pub factor: ExportFactorFfi,
    pub pin: Option<String>,
}
impl std::fmt::Debug for ExportStepUpFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExportStepUpFfi(<redacted>)")
    }
}
impl ExportStepUpFfi {
    fn into_native(self) -> CoreResult<native::ExportStepUp> {
        let mut password = Zeroizing::new(self.password);
        let mut pin = Zeroizing::new(self.pin);
        let factor = match self.factor {
            ExportFactorFfi::HardwareKey => native::ExportFactor::HardwareKey { pin: pin.take() },
            _ if pin.is_some() => {
                return Err(CoreError::InvalidArgument(
                    "PIN requires a hardware factor".into(),
                ))
            }
            ExportFactorFfi::DevicePassword => native::ExportFactor::DevicePassword,
            ExportFactorFfi::Biometric => native::ExportFactor::Biometric,
        };
        Ok(native::ExportStepUp {
            password: password.take(),
            factor,
        })
    }
}

#[derive(uniffi::Object)]
pub struct ExportAuthorizationFfi(Mutex<Option<native::ExportAuthorization>>);
impl ExportAuthorizationFfi {
    fn take(&self) -> CoreResult<native::ExportAuthorization> {
        self.0
            .lock()
            .expect("authorization")
            .take()
            .ok_or_else(|| CoreError::Unlock {
                kind: "export_authorization_required".into(),
                message: "export authorization has already been consumed".into(),
            })
    }
}

#[uniffi::export]
impl CoreFacade {
    pub fn export_security(&self) -> CoreResult<ExportSecurityFfi> {
        let security = self.inner.export_security()?;
        Ok(ExportSecurityFfi {
            policy: security.policy.into(),
            hardware_available: security.hardware_available,
            biometric_available: security.biometric_available,
        })
    }
    pub fn authorize_export(
        &self,
        proof: ExportStepUpFfi,
        operation: Arc<SessionOperationFfi>,
    ) -> CoreResult<Arc<ExportAuthorizationFfi>> {
        let authorization = self
            .inner
            .authorize_export(proof.into_native()?, operation.take()?)?;
        Ok(Arc::new(ExportAuthorizationFfi(Mutex::new(Some(
            authorization,
        )))))
    }
    pub fn set_export_policy(
        &self,
        policy: ExportPolicyFfi,
        authorization: Arc<ExportAuthorizationFfi>,
    ) -> CoreResult<()> {
        self.inner
            .set_export_policy(policy.into(), authorization.take()?)
            .map_err(Into::into)
    }
    pub fn backup_export_file(
        &self,
        path: String,
        authorization: Arc<ExportAuthorizationFfi>,
    ) -> CoreResult<BackupExportReport> {
        self.inner
            .backup_export_file(path, authorization.take()?)
            .map(Into::into)
            .map_err(Into::into)
    }
}
