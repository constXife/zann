//! Offline, device-local authorization for disclosing plaintext exports.
use std::fmt;
use zeroize::Zeroize;

pub const EXPORT_AUTHORIZATION_SECONDS: u64 = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportPolicy {
    AnyConfiguredFactor,
    PasswordAndHardwareOrBiometric,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportSecurity {
    pub policy: ExportPolicy,
    pub hardware_available: bool,
    pub biometric_available: bool,
}

impl ExportPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AnyConfiguredFactor => "any_configured_factor",
            Self::PasswordAndHardwareOrBiometric => "password_and_hardware_or_biometric",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ExportError> {
        match value {
            "any_configured_factor" => Ok(Self::AnyConfiguredFactor),
            "password_and_hardware_or_biometric" => Ok(Self::PasswordAndHardwareOrBiometric),
            _ => Err(ExportError::InvalidPolicy),
        }
    }
}

pub enum ExportFactor {
    DevicePassword,
    HardwareKey { pin: Option<String> },
    Biometric,
}

impl Drop for ExportFactor {
    fn drop(&mut self) {
        if let Self::HardwareKey { pin } = self {
            pin.zeroize();
        }
    }
}

/// The local password is mandatory for strict mode, including with hardware.
pub struct ExportStepUp {
    pub password: Option<String>,
    pub factor: ExportFactor,
}

impl ExportStepUp {
    pub fn device_password(password: String) -> Self {
        Self {
            password: Some(password),
            factor: ExportFactor::DevicePassword,
        }
    }
}

impl Drop for ExportStepUp {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Opaque one-use handle; the issuing service owns the proof and expiry.
pub struct ExportAuthorization {
    token: String,
}

impl ExportAuthorization {
    pub fn from_token(token: String) -> Self {
        Self { token }
    }
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl Drop for ExportAuthorization {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

macro_rules! redacted {
    ($($ty:ty),+) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("<redacted export authorization>") }
    })+ };
}
redacted!(ExportStepUp, ExportFactor, ExportAuthorization);

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("fresh export authorization is required")]
    AuthorizationRequired,
    #[error("export authorization expired; authenticate again")]
    AuthorizationExpired,
    #[error("export session or security policy changed; authenticate again")]
    AuthorizationChanged,
    #[error("the local device password is required")]
    PasswordRequired,
    #[error("a live enrolled hardware key or biometric confirmation is required")]
    SecondFactorRequired,
    #[error("biometric export confirmation is not enrolled or available")]
    BiometricUnavailable,
    #[error("disable strict export protection before removing its last enrolled factor")]
    LastFactor,
    #[error("invalid or missing export security policy")]
    InvalidPolicy,
}

impl ExportError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AuthorizationRequired => "export_authorization_required",
            Self::AuthorizationExpired => "export_authorization_expired",
            Self::AuthorizationChanged => "export_authorization_changed",
            Self::PasswordRequired => "export_password_required",
            Self::SecondFactorRequired => "export_second_factor_required",
            Self::BiometricUnavailable => "export_biometric_unavailable",
            Self::LastFactor => "export_last_factor",
            Self::InvalidPolicy => "export_policy_invalid",
        }
    }
}
