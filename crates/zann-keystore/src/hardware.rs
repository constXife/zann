//! Platform-independent hardware unlock port. No OS discovery or UI policy.
use serde::{Deserialize, Serialize};

/// What has to be remembered to derive a DWK again. Not secret.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardwareCredential {
    pub credential_id: Vec<u8>,
    pub salt: [u8; 32],
}

#[derive(thiserror::Error, Debug)]
pub enum FidoError {
    #[error("no authenticator connected")]
    NoDevice,
    #[error("the connected authenticator is not enrolled for this vault")]
    NotEnrolled,
    #[error("no touch received")]
    Timeout,
    #[error("the authenticator is in use by another application")]
    Busy,
    #[error("this authenticator does not support hmac-secret")]
    NoHmacSecret,
    #[error("the authenticator is connected but not accessible; check the udev rules")]
    NotAccessible,
    #[error("hardware keys are not supported on this platform")]
    UnsupportedPlatform,
    /// Classified backend failure with its original diagnostic chain intact.
    #[error("authenticator error ({kind}): {source}")]
    Backend {
        kind: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("authenticator error: {message}")]
    Internal { message: String },
}

impl FidoError {
    /// Stable identifier for the UI to translate; the variants map one-to-one
    /// onto the states a user can actually act on.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NoDevice => "hardware_key_absent",
            Self::NotEnrolled => "hardware_key_not_enrolled",
            Self::Timeout => "hardware_key_timeout",
            Self::Busy => "hardware_key_busy",
            Self::NoHmacSecret => "hardware_key_unsupported",
            Self::NotAccessible => "hardware_key_not_accessible",
            Self::UnsupportedPlatform => "hardware_key_unsupported_platform",
            Self::Backend { kind, .. } => kind,
            Self::Internal { .. } => "hardware_key_error",
        }
    }
}

/// Metadata reported by the device; a missing product string stays absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorInfo {
    pub product_name: Option<String>,
    pub hmac_secret: bool,
}

/// Blocking platform operations. Call from the shell's blocking executor.
/// `create_credential` and `derive_dwk` each request one touch;
/// `status` and `is_present` must never request a touch or user verification.
pub trait HardwareAuthenticator: Send + Sync {
    /// Whether this adapter implements hardware unlock (independent of device presence).
    fn supported(&self) -> bool;
    fn status(&self) -> Result<AuthenticatorInfo, FidoError>;
    fn create_credential(&self, salt: [u8; 32]) -> Result<HardwareCredential, FidoError>;
    fn derive_dwk(&self, credential: &HardwareCredential) -> Result<[u8; 32], FidoError>;
    /// An error or a different token must report absent so auto-lock fails closed.
    fn is_present(&self, credential: &HardwareCredential) -> bool;
}

pub struct UnsupportedAuthenticator;
impl HardwareAuthenticator for UnsupportedAuthenticator {
    fn supported(&self) -> bool {
        false
    }
    fn status(&self) -> Result<AuthenticatorInfo, FidoError> {
        Err(FidoError::UnsupportedPlatform)
    }
    fn create_credential(&self, _: [u8; 32]) -> Result<HardwareCredential, FidoError> {
        Err(FidoError::UnsupportedPlatform)
    }
    fn derive_dwk(&self, _: &HardwareCredential) -> Result<[u8; 32], FidoError> {
        Err(FidoError::UnsupportedPlatform)
    }
    fn is_present(&self, _: &HardwareCredential) -> bool {
        false
    }
}

/// Platform selection belongs at composition, never inside an unlock operation.
pub fn default_authenticator() -> Box<dyn HardwareAuthenticator> {
    #[cfg(all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos")))]
    {
        Box::new(crate::fido::CtapHidAuthenticator)
    }
    #[cfg(not(all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos"))))]
    {
        Box::new(UnsupportedAuthenticator)
    }
}
