use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreStatus {
    pub supported: bool,
    pub biometrics_available: bool,
    pub reason: Option<KeystoreStatusReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeystoreStatusReason {
    Unavailable,
    NotEnrolled,
    LockedOut,
    Changed,
}

#[derive(thiserror::Error, Debug, Clone, Serialize, Deserialize)]
pub enum KeystoreError {
    #[error("biometrics unavailable")]
    BiometryUnavailable,
    #[error("operation cancelled")]
    Cancelled,
    #[error("key not found")]
    NotFound,
    #[error("unsupported")]
    Unsupported,
    #[error("internal error: {message}")]
    Internal { message: String },
}

pub trait Keystore: Send + Sync {
    fn status(&self) -> Result<KeystoreStatus, KeystoreError>;
    fn store_dwk(&self, dwk: &[u8], require_biometrics: bool) -> Result<(), KeystoreError>;
    fn load_dwk(&self, prompt: &str) -> Result<Option<Vec<u8>>, KeystoreError>;
    fn delete_dwk(&self) -> Result<(), KeystoreError>;
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod windows;

#[cfg(target_os = "macos")]
pub use macos::MacosKeystore;
#[cfg(not(target_os = "macos"))]
pub use windows::WindowsKeystore;

pub fn default_keystore() -> Box<dyn Keystore> {
    #[cfg(target_os = "macos")]
    {
        Box::new(MacosKeystore::new("zann", "dwk"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(WindowsKeystore::new())
    }
}
