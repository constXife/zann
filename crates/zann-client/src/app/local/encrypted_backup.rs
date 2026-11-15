//! Typed encrypted-archive application ports. Handles expose no key material.
use zeroize::Zeroize;

#[derive(Clone)]
pub struct BackupHandle(String);
impl BackupHandle {
    pub fn from_token(token: String) -> Self {
        Self(token)
    }
    pub fn token(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for BackupHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupHandle(<redacted>)")
    }
}
impl Drop for BackupHandle {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub enum BackupRecipient {
    Passphrase {
        passphrase: String,
    },
    Hardware {
        pin: Option<String>,
        built_in_uv: bool,
    },
    Biometric,
}
impl Drop for BackupRecipient {
    fn drop(&mut self) {
        match self {
            Self::Passphrase { passphrase } => passphrase.zeroize(),
            Self::Hardware { pin, .. } => pin.zeroize(),
            Self::Biometric => {}
        }
    }
}
impl std::fmt::Debug for BackupRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupRecipient(<redacted>)")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupRecipientKind {
    Passphrase,
    Hardware,
    Biometric,
}
#[derive(Clone, Debug)]
pub struct BackupRecipientSummary {
    pub index: u32,
    pub kind: BackupRecipientKind,
}
#[derive(Clone, Debug)]
pub struct BackupSourceStorage {
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug)]
pub struct BackupInspection {
    pub storages: Vec<BackupSourceStorage>,
    pub vaults_count: u64,
    pub items_count: u64,
}

#[derive(Clone, Debug)]
pub struct BackupCapabilities {
    pub recipients: Vec<BackupRecipientKind>,
    pub max_recipients: u32,
}
