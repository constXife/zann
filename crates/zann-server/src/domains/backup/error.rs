use std::fmt;

#[derive(thiserror::Error)]
pub enum BackupError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("backup_io_failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("backup_database_failed")]
    Database(#[from] sqlx_core::Error),
    #[error("backup_crypto_failed: {0}")]
    Crypto(#[from] zann_crypto::VaultCryptoError),
    #[error("backup_payload_failed: {0}")]
    Payload(#[from] zann_crypto::PayloadError),
    #[error("{0}")]
    Json(#[from] JsonDiagnostic),
    #[error("backup_worker_failed: {0}")]
    Worker(#[from] tokio::task::JoinError),
}

// Original JSON diagnostics can quote plaintext. Retain the complete error
// for structured inspection, but never expose its unsafe rendering via logs
// or an Error::source chain. Location remains available in normal diagnostics.
pub struct JsonDiagnostic(serde_json::Error);
impl fmt::Display for JsonDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid_backup_json (line {}, column {})",
            self.0.line(),
            self.0.column()
        )
    }
}
impl fmt::Debug for JsonDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for JsonDiagnostic {}
impl From<serde_json::Error> for BackupError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(JsonDiagnostic(error))
    }
}
impl fmt::Debug for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
