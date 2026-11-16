#[derive(thiserror::Error)]
pub enum PasskeyError {
    #[error("invalid protected passkey metadata")]
    Metadata(#[source] JsonDiagnostic),
    #[error("passkeys require a personal client-encrypted vault")]
    Vault(#[source] zann_core::ServiceError),
    #[error("invalid passkey payload")]
    Payload,
    #[error("invalid passkey input or resource bound")]
    Input,
    #[error("unsupported passkey algorithm")]
    Algorithm,
    #[error("explicit per-ceremony user presence is required")]
    Presence,
    #[error("user verification is required")]
    Verification,
    #[error("credential is excluded")]
    Excluded,
    #[error("no matching passkey credential")]
    NoCredential,
    #[error("passkey origin admission failed")]
    Origin(#[source] zann_autofill::AutofillError),
    #[error("passkey cryptography failed")]
    Crypto(#[source] zann_crypto::es256::Es256Error),
    #[error("invalid passkey encoding")]
    Base64(#[source] base64::DecodeSliceError),
    #[error("invalid passkey creation time")]
    Time(#[source] chrono::ParseError),
    #[error("passkey response encoding failed")]
    Cbor(#[source] ciborium::ser::Error<std::io::Error>),
}

impl std::fmt::Debug for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Retains the original parser error and its location, without formatting input.
pub struct JsonDiagnostic(serde_json::Error);
impl From<serde_json::Error> for JsonDiagnostic {
    fn from(error: serde_json::Error) -> Self {
        Self(error)
    }
}
impl std::fmt::Display for JsonDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid JSON at line {}, column {} ({:?})",
            self.0.line(),
            self.0.column(),
            self.0.classify()
        )
    }
}
impl std::fmt::Debug for JsonDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for JsonDiagnostic {}
