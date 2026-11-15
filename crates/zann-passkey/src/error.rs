#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
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
