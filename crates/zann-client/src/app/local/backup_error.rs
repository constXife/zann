//! Stable, value-free archive diagnoses shared by every native client.
#[derive(Debug, thiserror::Error)]
pub enum BackupFailure {
    #[error("The backup operation is no longer available. Start again.")]
    HandleInvalid,
    #[error("The vault session changed. Start the backup operation again.")]
    SessionChanged,
    #[error("Choose a destination file for the encrypted backup.")]
    DestinationRequired,
    #[error("This backup operation cannot perform the requested action. Start again.")]
    HandleKind,
    #[error("Add a recovery passphrase or a security key before saving. Biometrics alone cannot open a backup on another device.")]
    PortableRecipientRequired,
    #[error("The device biometric backup key changed. Start again.")]
    BiometricKeyChanged,
    #[error("The device biometric backup key is invalid. Use a portable unlock method.")]
    BiometricKeyInvalid,
    #[error("This device no longer has the archive's biometric key. Use its recovery passphrase or security key.")]
    BiometricKeyMissing,
    #[error("Biometric backup access is not available on this device.")]
    BiometricsUnavailable,
    #[error("This unlock method is already included in the backup.")]
    RecipientDuplicate,
    #[error("The unlock method has invalid or conflicting verification options.")]
    RecipientInvalid,
    #[error("The backup has reached its unlock-method limit.")]
    RecipientLimit,
    #[error("Choose the unlock method matching the selected archive slot.")]
    RecipientMismatch,
    #[error("The new wrapped key failed verification. No backup was published.")]
    WrapVerification,
    #[error("The selected unlock method is absent from this archive.")]
    RecipientMissing,
}
impl BackupFailure {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::HandleInvalid => "backup_handle_invalid",
            Self::SessionChanged => "backup_session_changed",
            Self::DestinationRequired => "backup_destination_required",
            Self::HandleKind => "backup_handle_kind",
            Self::PortableRecipientRequired => "backup_portable_recipient_required",
            Self::BiometricKeyChanged => "backup_biometric_key_changed",
            Self::BiometricKeyInvalid => "backup_biometric_key_invalid",
            Self::BiometricKeyMissing => "backup_biometric_key_missing",
            Self::BiometricsUnavailable => "backup_biometrics_unavailable",
            Self::RecipientDuplicate => "backup_recipient_duplicate",
            Self::RecipientInvalid => "backup_recipient_invalid",
            Self::RecipientLimit => "backup_recipient_limit",
            Self::RecipientMismatch => "backup_recipient_mismatch",
            Self::WrapVerification => "backup_wrap_verification",
            Self::RecipientMissing => "backup_recipient_missing",
        }
    }
}
