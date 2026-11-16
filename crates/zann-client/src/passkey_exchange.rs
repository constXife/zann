//! Offline, file-to-file conversion of already-plaintext external exports.
//! Native vault exports use LocalVaultService's fresh step-up authorization.
use std::{fs::File, path::Path};
pub use zann_passkey::exchange::*;
pub use zann_passkey::{Credential, PASSKEY_TYPE_ID};

pub fn convert_to_cxf(
    input: &Path,
    format: ExchangeFormat,
    output: &Path,
    context: CxfExportContext<'_>,
) -> Result<usize, ExchangeError> {
    let document = import(open_regular_input(input)?, format)?;
    let count = document.credential_count();
    let target = std::path::absolute(output)?;
    let mut writer = crate::private_output::PrivateOutput::create(&target)?;
    write_cxf(&mut writer, &document, context)?;
    writer.seal()?;
    writer.publish()?;
    Ok(count)
}

/// Semantic validation shared by backup, verify and explicit native writes.
pub fn validate_payload(
    type_id: &str,
    payload: &zann_core::EncryptedPayload,
    kind: zann_core::VaultKind,
    encryption: zann_core::VaultEncryptionType,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if type_id == PASSKEY_TYPE_ID || payload.type_id == PASSKEY_TYPE_ID {
        if type_id != payload.type_id {
            return Err(zann_core::ServiceError::new(
                "passkey_type_mismatch",
                "passkey item type mismatch",
            )
            .into());
        }
        zann_core::item_policy::admit_item_type(type_id, kind, encryption)?;
        Credential::from_payload(payload)?;
    }
    Ok(())
}

/// A bounded ordinary file only; Unix opens cannot block on a swapped FIFO.
pub fn open_regular_input(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_EXCHANGE_BYTES as u64 {
        return Err(std::io::Error::other(
            "passkey exchange requires a bounded regular file",
        ));
    }
    Ok(file)
}
