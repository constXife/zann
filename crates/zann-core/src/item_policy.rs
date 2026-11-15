//! Domain restrictions shared by storage, ceremonies and presentation.
use crate::{ServiceError, ServiceResult, VaultEncryptionType, VaultKind};

pub const PASSKEY_TYPE_ID: &str = "passkey";
pub const PASSKEY_ALGORITHM: i32 = -7;

pub fn ceremony_managed(type_id: &str) -> bool {
    type_id == PASSKEY_TYPE_ID
}

pub fn admit_item_type(
    type_id: &str,
    kind: VaultKind,
    encryption: VaultEncryptionType,
) -> ServiceResult<()> {
    if ceremony_managed(type_id)
        && (kind != VaultKind::Personal || encryption != VaultEncryptionType::Client)
    {
        return Err(ServiceError::new(
            "passkey_personal_only",
            "passkeys require a personal client-encrypted vault",
        ));
    }
    Ok(())
}
