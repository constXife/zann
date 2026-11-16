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

/// Public, rebuildable lookup metadata. This does not authorize an RP: provider
/// requests still pass canonical zann-autofill admission and payload validation.
pub fn passkey_rp_projection(payload: &crate::EncryptedPayload) -> Option<&str> {
    (payload.type_id == PASSKEY_TYPE_ID)
        .then(|| payload.fields.get("rp_id"))
        .flatten()
        .filter(|field| field.kind == crate::FieldKind::Text && field.value.len() <= 253)
        .map(|field| field.value.as_str())
}
