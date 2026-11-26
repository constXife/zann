//! Domain restrictions shared by storage, ceremonies and presentation.
use crate::{
    FieldKind, SecurityProfileRegistry, ServiceError, ServiceResult, VaultEncryptionType, VaultKind,
};
use std::sync::OnceLock;

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

pub fn ceremony_field_visible(type_id: &str, key: &str) -> bool {
    if !ceremony_managed(type_id) {
        return true;
    }
    static PROFILES: OnceLock<SecurityProfileRegistry> = OnceLock::new();
    let profiles = PROFILES.get_or_init(|| {
        SecurityProfileRegistry::from_yaml(include_str!("../../../schemas/security_profiles.yaml"))
            .expect("embedded security profiles must validate")
    });
    profiles.profile(type_id).is_some_and(|profile| {
        profile
            .exposable_public_attrs
            .iter()
            .any(|name| name == key)
    })
}

/// Label used by the native reading view, including its one-time-code projection.
pub fn field_label_key(kind: FieldKind, key: &str) -> &str {
    if kind == FieldKind::Otp {
        "otp"
    } else {
        key
    }
}
