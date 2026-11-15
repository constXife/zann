//! Ceremony-managed credentials expose only profile-admitted public fields.
//! Shell metadata cannot override the canonical security profile.
use std::sync::OnceLock;
use zann_core::{item_policy::ceremony_managed, SecurityProfileRegistry};

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

pub(crate) fn ensure_editable(type_id: &str) -> Result<(), crate::item_editor::DraftError> {
    if ceremony_managed(type_id) {
        return Err(crate::item_editor::DraftError::CeremonyManaged);
    }
    Ok(())
}
