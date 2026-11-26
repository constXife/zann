//! Ceremony-managed credentials expose only profile-admitted public fields.
//! Shell metadata cannot override the canonical security profile.
use zann_core::item_policy::ceremony_managed;

pub(crate) fn ensure_editable(type_id: &str) -> Result<(), crate::item_editor::DraftError> {
    if ceremony_managed(type_id) {
        return Err(crate::item_editor::DraftError::CeremonyManaged);
    }
    Ok(())
}
