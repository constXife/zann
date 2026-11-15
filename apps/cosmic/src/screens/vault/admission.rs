//! Admission shared by native workspace controls.
use super::*;
impl State {
    pub fn can_focus_search(&self) -> bool {
        !self.switching_context && self.editor.is_none() && self.history.is_none()
    }
    pub fn can_create(&self) -> bool {
        self.can_focus_search()
            && self.selected_vault_id.is_some()
            && !self.busy
            && !self.searching
            && !self
                .selected_category()
                .as_deref()
                .and_then(zann_ui_core::category)
                .is_some_and(|category| category.is_trash())
    }
    pub fn can_edit(&self) -> bool {
        self.can_focus_search() && !self.busy && !self.searching && self.detail_ready()
    }
}
