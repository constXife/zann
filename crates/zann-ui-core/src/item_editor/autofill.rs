//! Typed editor operations over the one canonical encrypted match_rules field.
pub use zann_autofill::{MatchMode, MatchRules, MATCH_RULES_KEY};

use super::{DraftError, DraftField, ItemDraft};

impl ItemDraft {
    pub fn login_match_rules(&self) -> Result<Option<MatchRules>, DraftError> {
        if self.type_id != "login" {
            return Ok(None);
        }
        MatchRules::from_field(
            self.fields
                .iter()
                .find(|f| f.key == MATCH_RULES_KEY)
                .map(|f| &f.value),
        )
        .map(Some)
        .map_err(DraftError::Autofill)
    }

    /// Accept incomplete regex input while typing; save is the validation gate.
    pub fn set_login_match_rules(&mut self, rules: MatchRules) -> Result<(), DraftError> {
        if self.type_id != "login" {
            return Err(DraftError::Type);
        }
        if let Some(field) = self.fields.iter_mut().find(|f| f.key == MATCH_RULES_KEY) {
            field.value = rules.field();
        } else {
            self.fields.push(DraftField {
                key: MATCH_RULES_KEY.into(),
                value: rules.field(),
            });
        }
        Ok(())
    }

    pub(super) fn validate_match_rules(&self) -> Result<(), DraftError> {
        if let Some(rules) = self.login_match_rules()? {
            rules.validate().map_err(DraftError::Autofill)?;
        }
        Ok(())
    }
}
