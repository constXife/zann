//! Toolkit controls only; rule parsing and validation belong to the shared draft.
use cosmic::{theme, widget, Element};
use zann_ui_core::item_editor::{MatchMode, MatchRules, MATCH_RULES_KEY};

use super::{Message, State};
use crate::i18n::t;

impl State {
    pub(super) fn is_match_rules_field(&self, key: &str) -> bool {
        key == MATCH_RULES_KEY && matches!(self.draft.login_match_rules(), Ok(Some(_)))
    }

    pub(super) fn update_match_rules(&mut self, mode: Option<MatchMode>, pattern: Option<String>) {
        let result = self.draft.login_match_rules().and_then(|rules| {
            let rules = rules.ok_or(zann_ui_core::item_editor::DraftError::Type)?;
            self.draft.set_login_match_rules(MatchRules::with_mode(
                mode.unwrap_or(rules.mode()),
                pattern.unwrap_or_else(|| rules.pattern().to_string()),
            ))
        });
        match result {
            Ok(()) => {
                self.revealed.resize(self.draft.fields.len(), false);
                self.multiline.resize_with(self.draft.fields.len(), || None);
            }
            Err(error) => self.error = Some(t(error.translation_key())),
        }
    }

    pub(super) fn match_rules_view(&self) -> Option<Element<'_, Message>> {
        let rules = match self.draft.login_match_rules() {
            Ok(Some(rules)) => rules,
            Ok(None) => return None,
            Err(error) => return Some(widget::text::caption(t(error.translation_key())).into()),
        };
        let modes = MatchMode::ALL;
        let labels: Vec<_> = modes.iter().map(|mode| t(mode.translation_key())).collect();
        let selected = modes.iter().position(|mode| *mode == rules.mode());
        let mut controls = widget::column::with_capacity(4)
            .push(widget::text::caption(t("fields.match_rules")))
            .push(widget::dropdown(labels, selected, move |index| {
                Message::MatchMode(modes[index])
            }))
            .spacing(theme::spacing().space_s);
        if rules.mode() == MatchMode::Regex {
            controls = controls.push(
                widget::text_input::text_input(t("autofill.pattern"), rules.pattern().to_string())
                    .on_input(Message::MatchPattern),
            );
        }
        Some(controls.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_edits_shared_rules_and_invalid_regex_blocks_submit() {
        let mut state = State::create("login").unwrap();
        state.update(Message::Path("site".into()));
        state.update(Message::MatchMode(MatchMode::Host));
        assert_eq!(
            state.draft.login_match_rules().unwrap(),
            Some(MatchRules::Host)
        );
        assert!(state.is_match_rules_field(MATCH_RULES_KEY));
        assert_eq!(state.draft.fields.len(), state.revealed.len());
        assert_eq!(state.draft.fields.len(), state.multiline.len());
        state.update(Message::MatchMode(MatchMode::Regex));
        state.update(Message::MatchPattern("(".into()));
        assert!(state.save_request().is_err());
        state.update(Message::MatchPattern(r"https://example\.com/.*".into()));
        assert!(state.save_request().is_ok());
        assert!(
            !format!("{:?}", Message::MatchPattern("private-sentinel".into()))
                .contains("private-sentinel")
        );
    }
}
