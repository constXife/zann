use zann_ui_core::item_editor::{MatchMode, MatchRules};

use super::ItemDraftFfi;
use crate::CoreResult;

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MatchModeFfi {
    RegistrableDomain,
    Host,
    Exact,
    Regex,
    Never,
}

impl From<MatchMode> for MatchModeFfi {
    fn from(value: MatchMode) -> Self {
        match value {
            MatchMode::RegistrableDomain => Self::RegistrableDomain,
            MatchMode::Host => Self::Host,
            MatchMode::Exact => Self::Exact,
            MatchMode::Regex => Self::Regex,
            MatchMode::Never => Self::Never,
        }
    }
}

impl From<MatchModeFfi> for MatchMode {
    fn from(value: MatchModeFfi) -> Self {
        match value {
            MatchModeFfi::RegistrableDomain => Self::RegistrableDomain,
            MatchModeFfi::Host => Self::Host,
            MatchModeFfi::Exact => Self::Exact,
            MatchModeFfi::Regex => Self::Regex,
            MatchModeFfi::Never => Self::Never,
        }
    }
}

#[derive(Clone, uniffi::Record)]
pub struct LoginMatchRulesFfi {
    pub mode: MatchModeFfi,
    pub pattern: String,
}

impl std::fmt::Debug for LoginMatchRulesFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginMatchRulesFfi(<redacted>)")
    }
}

#[uniffi::export]
impl ItemDraftFfi {
    pub fn login_match_rules(&self) -> CoreResult<Option<LoginMatchRulesFfi>> {
        Ok(self
            .0
            .lock()
            .expect("lock poisoned")
            .login_match_rules()?
            .map(|rules| LoginMatchRulesFfi {
                mode: rules.mode().into(),
                pattern: rules.pattern().into(),
            }))
    }

    pub fn set_login_match_rules(&self, rules: LoginMatchRulesFfi) -> CoreResult<()> {
        Ok(self
            .0
            .lock()
            .expect("lock poisoned")
            .set_login_match_rules(MatchRules::with_mode(rules.mode.into(), rules.pattern))?)
    }
}
