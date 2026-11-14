use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use zann_core::secrets::{FieldKind, FieldValue};

use crate::AutofillError;

pub const MATCH_RULES_KEY: &str = "match_rules";
const MAX_RULE_BYTES: usize = 4096;

/// These five modes are the sole catalogue used by presentation adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchMode {
    RegistrableDomain,
    Host,
    Exact,
    Regex,
    Never,
}

impl MatchMode {
    pub const ALL: [Self; 5] = [
        Self::RegistrableDomain,
        Self::Host,
        Self::Exact,
        Self::Regex,
        Self::Never,
    ];

    pub fn translation_key(self) -> &'static str {
        match self {
            Self::RegistrableDomain => "autofill.registrableDomain",
            Self::Host => "autofill.host",
            Self::Exact => "autofill.exact",
            Self::Regex => "autofill.regex",
            Self::Never => "autofill.never",
        }
    }
}

#[derive(Clone, Default, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum MatchRules {
    #[default]
    RegistrableDomain,
    Host,
    Exact,
    Regex {
        pattern: String,
    },
    Never,
}

// Serde's internally tagged unit variants ignore unknown fields even with
// deny_unknown_fields. A strict struct also rejects duplicate keys and lets us
// forbid pattern on modes for which it has no meaning.
impl<'de> Deserialize<'de> for MatchRules {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        fn present_pattern<'de, D: serde::Deserializer<'de>>(
            decoder: D,
        ) -> Result<Option<String>, D::Error> {
            String::deserialize(decoder).map(Some)
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            mode: MatchMode,
            #[serde(default, deserialize_with = "present_pattern")]
            pattern: Option<String>,
        }
        let wire = Wire::deserialize(decoder)?;
        match (wire.mode, wire.pattern) {
            (MatchMode::Regex, Some(pattern)) => Ok(Self::Regex { pattern }),
            (MatchMode::Regex, None) => Err(serde::de::Error::missing_field("pattern")),
            (_, Some(_)) => Err(serde::de::Error::custom("pattern requires regex mode")),
            (mode, None) => Ok(Self::with_mode(mode, String::new())),
        }
    }
}

impl std::fmt::Debug for MatchRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MatchRules").field(&self.mode()).finish()
    }
}

impl MatchRules {
    /// Absence alone means the documented domain default for existing logins.
    /// Malformed, empty or future rules never downgrade to that default.
    pub fn from_field(field: Option<&FieldValue>) -> Result<Self, AutofillError> {
        let Some(field) = field else {
            return Ok(Self::default());
        };
        if field.kind != FieldKind::Text || field.value.len() > MAX_RULE_BYTES {
            return Err(AutofillError::RulesField);
        }
        serde_json::from_str(&field.value).map_err(AutofillError::Rules)
    }

    pub fn field(&self) -> FieldValue {
        FieldValue {
            kind: FieldKind::Text,
            value: serde_json::to_string(self).expect("MatchRules serializes"),
            meta: None,
        }
    }

    pub fn mode(&self) -> MatchMode {
        match self {
            Self::RegistrableDomain => MatchMode::RegistrableDomain,
            Self::Host => MatchMode::Host,
            Self::Exact => MatchMode::Exact,
            Self::Regex { .. } => MatchMode::Regex,
            Self::Never => MatchMode::Never,
        }
    }

    pub fn pattern(&self) -> &str {
        match self {
            Self::Regex { pattern } => pattern,
            _ => "",
        }
    }

    pub fn with_mode(mode: MatchMode, pattern: String) -> Self {
        match mode {
            MatchMode::RegistrableDomain => Self::RegistrableDomain,
            MatchMode::Host => Self::Host,
            MatchMode::Exact => Self::Exact,
            MatchMode::Regex => Self::Regex { pattern },
            MatchMode::Never => Self::Never,
        }
    }

    pub fn validate(&self) -> Result<(), AutofillError> {
        self.compile_regex().map(|_| ())
    }

    pub(crate) fn compile_regex(&self) -> Result<Option<Regex>, AutofillError> {
        let Self::Regex { pattern } = self else {
            return Ok(None);
        };
        if pattern.is_empty() || pattern.len() > 2048 {
            return Err(AutofillError::RegexSize);
        }
        let compile = |source: &str| {
            RegexBuilder::new(source)
                .size_limit(256 * 1024)
                .dfa_size_limit(256 * 1024)
                .nest_limit(32)
                .build()
                .map_err(AutofillError::Regex)
        };
        // Validate standalone syntax first: unmatched parentheses must not
        // escape the wrapper and turn the anchors into a different alternation.
        compile(pattern)?;
        compile(&format!(r"\A(?:{pattern})\z")).map(Some)
    }
}
