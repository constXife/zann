//! One-to-one projection of the shared client generator, without shell policy.
use zann_ui_core::generator::{
    self, GeneratorError, PassphraseOptions, PasswordOptions, WordSeparator,
};

use crate::{CoreError, CoreResult};

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PasswordOptionsFfi {
    pub length: u32,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl From<PasswordOptions> for PasswordOptionsFfi {
    fn from(value: PasswordOptions) -> Self {
        Self {
            length: value.length,
            lowercase: value.lowercase,
            uppercase: value.uppercase,
            digits: value.digits,
            symbols: value.symbols,
            avoid_ambiguous: value.avoid_ambiguous,
        }
    }
}

impl From<PasswordOptionsFfi> for PasswordOptions {
    fn from(value: PasswordOptionsFfi) -> Self {
        Self {
            length: value.length,
            lowercase: value.lowercase,
            uppercase: value.uppercase,
            digits: value.digits,
            symbols: value.symbols,
            avoid_ambiguous: value.avoid_ambiguous,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum WordSeparatorFfi {
    Space,
    Period,
    Underscore,
}

impl From<WordSeparatorFfi> for WordSeparator {
    fn from(value: WordSeparatorFfi) -> Self {
        match value {
            WordSeparatorFfi::Space => Self::Space,
            WordSeparatorFfi::Period => Self::Period,
            WordSeparatorFfi::Underscore => Self::Underscore,
        }
    }
}

impl From<WordSeparator> for WordSeparatorFfi {
    fn from(value: WordSeparator) -> Self {
        match value {
            WordSeparator::Space => Self::Space,
            WordSeparator::Period => Self::Period,
            WordSeparator::Underscore => Self::Underscore,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PassphraseOptionsFfi {
    pub word_count: u32,
    pub separator: WordSeparatorFfi,
    pub capitalize: bool,
    pub include_digit: bool,
}

impl From<PassphraseOptions> for PassphraseOptionsFfi {
    fn from(value: PassphraseOptions) -> Self {
        Self {
            word_count: value.word_count,
            separator: value.separator.into(),
            capitalize: value.capitalize,
            include_digit: value.include_digit,
        }
    }
}

impl From<PassphraseOptionsFfi> for PassphraseOptions {
    fn from(value: PassphraseOptionsFfi) -> Self {
        Self {
            word_count: value.word_count,
            separator: value.separator.into(),
            capitalize: value.capitalize,
            include_digit: value.include_digit,
        }
    }
}

/// All defaults and bounds come from the canonical owner, including UI ranges.
#[derive(Clone, Debug, uniffi::Record)]
pub struct GeneratorDefaultsFfi {
    pub password: PasswordOptionsFfi,
    pub passphrase: PassphraseOptionsFfi,
    pub min_password_length: u32,
    pub max_password_length: u32,
    pub min_words: u32,
    pub max_words: u32,
    pub separators: Vec<WordSeparatorFfi>,
}

#[uniffi::export]
pub fn generator_defaults() -> GeneratorDefaultsFfi {
    GeneratorDefaultsFfi {
        password: PasswordOptions::default().into(),
        passphrase: PassphraseOptions::default().into(),
        min_password_length: generator::MIN_PASSWORD_LENGTH,
        max_password_length: generator::MAX_PASSWORD_LENGTH,
        min_words: generator::MIN_WORDS,
        max_words: generator::MAX_WORDS,
        separators: generator::WORD_SEPARATORS
            .iter()
            .copied()
            .map(Into::into)
            .collect(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum GeneratorErrorKindFfi {
    PasswordLength,
    EmptyAlphabet,
    WordCount,
    Randomness,
    RandomnessRejected,
}

fn error(value: GeneratorError) -> CoreError {
    let kind = match &value {
        GeneratorError::PasswordLength => GeneratorErrorKindFfi::PasswordLength,
        GeneratorError::EmptyAlphabet => GeneratorErrorKindFfi::EmptyAlphabet,
        GeneratorError::WordCount => GeneratorErrorKindFfi::WordCount,
        GeneratorError::Randomness(_) => GeneratorErrorKindFfi::Randomness,
        GeneratorError::RandomnessRejected => GeneratorErrorKindFfi::RandomnessRejected,
    };
    // Display includes the original OS error; no generated value crosses errors.
    CoreError::Generator {
        kind,
        translation_key: value.translation_key().map(str::to_string),
        message: value.to_string(),
    }
}

#[uniffi::export]
pub fn generate_password(options: PasswordOptionsFfi) -> CoreResult<String> {
    generator::generate_password(&options.into())
        .map(|value| value.into_string())
        .map_err(error)
}

#[uniffi::export]
pub fn generate_passphrase(options: PassphraseOptionsFfi) -> CoreResult<String> {
    generator::generate_passphrase(&options.into())
        .map(|value| value.into_string())
        .map_err(error)
}

/// Rendering a separator is presentation policy too (not Swift punctuation).
#[uniffi::export]
pub fn word_separator_text(separator: WordSeparatorFfi) -> String {
    WordSeparator::from(separator).as_str().to_string()
}
