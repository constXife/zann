//! Client password and passphrase policy. No IO, storage or shell state other
//! than fallible OS entropy. Server-managed rotation policies are a separate
//! server capability and do not depend on presentation.

mod passphrase;
mod password;
mod random;

pub use passphrase::{PassphraseOptions, WordSeparator, MAX_WORDS, MIN_WORDS, WORD_SEPARATORS};
pub use password::{PasswordOptions, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, PASSWORD_SYMBOLS};
use zeroize::Zeroizing;

/// A generated value must not appear in message/debug logs. Taking the String
/// transfers secret custody to the editor or FFI caller.
pub struct GeneratedSecret(Zeroizing<String>);

impl GeneratedSecret {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl std::fmt::Debug for GeneratedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GeneratedSecret(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GeneratorError {
    #[error("password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}")]
    PasswordLength,
    #[error("select at least one password character class")]
    EmptyAlphabet,
    #[error("passphrase word count must be between {MIN_WORDS} and {MAX_WORDS}")]
    WordCount,
    #[error("OS randomness unavailable: {0}")]
    Randomness(#[source] getrandom::Error),
    #[error("OS randomness exceeded the rejection sampling limit")]
    RandomnessRejected,
}

impl GeneratorError {
    /// Validation is translated by the shell. Entropy failures retain their
    /// diagnostic message, including the original OS source.
    pub fn translation_key(&self) -> Option<&'static str> {
        match self {
            Self::PasswordLength => Some("errors.generatorPasswordLength"),
            Self::EmptyAlphabet => Some("errors.generatorEmptyAlphabet"),
            Self::WordCount => Some("errors.generatorWordCount"),
            Self::Randomness(_) | Self::RandomnessRejected => None,
        }
    }
}

/// Every selected class occurs at least once. Remaining characters are drawn
/// from their union and the result is shuffled. Individual draws are unbiased;
/// this does not claim uniformity over all strings satisfying the policy.
pub fn generate_password(options: &PasswordOptions) -> Result<GeneratedSecret, GeneratorError> {
    password::generate(options, &mut getrandom::getrandom)
}

/// Words are independent, uniform draws with replacement from the bundled EFF
/// Long Wordlist (7776 words). Six words carry about 77.5 bits of word entropy.
/// Case, separator and optional digit never replace or truncate a word.
pub fn generate_passphrase(options: &PassphraseOptions) -> Result<GeneratedSecret, GeneratorError> {
    passphrase::generate(options, &mut getrandom::getrandom)
}

#[cfg(test)]
mod tests;
