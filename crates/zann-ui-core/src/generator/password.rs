use super::{random, GeneratedSecret, GeneratorError};
use zeroize::Zeroizing;

pub const MIN_PASSWORD_LENGTH: u32 = 4;
pub const MAX_PASSWORD_LENGTH: u32 = 128;
pub const PASSWORD_SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
const AMBIGUOUS: &[u8] = b"IlOilo01";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: u32,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: false,
            avoid_ambiguous: false,
        }
    }
}

impl PasswordOptions {
    pub fn validate(&self) -> Result<(), GeneratorError> {
        if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&self.length) {
            return Err(GeneratorError::PasswordLength);
        }
        if !(self.lowercase || self.uppercase || self.digits || self.symbols) {
            return Err(GeneratorError::EmptyAlphabet);
        }
        Ok(())
    }
}

pub(super) fn generate(
    options: &PasswordOptions,
    entropy: &mut random::Entropy<'_>,
) -> Result<GeneratedSecret, GeneratorError> {
    options.validate()?;
    let groups: Vec<Vec<u8>> = [
        (options.lowercase, "abcdefghijklmnopqrstuvwxyz"),
        (options.uppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (options.digits, "0123456789"),
        (options.symbols, PASSWORD_SYMBOLS),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, alphabet)| {
        alphabet
            .bytes()
            .filter(|byte| !options.avoid_ambiguous || !AMBIGUOUS.contains(byte))
            .collect()
    })
    .collect();
    let alphabet: Vec<u8> = groups.iter().flatten().copied().collect();
    let mut bytes = Zeroizing::new(Vec::with_capacity(options.length as usize));
    for group in &groups {
        bytes.push(group[random::index(group.len(), entropy)?]);
    }
    while bytes.len() < options.length as usize {
        bytes.push(alphabet[random::index(alphabet.len(), entropy)?]);
    }
    // Fisher-Yates: mandatory characters have no predictable positions.
    for end in (1..bytes.len()).rev() {
        let index = random::index(end + 1, entropy)?;
        bytes.swap(end, index);
    }
    // The alphabets are ASCII; the scratch buffer is wiped on every exit.
    Ok(GeneratedSecret(Zeroizing::new(
        bytes.iter().map(|byte| char::from(*byte)).collect(),
    )))
}
