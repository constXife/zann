use std::sync::OnceLock;
use zeroize::Zeroizing;

use super::{random, GeneratedSecret, GeneratorError};

pub const MIN_WORDS: u32 = 4;
pub const MAX_WORDS: u32 = 20;
pub const WORD_SEPARATORS: &[WordSeparator] = &[
    WordSeparator::Space,
    WordSeparator::Period,
    WordSeparator::Underscore,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordSeparator {
    Space,
    Period,
    Underscore,
}

impl WordSeparator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Space => " ",
            Self::Period => ".",
            Self::Underscore => "_",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub word_count: u32,
    pub separator: WordSeparator,
    pub capitalize: bool,
    pub include_digit: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            word_count: 6,
            separator: WordSeparator::Space,
            capitalize: false,
            include_digit: false,
        }
    }
}

impl PassphraseOptions {
    pub fn validate(&self) -> Result<(), GeneratorError> {
        if !(MIN_WORDS..=MAX_WORDS).contains(&self.word_count) {
            return Err(GeneratorError::WordCount);
        }
        Ok(())
    }
}

struct Dictionary {
    words: Vec<&'static str>,
    max_word_bytes: usize,
}

fn dictionary() -> &'static Dictionary {
    static DICTIONARY: OnceLock<Dictionary> = OnceLock::new();
    DICTIONARY.get_or_init(|| {
        let words: Vec<_> = include_str!("eff_large_wordlist.txt")
            .lines()
            .map(|line| line.split_once('\t').expect("bundled EFF wordlist row").1)
            .collect();
        let max_word_bytes = words
            .iter()
            .map(|word| word.len())
            .max()
            .expect("bundled EFF words");
        Dictionary {
            words,
            max_word_bytes,
        }
    })
}

pub(super) fn generate(
    options: &PassphraseOptions,
    entropy: &mut random::Entropy<'_>,
) -> Result<GeneratedSecret, GeneratorError> {
    options.validate()?;
    let dictionary = dictionary();
    let digit_word = if options.include_digit {
        Some(random::index(options.word_count as usize, entropy)?)
    } else {
        None
    };
    // Reserve the entire upper bound before holding secrets: String growth
    // would otherwise leave unwiped copies in freed allocations.
    let capacity = options.word_count as usize
        * (dictionary.max_word_bytes + options.separator.as_str().len())
        + usize::from(options.include_digit);
    let mut result = Zeroizing::new(String::with_capacity(capacity));
    for index in 0..options.word_count as usize {
        if index != 0 {
            result.push_str(options.separator.as_str());
        }
        let word = dictionary.words[random::index(dictionary.words.len(), entropy)?];
        if options.capitalize {
            // Words start with lowercase ASCII (including four hyphenated entries).
            result.push(char::from(word.as_bytes()[0].to_ascii_uppercase()));
            result.push_str(&word[1..]);
        } else {
            result.push_str(word);
        }
        if digit_word == Some(index) {
            result.push(char::from(b'0' + random::index(10, entropy)? as u8));
        }
    }
    Ok(GeneratedSecret(result))
}
