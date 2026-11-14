use super::*;
use std::collections::HashSet;
use std::error::Error;

fn sequence(values: &[u32]) -> impl FnMut(&mut [u8]) -> Result<(), getrandom::Error> + '_ {
    let mut values = values.iter().cycle();
    move |bytes| {
        bytes.copy_from_slice(&values.next().unwrap().to_le_bytes());
        Ok(())
    }
}

#[test]
fn every_nonempty_class_combination_satisfies_its_contract_at_both_bounds() {
    for classes in 1..16 {
        for length in [MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH] {
            for avoid_ambiguous in [false, true] {
                let options = PasswordOptions {
                    length,
                    lowercase: classes & 1 != 0,
                    uppercase: classes & 2 != 0,
                    digits: classes & 4 != 0,
                    symbols: classes & 8 != 0,
                    avoid_ambiguous,
                };
                let result = password::generate(&options, &mut sequence(&[0, 31, 97, 45])).unwrap();
                let value = result.as_str();
                assert_eq!(value.len(), length as usize);
                assert_eq!(
                    value.bytes().any(|c| c.is_ascii_lowercase()),
                    options.lowercase
                );
                assert_eq!(
                    value.bytes().any(|c| c.is_ascii_uppercase()),
                    options.uppercase
                );
                assert_eq!(value.bytes().any(|c| c.is_ascii_digit()), options.digits);
                assert_eq!(
                    value
                        .bytes()
                        .any(|c| PASSWORD_SYMBOLS.as_bytes().contains(&c)),
                    options.symbols
                );
                assert!(!avoid_ambiguous || !value.bytes().any(|c| b"IlOilo01".contains(&c)));
            }
        }
    }
}

#[test]
fn invalid_options_are_rejected_before_requesting_entropy() {
    let mut never = |_: &mut [u8]| -> Result<(), getrandom::Error> {
        panic!("invalid policy requested entropy")
    };
    for length in [
        0,
        MIN_PASSWORD_LENGTH - 1,
        MAX_PASSWORD_LENGTH + 1,
        u32::MAX,
    ] {
        let options = PasswordOptions {
            length,
            ..PasswordOptions::default()
        };
        assert!(matches!(
            password::generate(&options, &mut never),
            Err(GeneratorError::PasswordLength)
        ));
    }
    let options = PasswordOptions {
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: false,
        ..PasswordOptions::default()
    };
    assert!(matches!(
        password::generate(&options, &mut never),
        Err(GeneratorError::EmptyAlphabet)
    ));
    for word_count in [0, MIN_WORDS - 1, MAX_WORDS + 1, u32::MAX] {
        let options = PassphraseOptions {
            word_count,
            ..PassphraseOptions::default()
        };
        assert!(matches!(
            passphrase::generate(&options, &mut never),
            Err(GeneratorError::WordCount)
        ));
    }
}

#[test]
fn validation_errors_have_translations_in_every_shared_catalogue() {
    for error in [
        GeneratorError::PasswordLength,
        GeneratorError::EmptyAlphabet,
        GeneratorError::WordCount,
    ] {
        let key = error.translation_key().unwrap();
        for (language, _) in crate::LANGUAGES {
            assert!(crate::Catalogue::new(language).has(key));
        }
    }
    assert!(GeneratorError::Randomness(getrandom::Error::UNSUPPORTED)
        .translation_key()
        .is_none());
}

#[test]
fn entropy_failure_preserves_the_source_and_never_returns_a_partial_secret() {
    let mut failure = |_: &mut [u8]| Err(getrandom::Error::UNSUPPORTED);
    let error = password::generate(&PasswordOptions::default(), &mut failure).unwrap_err();
    assert!(matches!(error, GeneratorError::Randomness(_)));
    assert!(error
        .source()
        .unwrap()
        .downcast_ref::<getrandom::Error>()
        .is_some());
    let mut calls = 0;
    let mut late_failure = |bytes: &mut [u8]| {
        calls += 1;
        if calls == 3 {
            Err(getrandom::Error::UNSUPPORTED)
        } else {
            bytes.fill(0);
            Ok(())
        }
    };
    assert!(matches!(
        passphrase::generate(&PassphraseOptions::default(), &mut late_failure),
        Err(GeneratorError::Randomness(_))
    ));
    assert_eq!(calls, 3);
}

#[test]
fn sampling_rejects_incomplete_buckets_and_accepts_their_boundary() {
    // 2^32 mod 10 = 6: 4294967290..=MAX must be discarded.
    assert_eq!(
        random::index(10, &mut sequence(&[u32::MAX, 4_294_967_290, 4_294_967_289])).unwrap(),
        9
    );
    // Power-of-two bounds have no discarded bucket, including MAX.
    assert_eq!(random::index(128, &mut sequence(&[u32::MAX])).unwrap(), 127);
    assert!(matches!(
        random::index(7776, &mut sequence(&[u32::MAX])),
        Err(GeneratorError::RandomnessRejected)
    ));
}

#[test]
fn dictionary_has_all_dice_codes_and_7776_unique_nonempty_ascii_words() {
    let text = include_str!("eff_large_wordlist.txt");
    let mut words = HashSet::new();
    for (index, line) in text.lines().enumerate() {
        let (code, word) = line.split_once('\t').unwrap();
        let mut value = index;
        let mut expected = [b'1'; 5];
        for digit in expected.iter_mut().rev() {
            *digit += (value % 6) as u8;
            value /= 6;
        }
        assert_eq!(code.as_bytes(), expected);
        assert!(!word.is_empty() && word.bytes().all(|c| c.is_ascii_lowercase() || c == b'-'));
        assert!(word.as_bytes()[0].is_ascii_lowercase());
        assert!(WORD_SEPARATORS
            .iter()
            .all(|separator| !word.contains(separator.as_str())));
        assert!(words.insert(word));
    }
    assert_eq!(words.len(), 7776);
}

#[test]
fn passphrase_draws_reach_both_ends_of_the_dictionary_and_allow_repeats() {
    let value =
        passphrase::generate(&PassphraseOptions::default(), &mut sequence(&[0, 7775])).unwrap();
    assert_eq!(value.as_str(), "abacus zoom abacus zoom abacus zoom");
}

#[test]
fn passphrase_formatting_preserves_full_words_and_exact_count() {
    for word_count in [MIN_WORDS, MAX_WORDS] {
        for separator in WORD_SEPARATORS {
            let options = PassphraseOptions {
                word_count,
                separator: *separator,
                capitalize: true,
                include_digit: true,
            };
            let value = passphrase::generate(&options, &mut sequence(&[0])).unwrap();
            let words: Vec<_> = value.as_str().split(separator.as_str()).collect();
            assert_eq!(words.len(), word_count as usize);
            assert_eq!(words[0], "Abacus0");
            assert!(words[1..].iter().all(|word| *word == "Abacus"));
        }
    }
}

#[test]
fn generated_secrets_redact_debug_and_can_transfer_custody() {
    let value = password::generate(&PasswordOptions::default(), &mut sequence(&[0])).unwrap();
    assert_eq!(format!("{value:?}"), "GeneratedSecret(<redacted>)");
    let expected = value.as_str().to_string();
    assert_eq!(value.into_string(), expected);
}

#[test]
fn public_entry_points_use_os_entropy() {
    assert!(generate_password(&PasswordOptions::default()).is_ok());
    assert!(generate_passphrase(&PassphraseOptions::default()).is_ok());
}
