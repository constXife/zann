use zann_ffi::*;
use zann_ui_core::generator as shared;

#[test]
fn ffi_defaults_and_bounds_are_the_shared_policy() {
    let config = generator_defaults();
    assert_eq!(
        shared::PasswordOptions::from(config.password),
        shared::PasswordOptions::default()
    );
    assert_eq!(
        shared::PassphraseOptions::from(config.passphrase),
        shared::PassphraseOptions::default()
    );
    assert_eq!(config.min_password_length, shared::MIN_PASSWORD_LENGTH);
    assert_eq!(config.max_password_length, shared::MAX_PASSWORD_LENGTH);
    assert_eq!(config.min_words, shared::MIN_WORDS);
    assert_eq!(config.max_words, shared::MAX_WORDS);
    let separators: Vec<_> = config
        .separators
        .into_iter()
        .map(shared::WordSeparator::from)
        .collect();
    assert_eq!(separators, shared::WORD_SEPARATORS);
}

#[test]
fn ffi_generation_uses_supplied_options_and_preserves_typed_errors() {
    let mut options = generator_defaults().password;
    options.length = 128;
    options.lowercase = false;
    options.uppercase = false;
    options.symbols = false;
    options.digits = true;
    options.avoid_ambiguous = true;
    let value = generate_password(options.clone()).unwrap();
    assert_eq!(value.len(), 128);
    assert!(value.bytes().all(|c| (b'2'..=b'9').contains(&c)));
    options.digits = false;
    let Err(CoreError::Generator {
        kind,
        translation_key,
        ..
    }) = generate_password(options)
    else {
        panic!("empty alphabet must return a typed generator error")
    };
    assert_eq!(kind, GeneratorErrorKindFfi::EmptyAlphabet);
    assert_eq!(
        translation_key.as_deref(),
        shared::GeneratorError::EmptyAlphabet.translation_key()
    );
    let mut options = generator_defaults().passphrase;
    options.separator = WordSeparatorFfi::Space;
    options.word_count = 8;
    let value = generate_passphrase(options.clone()).unwrap();
    assert_eq!(value.split(' ').count(), 8);
    options.word_count = u32::MAX;
    assert!(matches!(
        generate_passphrase(options),
        Err(CoreError::Generator {
            kind: GeneratorErrorKindFfi::WordCount,
            ..
        })
    ));
}
