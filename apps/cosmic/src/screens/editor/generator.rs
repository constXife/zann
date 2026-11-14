//! Generator controls only; all defaults, validation and randomness are shared.
use cosmic::{theme, widget, Element};
use zann_ui_core::generator::{
    self, GeneratedSecret, GeneratorError, PassphraseOptions, PasswordOptions,
};

use crate::i18n::t;

#[derive(Default)]
pub(super) struct State {
    passphrase_mode: bool,
    password: PasswordOptions,
    passphrase: PassphraseOptions,
}

#[derive(Clone, Debug)]
pub enum Message {
    Mode(bool),
    Length(u32),
    Lowercase(bool),
    Uppercase(bool),
    Digits(bool),
    Symbols(bool),
    AvoidAmbiguous(bool),
    Words(u32),
    Separator(usize),
    Capitalize(bool),
    IncludeDigit(bool),
    Generate,
}

impl State {
    pub(super) fn update(&mut self, message: Message) {
        match message {
            Message::Mode(value) => self.passphrase_mode = value,
            Message::Length(value) => self.password.length = value,
            Message::Lowercase(value) => self.password.lowercase = value,
            Message::Uppercase(value) => self.password.uppercase = value,
            Message::Digits(value) => self.password.digits = value,
            Message::Symbols(value) => self.password.symbols = value,
            Message::AvoidAmbiguous(value) => self.password.avoid_ambiguous = value,
            Message::Words(value) => self.passphrase.word_count = value,
            Message::Separator(index) => {
                if let Some(separator) = generator::WORD_SEPARATORS.get(index) {
                    self.passphrase.separator = *separator;
                }
            }
            Message::Capitalize(value) => self.passphrase.capitalize = value,
            Message::IncludeDigit(value) => self.passphrase.include_digit = value,
            Message::Generate => {}
        }
    }

    pub(super) fn generate(&self) -> Result<GeneratedSecret, GeneratorError> {
        if self.passphrase_mode {
            generator::generate_passphrase(&self.passphrase)
        } else {
            generator::generate_password(&self.password)
        }
    }

    pub(super) fn view(&self) -> Element<'_, Message> {
        let mut controls = widget::column::with_capacity(10)
            .spacing(theme::spacing().space_xs)
            .push(widget::text::heading(t("create.generatorTitle")))
            .push(
                widget::checkbox(self.passphrase_mode)
                    .label(t("create.generatorPassphrase"))
                    .on_toggle(Message::Mode),
            );
        if self.passphrase_mode {
            controls = controls
                .push(widget::text(format!(
                    "{}: {}",
                    t("create.generatorWords"),
                    self.passphrase.word_count
                )))
                .push(widget::slider(
                    generator::MIN_WORDS..=generator::MAX_WORDS,
                    self.passphrase.word_count,
                    Message::Words,
                ))
                .push(widget::text::caption(t("create.generatorSeparator")))
                .push(widget::dropdown(
                    generator::WORD_SEPARATORS
                        .iter()
                        .map(|separator| {
                            if *separator == generator::WordSeparator::Space {
                                t("create.generatorSpace")
                            } else {
                                separator.as_str().to_string()
                            }
                        })
                        .collect::<Vec<_>>(),
                    generator::WORD_SEPARATORS
                        .iter()
                        .position(|separator| *separator == self.passphrase.separator),
                    Message::Separator,
                ))
                .push(
                    widget::checkbox(self.passphrase.capitalize)
                        .label(t("create.generatorCapitalize"))
                        .on_toggle(Message::Capitalize),
                )
                .push(
                    widget::checkbox(self.passphrase.include_digit)
                        .label(t("create.generatorAddDigit"))
                        .on_toggle(Message::IncludeDigit),
                );
        } else {
            controls = controls
                .push(widget::text(format!(
                    "{}: {}",
                    t("create.generatorLength"),
                    self.password.length
                )))
                .push(widget::slider(
                    generator::MIN_PASSWORD_LENGTH..=generator::MAX_PASSWORD_LENGTH,
                    self.password.length,
                    Message::Length,
                ))
                .push(
                    widget::checkbox(self.password.lowercase)
                        .label(t("create.generatorLower"))
                        .on_toggle(Message::Lowercase),
                )
                .push(
                    widget::checkbox(self.password.uppercase)
                        .label(t("create.generatorUpper"))
                        .on_toggle(Message::Uppercase),
                )
                .push(
                    widget::checkbox(self.password.digits)
                        .label(t("create.generatorDigits"))
                        .on_toggle(Message::Digits),
                )
                .push(
                    widget::checkbox(self.password.symbols)
                        .label(t("create.generatorSymbols"))
                        .on_toggle(Message::Symbols),
                )
                .push(
                    widget::checkbox(self.password.avoid_ambiguous)
                        .label(t("create.generatorAvoidAmbiguous"))
                        .on_toggle(Message::AvoidAmbiguous),
                );
        }
        controls
            .push(widget::button::standard(t("create.generateSecret")).on_press(Message::Generate))
            .into()
    }
}
