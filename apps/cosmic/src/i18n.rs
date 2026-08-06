// SPDX-License-Identifier: MIT

//! The app's copy of the shared catalogue.
//!
//! The strings live in `i18n/` at the repo root and reach here through
//! `zann-ui-core`, which is also where the desktop app gets them — so a string
//! added for one client is a string the other can ask for by the same name.
//!
//! The catalogue is process-wide rather than threaded through every `view`.
//! That is what `i18n-embed` does for the COSMIC apps, and for the same reason:
//! a `view` that has to be handed a catalogue to name a button ends up carrying
//! one through every widget that has nothing else to do with language.

use std::sync::{OnceLock, RwLock};

use zann_ui_core::i18n::Catalogue;

fn catalogue() -> &'static RwLock<Catalogue> {
    static CATALOGUE: OnceLock<RwLock<Catalogue>> = OnceLock::new();
    CATALOGUE.get_or_init(|| RwLock::new(Catalogue::from_env()))
}

/// Switches language for everything drawn from here on. `None` means whatever
/// the environment asks for, which is what an unset preference means.
pub fn set_language(language: Option<&str>) {
    let next = match language {
        Some(tag) => Catalogue::new(tag),
        None => Catalogue::from_env(),
    };
    if let Ok(mut current) = catalogue().write() {
        *current = next;
    }
}

/// The language actually in use, which is not always the one asked for — a tag
/// with no catalogue behind it reads as English.
pub fn language() -> String {
    catalogue()
        .read()
        .map(|catalogue| catalogue.language().to_string())
        .unwrap_or_else(|_| "en".to_string())
}

/// The string for a dotted key.
///
/// Returns an owned `String` because the catalogue sits behind a lock and the
/// language can change under it. That is one small allocation per string per
/// frame, against widgets that mostly want an owned string anyway.
pub fn t(key: &str) -> String {
    catalogue().read().map_or_else(
        |_| key.to_string(),
        |catalogue| catalogue.get(key).to_string(),
    )
}

/// Whether the catalogue carries a key at all, in any language. For callers
/// whose keys come from the data rather than from the source, like a field name.
pub fn has(key: &str) -> bool {
    catalogue().read().is_ok_and(|catalogue| catalogue.has(key))
}

/// The string for a key with its `{name}` placeholders filled in — the same
/// spelling `vue-i18n` uses on the other side, so one catalogue entry serves
/// both clients.
///
/// A placeholder with no argument is left as it is written: showing `{count}`
/// says which one was forgotten, where dropping it would only look wrong.
pub fn t_args(key: &str, args: &[(&str, &str)]) -> String {
    let mut text = t(key);
    for (name, value) in args {
        text = text.replace(&format!("{{{name}}}"), value);
    }
    text
}
