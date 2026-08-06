//! The translation catalogue every client reads.
//!
//! The files at `i18n/` are the source of truth for both frontends: the desktop
//! app imports them into `vue-i18n`, and this module embeds the same bytes so
//! the COSMIC client is never a second, drifting copy of the same strings.
//!
//! Keys are the dotted paths the JSON nests — `settings.autolockAfter` — which
//! is the shape `vue-i18n` already uses, so a string added for one client is a
//! string the other can ask for by the same name.

use std::collections::BTreeMap;

use serde_json::Value;

pub const EN: &str = include_str!("../../../i18n/en.json");
pub const RU: &str = include_str!("../../../i18n/ru.json");

/// The language tags with a catalogue behind them, in the order a picker should
/// offer them.
pub const LANGUAGES: &[(&str, &str)] = &[("en", "English"), ("ru", "Русский")];

/// One language, flattened to the dotted keys callers ask for.
///
/// English is always loaded alongside, because a translation that has fallen
/// behind should show the English string rather than a raw key.
pub struct Catalogue {
    language: String,
    strings: BTreeMap<String, String>,
    fallback: BTreeMap<String, String>,
}

impl Catalogue {
    /// The catalogue for a language tag. Anything with no catalogue behind it —
    /// including a region like `pt-BR` whose base is not carried either — comes
    /// back as English rather than as an error, because a missing translation is
    /// not a reason to refuse to draw.
    #[must_use]
    pub fn new(language: &str) -> Self {
        let fallback = flatten(EN);
        let base = language.split(['-', '_']).next().unwrap_or(language);
        let (language, strings) = match base {
            "ru" => ("ru".to_string(), flatten(RU)),
            _ => ("en".to_string(), fallback.clone()),
        };
        Self {
            language,
            strings,
            fallback,
        }
    }

    /// The catalogue the environment asks for, the way every other console
    /// program decides: `LC_ALL`, then `LC_MESSAGES`, then `LANG`.
    #[must_use]
    pub fn from_env() -> Self {
        let tag = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|name| std::env::var(name).ok())
            .filter(|value| !value.is_empty() && value != "C" && value != "POSIX")
            // `ru_RU.UTF-8` — the encoding is not part of the language.
            .and_then(|value| value.split('.').next().map(str::to_string))
            .unwrap_or_default();
        Self::new(&tag)
    }

    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }

    /// The string for a key, falling back to English and then to the key
    /// itself — a missing string should be obvious on screen, not invisible.
    #[must_use]
    pub fn get<'a>(&'a self, key: &'a str) -> &'a str {
        self.strings
            .get(key)
            .or_else(|| self.fallback.get(key))
            .map_or(key, String::as_str)
    }

    /// Whether a key exists at all, in any language. For tests that guard a
    /// client against asking for something the catalogue never had.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.fallback.contains_key(key) || self.strings.contains_key(key)
    }
}

/// Nested objects to the dotted keys callers use. Anything that is not a string
/// at the leaf is dropped: the catalogue is text, and a caller asking for a
/// branch has asked for the wrong thing.
fn flatten(source: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(root) = serde_json::from_str::<Value>(source) else {
        return out;
    };
    walk(&root, &mut String::new(), &mut out);
    out
}

fn walk(value: &Value, prefix: &mut String, out: &mut BTreeMap<String, String>) {
    match value {
        Value::String(text) => {
            out.insert(prefix.clone(), text.clone());
        }
        Value::Object(fields) => {
            let base = prefix.len();
            for (key, child) in fields {
                if base > 0 {
                    prefix.push('.');
                }
                prefix.push_str(key);
                walk(child, prefix, out);
                prefix.truncate(base);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_catalogues_parse_and_agree_on_their_keys() {
        let en = flatten(EN);
        let ru = flatten(RU);
        assert!(en.len() > 500, "the English catalogue looks truncated");

        // A key only one side has is a string that silently shows in English —
        // worth knowing about, and cheap to keep at zero.
        let missing: Vec<&str> = en
            .keys()
            .filter(|key| !ru.contains_key(*key))
            .map(String::as_str)
            .collect();
        assert!(missing.is_empty(), "not translated into ru: {missing:?}");

        let extra: Vec<&str> = ru
            .keys()
            .filter(|key| !en.contains_key(*key))
            .map(String::as_str)
            .collect();
        assert!(extra.is_empty(), "in ru but not in en: {extra:?}");
    }

    #[test]
    fn a_language_with_no_catalogue_reads_as_english() {
        let catalogue = Catalogue::new("pt-BR");
        assert_eq!(catalogue.language(), "en");
        assert_eq!(catalogue.get("settings.title"), "Settings");

        // A region of a language we do carry still resolves to it.
        let catalogue = Catalogue::new("ru_RU");
        assert_eq!(catalogue.language(), "ru");
        assert_ne!(catalogue.get("settings.title"), "Settings");
    }

    #[test]
    fn an_unknown_key_shows_itself() {
        let catalogue = Catalogue::new("en");
        assert_eq!(catalogue.get("no.such.key"), "no.such.key");
        assert!(!catalogue.has("no.such.key"));
        assert!(catalogue.has("settings.title"));
    }
}
