//! The translation catalogue every client reads.
//!
//! The files at `i18n/` are the source of truth. They keep semantic keys stable
//! while each toolkit chooses its own widgets and layout.

use std::collections::BTreeMap;

use serde_json::Value;

pub const EN: &str = include_str!("../../../i18n/en.json");
pub const RU: &str = include_str!("../../../i18n/ru.json");

pub const LANGUAGES: &[(&str, &str)] = &[("en", "English"), ("ru", "Русский")];

/// One language flattened to the dotted keys both Vue and native clients use.
pub struct Catalogue {
    language: String,
    strings: BTreeMap<String, String>,
    fallback: BTreeMap<String, String>,
}

impl Catalogue {
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

    #[must_use]
    pub fn from_env() -> Self {
        let tag = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|name| std::env::var(name).ok())
            .filter(|value| !value.is_empty() && value != "C" && value != "POSIX")
            .and_then(|value| value.split('.').next().map(str::to_string))
            .unwrap_or_default();
        Self::new(&tag)
    }

    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }

    #[must_use]
    pub fn get<'a>(&'a self, key: &'a str) -> &'a str {
        self.strings
            .get(key)
            .or_else(|| self.fallback.get(key))
            .map_or(key, String::as_str)
    }

    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.fallback.contains_key(key) || self.strings.contains_key(key)
    }

    /// The label for an item field key: the `fields.*` translation when one
    /// exists, otherwise the key with underscores spaced and the first letter
    /// capitalized, so custom fields still read naturally.
    #[must_use]
    pub fn field_label(&self, key: &str) -> String {
        let translated = match key {
            "otp" | "totp" => "fields.otp".to_string(),
            named => format!("fields.{named}"),
        };
        if self.has(&translated) {
            return self.get(&translated).to_string();
        }
        let spaced = key.replace('_', " ");
        let mut chars = spaced.chars();
        match chars.next() {
            Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            None => spaced,
        }
    }

    /// The label for an item type id: the `types.*` translation, or the id
    /// itself for a type this catalogue does not know.
    #[must_use]
    pub fn type_label(&self, type_id: &str) -> String {
        let key = format!("types.{type_id}");
        if self.has(&key) {
            self.get(&key).to_string()
        } else {
            type_id.to_string()
        }
    }

    /// The label for a minutes option in settings, such as the auto-lock
    /// timeout: never, one hour, or a number of minutes.
    #[must_use]
    pub fn minutes_label(&self, minutes: u32) -> String {
        match minutes {
            0 => self.get("time.never").to_string(),
            60 => self.get("time.hour").to_string(),
            value => format!("{value} {}", self.get("time.minutes")),
        }
    }

    /// The label for a seconds option in settings, such as the clipboard
    /// timeout; whole minutes from two minutes up read as minutes.
    #[must_use]
    pub fn seconds_label(&self, seconds: u32) -> String {
        match seconds {
            0 => self.get("time.never").to_string(),
            value if value >= 120 && value % 60 == 0 => {
                format!("{} {}", value / 60, self.get("time.minutes"))
            }
            value => format!("{value} {}", self.get("time.seconds")),
        }
    }
}

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
    fn duration_options_read_as_never_hours_minutes_or_seconds() {
        let catalogue = Catalogue::new("en");
        assert_eq!(catalogue.minutes_label(0), "Never");
        assert_eq!(catalogue.minutes_label(5), "5 minutes");
        assert_eq!(catalogue.minutes_label(60), "1 hour");
        assert_eq!(catalogue.seconds_label(0), "Never");
        assert_eq!(catalogue.seconds_label(60), "60 seconds");
        assert_eq!(catalogue.seconds_label(300), "5 minutes");
    }

    #[test]
    fn catalogues_parse_and_agree_on_keys() {
        let en = flatten(EN);
        let ru = flatten(RU);
        assert!(en.len() > 500, "the English catalogue looks truncated");
        assert_eq!(en.keys().collect::<Vec<_>>(), ru.keys().collect::<Vec<_>>());
    }

    #[test]
    fn unknown_languages_fall_back_to_english() {
        let catalogue = Catalogue::new("pt-BR");
        assert_eq!(catalogue.language(), "en");
        assert_eq!(catalogue.get("settings.title"), "Settings");
        assert_eq!(Catalogue::new("ru_RU").language(), "ru");
    }

    #[test]
    fn field_labels_translate_known_keys_and_humanize_custom_ones() {
        let catalogue = Catalogue::new("en");
        assert_eq!(catalogue.field_label("username"), "Username");
        assert_eq!(catalogue.field_label("totp"), "One-time code");
        assert_eq!(catalogue.field_label("otp"), "One-time code");
        assert_eq!(catalogue.field_label("recovery_code"), "Recovery code");
        assert_eq!(catalogue.field_label(""), "");
        assert_eq!(Catalogue::new("ru").field_label("password"), "Пароль");
    }

    #[test]
    fn type_labels_translate_known_types_and_keep_unknown_ids() {
        let catalogue = Catalogue::new("en");
        assert_eq!(catalogue.type_label("kv"), "Key-Value");
        assert_eq!(catalogue.type_label("login"), "Login");
        assert_eq!(catalogue.type_label("future_type"), "future_type");
        assert_eq!(Catalogue::new("ru").type_label("login"), "Логин");
    }
}
