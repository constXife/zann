//! Process-wide view of the shared translation catalogue.

use std::sync::{OnceLock, RwLock};

use zann_ui_core::Catalogue;

fn catalogue() -> &'static RwLock<Catalogue> {
    static CATALOGUE: OnceLock<RwLock<Catalogue>> = OnceLock::new();
    CATALOGUE.get_or_init(|| RwLock::new(Catalogue::from_env()))
}

pub fn set_language(language: Option<&str>) {
    let next = language.map_or_else(Catalogue::from_env, Catalogue::new);
    if let Ok(mut current) = catalogue().write() {
        *current = next;
    }
}

pub fn t(key: &str) -> String {
    catalogue().read().map_or_else(
        |_| key.to_string(),
        |catalogue| catalogue.get(key).to_string(),
    )
}

pub fn t_args(key: &str, args: &[(&str, &str)]) -> String {
    let mut text = t(key);
    for (name, value) in args {
        text = text.replace(&format!("{{{name}}}"), value);
    }
    text
}

pub fn field_label(key: &str) -> String {
    catalogue()
        .read()
        .map_or_else(|_| key.to_string(), |catalogue| catalogue.field_label(key))
}

pub fn type_label(type_id: &str) -> String {
    catalogue().read().map_or_else(
        |_| type_id.to_string(),
        |catalogue| catalogue.type_label(type_id),
    )
}

pub fn minutes_label(minutes: u32) -> String {
    catalogue().read().map_or_else(
        |_| minutes.to_string(),
        |catalogue| catalogue.minutes_label(minutes),
    )
}

pub fn seconds_label(seconds: u32) -> String {
    catalogue().read().map_or_else(
        |_| seconds.to_string(),
        |catalogue| catalogue.seconds_label(seconds),
    )
}

pub fn has(key: &str) -> bool {
    catalogue().read().is_ok_and(|catalogue| catalogue.has(key))
}
