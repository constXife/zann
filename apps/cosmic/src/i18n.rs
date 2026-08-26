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

pub fn has(key: &str) -> bool {
    catalogue().read().is_ok_and(|catalogue| catalogue.has(key))
}
