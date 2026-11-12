//! The shared translation catalogue (`i18n/`) for shells that render the
//! semantic keys zann-ui-core hands out, such as category `label_key`s.

use std::sync::Arc;

use zann_ui_core::Catalogue;

#[derive(uniffi::Object)]
pub struct TranslationCatalogue(Catalogue);

#[uniffi::export]
impl TranslationCatalogue {
    /// `language` is a BCP 47 or POSIX tag such as `ru-RU`; languages without
    /// a catalogue read English.
    #[uniffi::constructor]
    pub fn new(language: String) -> Arc<Self> {
        Arc::new(Self(Catalogue::new(&language)))
    }

    /// The language actually loaded, after fallback.
    pub fn language(&self) -> String {
        self.0.language().to_string()
    }

    /// The text for `key`, or the key itself when no catalogue defines it.
    pub fn get(&self, key: String) -> String {
        self.0.get(&key).to_string()
    }

    pub fn field_label(&self, key: String) -> String {
        self.0.field_label(&key)
    }

    pub fn type_label(&self, type_id: String) -> String {
        self.0.type_label(&type_id)
    }

    pub fn minutes_label(&self, minutes: u32) -> String {
        self.0.minutes_label(minutes)
    }

    pub fn seconds_label(&self, seconds: u32) -> String {
        self.0.seconds_label(seconds)
    }
}
