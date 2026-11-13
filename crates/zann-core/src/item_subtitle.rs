//! The line under an item's title in a list: who or where the item is for,
//! so items with the same title tell apart without opening them.
//!
//! It comes from the decrypted payload, so only fields that are never
//! secret qualify: a field of kind `text` or `url` that is not marked
//! masked. Passwords, one-time codes and notes never show, whatever their
//! key is.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{EncryptedPayload, FieldKind, FieldValue};

/// Longest subtitle kept, in characters; a list row shows one line.
pub const ITEM_SUBTITLE_MAX_CHARS: usize = 120;

/// A list subtitle taken from a decrypted payload. Its `Debug` never shows
/// the value, which can be a username or an email.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ItemSubtitle(String);

impl ItemSubtitle {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for ItemSubtitle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ItemSubtitle(<redacted>)")
    }
}

impl Zeroize for ItemSubtitle {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ItemSubtitle {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ItemSubtitle {}

/// The payload fields an item type is told apart by, first match wins.
/// Types whose identifying content is secret or long text have none. Every
/// key must be one of the type's `exposable_public_attrs` in
/// `schemas/security_profiles.yaml`, which a test checks.
const SUBTITLE_KEYS: &[(&str, &[&str])] = &[
    ("login", &["username", "url"]),
    ("api", &["url"]),
    ("identity", &["email"]),
    ("card", &["cardholder"]),
    ("ssh_key", &["username"]),
    ("database", &["host", "user"]),
    ("server_credentials", &["host", "username"]),
    ("cloud_iam", &["role", "region"]),
    ("file_secret", &["filename"]),
];

fn subtitle_keys(type_id: &str) -> &'static [&'static str] {
    SUBTITLE_KEYS
        .iter()
        .find(|(id, _)| *id == type_id)
        .map_or(&[], |(_, keys)| keys)
}

/// The subtitle of an item of `type_id`, or `None` when none of its
/// identifying fields holds a value that may show.
#[must_use]
pub fn item_subtitle(type_id: &str, payload: &EncryptedPayload) -> Option<ItemSubtitle> {
    subtitle_keys(type_id)
        .iter()
        .filter_map(|key| payload.fields.get(*key))
        .find_map(shown_value)
        .map(ItemSubtitle)
}

fn shown_value(field: &FieldValue) -> Option<String> {
    if field.meta.as_ref().and_then(|meta| meta.masked) == Some(true) {
        return None;
    }
    let value = match field.kind {
        FieldKind::Text => first_line(&field.value),
        FieldKind::Url => url_host(&field.value),
        FieldKind::Password | FieldKind::Otp | FieldKind::Note => return None,
    };
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.chars().take(ITEM_SUBTITLE_MAX_CHARS).collect())
}

fn first_line(value: &str) -> &str {
    value
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
}

/// The host of `value`: no scheme, credentials, port, path, query or
/// fragment. A value without a scheme reads as a host and path.
fn url_host(value: &str) -> &str {
    let value = value.trim();
    let rest = value.split_once("://").map_or(value, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if let Some(bracketed) = host.strip_prefix('[') {
        // An IPv6 literal keeps its colons; only the port after `]` goes.
        return bracketed.split(']').next().unwrap_or("");
    }
    host.split(':').next().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::FieldMeta;

    fn payload(type_id: &str, fields: &[(&str, FieldKind, &str)]) -> EncryptedPayload {
        EncryptedPayload {
            v: 1,
            type_id: type_id.to_string(),
            fields: fields
                .iter()
                .map(|(key, kind, value)| {
                    (
                        (*key).to_string(),
                        FieldValue {
                            kind: *kind,
                            value: (*value).to_string(),
                            meta: None,
                        },
                    )
                })
                .collect::<HashMap<_, _>>(),
            extra: None,
        }
    }

    fn subtitle(type_id: &str, fields: &[(&str, FieldKind, &str)]) -> Option<String> {
        item_subtitle(type_id, &payload(type_id, fields)).map(ItemSubtitle::into_string)
    }

    #[test]
    fn a_login_shows_its_username_then_its_host() {
        let login = [
            ("username", FieldKind::Text, "alice"),
            ("password", FieldKind::Password, "hunter2"),
            ("url", FieldKind::Url, "https://accounts.example.com/"),
        ];
        assert_eq!(subtitle("login", &login).as_deref(), Some("alice"));
        assert_eq!(
            subtitle("login", &login[1..]).as_deref(),
            Some("accounts.example.com")
        );
        assert_eq!(subtitle("login", &login[1..2]), None);
    }

    #[test]
    fn a_url_shows_only_its_host() {
        let cases = [
            ("https://user:pw@example.com:8443/a?b#c", "example.com"),
            ("example.com/login", "example.com"),
            ("http://192.168.1.1:3000", "192.168.1.1"),
            ("https://[::1]:8080/x", "::1"),
        ];
        for (url, host) in cases {
            assert_eq!(
                subtitle("api", &[("url", FieldKind::Url, url)]).as_deref(),
                Some(host),
                "{url}"
            );
        }
    }

    #[test]
    fn secret_fields_never_show_whatever_their_key() {
        // A username stored as a password field stays hidden.
        assert_eq!(
            subtitle("login", &[("username", FieldKind::Password, "alice")]),
            None
        );
        assert_eq!(
            subtitle("login", &[("username", FieldKind::Otp, "123456")]),
            None
        );
        assert_eq!(
            subtitle("card", &[("cardholder", FieldKind::Note, "Alice")]),
            None
        );
        let mut masked = payload("login", &[("username", FieldKind::Text, "alice")]);
        if let Some(field) = masked.fields.get_mut("username") {
            field.meta = Some(FieldMeta {
                masked: Some(true),
                multiline: None,
                copyable: None,
                readonly: None,
                placeholder: None,
            });
        }
        assert_eq!(item_subtitle("login", &masked), None);
    }

    #[test]
    fn types_without_identifying_fields_have_no_subtitle() {
        assert_eq!(subtitle("note", &[("title", FieldKind::Text, "x")]), None);
        assert_eq!(
            subtitle("secret", &[("policy", FieldKind::Text, "x")]),
            None
        );
        assert_eq!(
            subtitle("unknown", &[("username", FieldKind::Text, "x")]),
            None
        );
    }

    #[test]
    fn a_subtitle_is_one_bounded_line() {
        assert_eq!(
            subtitle(
                "identity",
                &[("email", FieldKind::Text, "\n  a@b.c \nmore")]
            )
            .as_deref(),
            Some("a@b.c")
        );
        assert_eq!(
            subtitle("identity", &[("email", FieldKind::Text, "  ")]),
            None
        );
        let long = "x".repeat(500);
        let shown = subtitle("card", &[("cardholder", FieldKind::Text, &long)]);
        assert_eq!(
            shown.map(|value| value.chars().count()),
            Some(ITEM_SUBTITLE_MAX_CHARS)
        );
    }

    #[test]
    fn subtitle_fields_are_exposable_by_the_security_profiles() {
        let profiles = crate::SecurityProfileRegistry::from_yaml(include_str!(
            "../../../schemas/security_profiles.yaml"
        ))
        .expect("security profiles parse");
        for (type_id, keys) in SUBTITLE_KEYS {
            let profile = profiles
                .profile(type_id)
                .unwrap_or_else(|| panic!("{type_id} has subtitle fields but no security profile"));
            for key in *keys {
                assert!(
                    profile
                        .exposable_public_attrs
                        .iter()
                        .any(|attr| attr == key),
                    "{type_id}.{key} is not in exposable_public_attrs"
                );
            }
        }
    }

    #[test]
    fn debug_hides_the_value() {
        let shown = item_subtitle(
            "login",
            &payload("login", &[("username", FieldKind::Text, "alice")]),
        );
        assert!(!format!("{shown:?}").contains("alice"));
    }
}
