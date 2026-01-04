use proptest::prelude::*;

use super::helpers::{decode_cursor, encode_cursor, normalize_path_and_name};
use super::types::ErrorResponse;

proptest! {
    #[test]
    fn cursor_roundtrip(seq in any::<i64>()) {
        let encoded = encode_cursor(seq);
        let decoded = decode_cursor(Some(encoded)).expect("decode");
        prop_assert_eq!(decoded, seq);
    }
}

#[test]
fn decode_cursor_invalid_rejected() {
    let result = decode_cursor(Some("not-base64".to_string()));
    assert!(matches!(
        result,
        Err(ErrorResponse {
            error: "invalid_cursor"
        })
    ));
}

#[test]
fn normalize_path_and_name_replaces_basename() {
    let (path, name) = normalize_path_and_name("apps/one", None, Some("two"));
    assert_eq!(path, "apps/two");
    assert_eq!(name, "two");
}

#[test]
fn normalize_path_and_name_uses_basename_from_path_like_name() {
    let (path, name) = normalize_path_and_name("apps/one", None, Some("foo/bar"));
    assert_eq!(path, "apps/bar");
    assert_eq!(name, "bar");
}
