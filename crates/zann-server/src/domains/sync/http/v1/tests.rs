use proptest::prelude::*;

use super::helpers::{decode_cursor, encode_cursor};
use super::types::ErrorResponse;
use crate::domains::items::contract::{canonical_update_location, ItemContractError};

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
fn canonical_location_replaces_basename() {
    let (path, name) =
        canonical_update_location("apps/one", None, Some("two")).expect("valid rename");
    assert_eq!(path, "apps/two");
    assert_eq!(name, "two");
}

#[test]
fn canonical_location_rejects_a_path_disguised_as_a_name() {
    assert_eq!(
        canonical_update_location("apps/one", None, Some("foo/bar")),
        Err(ItemContractError::InvalidName)
    );
}
