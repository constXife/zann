//! Persistence-independent sync vocabulary and ports.

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;
use zann_core::{AuthMethod, ChangeType, SyncStatus};
use zann_crypto::SecretKey;
use zeroize::Zeroizing;

use crate::config::AuthorizedTargetGeneration;
use crate::session::{OperationCompletion, SessionOperationId, SessionTarget};

pub(crate) const CATALOG_PAGE_LIMIT: usize = 200;
// The current endpoint has offset pagination but no versioned snapshot/cursor.
// A full page could hide additional vaults, so only a strictly shorter page is
// safe to reconcile as a complete catalog.
pub(crate) const MAX_CATALOG_VAULTS: usize = CATALOG_PAGE_LIMIT - 1;
// `Vec<u8>` is represented as a JSON integer array by the current wire
// contract. Four maximum-size items with five history entries remain below the
// fixed 32 MiB response cap; a larger legal page would not be transportable.
pub(crate) const PULL_PAGE_LIMIT: usize = 4;
pub(crate) const MAX_PULL_PAGES: usize = 1_024;
pub(crate) const MAX_PULL_CHANGES: usize = 16_384;
pub(crate) const MAX_HISTORY_PER_ITEM: usize = 5;
pub(crate) const MAX_CURSOR_BYTES: usize = 4_096;
pub(crate) const MAX_PENDING_CHANGES: usize = 64;
pub(crate) const MAX_PAYLOAD_BYTES: usize = 262_144;
pub(crate) const MAX_CIPHERTEXT_BYTES: usize = MAX_PAYLOAD_BYTES + 256;
pub(crate) const MAX_ITEM_NAME_BYTES: usize = 200;
pub(crate) const MAX_ITEM_PATH_BYTES: usize = 500;
pub(crate) const MAX_ITEM_PATH_SEGMENTS: usize = 32;
pub(crate) const MAX_TYPE_ID_BYTES: usize = 128;
pub(crate) const MAX_EMAIL_BYTES: usize = 320;
pub(crate) const MAX_DISPLAY_NAME_BYTES: usize = 200;

pub(crate) fn validate_required(value: &str, max_bytes: usize) -> Result<(), SyncModelError> {
    if value.is_empty() || value.len() > max_bytes || value.trim() != value {
        return Err(SyncModelError::InvalidText);
    }
    Ok(())
}

fn validate_cache_key_fingerprint(value: &str) -> Result<(), SyncModelError> {
    if value.len() != 12
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SyncModelError::InvalidText);
    }
    Ok(())
}

pub(crate) fn validate_path(path: &str) -> Result<(), SyncModelError> {
    validate_required(path, MAX_ITEM_PATH_BYTES)?;
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.is_empty()
        || segments.len() > MAX_ITEM_PATH_SEGMENTS
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.len() > MAX_ITEM_NAME_BYTES
                || *segment == "."
                || *segment == ".."
                || segment.starts_with('.')
                || segment.trim() != *segment
        })
    {
        return Err(SyncModelError::InvalidPath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use zann_crypto::SecretKey;

    use super::{SyncCursor, VaultPayloadKey};

    fn encoded(json: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
    }

    #[test]
    fn cursor_is_strict_bounded_standard_base64_json() {
        let zero = SyncCursor::new(encoded(r#"{"seq":0}"#)).expect("seq zero is valid");
        assert_eq!(zero.sequence(), 0);
        assert!(SyncCursor::new(encoded(r#"{"seq":-1}"#)).is_err());
        assert!(SyncCursor::new(encoded(r#"{"seq":1,"extra":2}"#)).is_err());
        assert!(SyncCursor::new(encoded(r#"{"seq":1,"seq":2}"#)).is_err());
        assert!(SyncCursor::new("not-base64").is_err());
    }

    #[test]
    fn payload_key_fingerprint_is_bound_to_exact_key_bytes() {
        let first = VaultPayloadKey::from_secret_key(SecretKey::from_bytes([7_u8; 32]));
        let borrowed = SecretKey::from_bytes([7_u8; 32]);
        let same = VaultPayloadKey::copy_from_secret_key(&borrowed);
        let rotated = VaultPayloadKey::from_bytes([8_u8; 32]);

        assert_eq!(first.cache_key_fingerprint(), same.cache_key_fingerprint());
        assert_ne!(
            first.cache_key_fingerprint(),
            rotated.cache_key_fingerprint()
        );
        assert_eq!(first.cache_key_fingerprint().len(), 12);
        assert_eq!(format!("{first:?}"), "VaultPayloadKey(<redacted>)");
        assert!(!format!("{first:?}").contains(first.cache_key_fingerprint()));
    }
}

mod catalog;
mod commit;
mod cursor;
mod error;
mod item;
mod progress;
mod store;
pub use catalog::*;
pub use commit::*;
pub use cursor::*;
pub use error::*;
pub use item::*;
pub use progress::*;
pub use store::*;
