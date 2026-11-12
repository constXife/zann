//! How an operation store's master key stands against the connection's
//! `expected_master_key_fp`. A connection binds its key for good only after
//! the sync has proved it against the account's catalog; until then the key
//! is a candidate that may take part in that proof and nothing else.

use zann_crypto::SecretKey;

use crate::{canonical_cache_fingerprint, store_error, SyncStoreError, SyncStoreErrorKind};

/// How the connection's config binds the store's master key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MasterKeyBinding {
    /// The connection's fingerprint is this key's.
    Bound,
    /// The connection has bound no key yet: the sync must prove this one
    /// against the account's catalog before it is bound.
    Candidate,
}

/// Checks the store's master key against the connection's binding. A bound
/// fingerprint must be the key's own; an unbound connection admits the key
/// only as a candidate.
pub(crate) fn master_key_binding(
    expected: Option<&str>,
    master_key: &SecretKey,
) -> Result<MasterKeyBinding, SyncStoreError> {
    let Some(expected) = expected else {
        return Ok(MasterKeyBinding::Candidate);
    };
    if !canonical_cache_fingerprint(expected) {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    if expected != zann_crypto::cache_key_fingerprint(master_key) {
        return Err(store_error(SyncStoreErrorKind::StaleKeyBinding));
    }
    Ok(MasterKeyBinding::Bound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unbound_connection_admits_the_key_as_a_candidate() {
        let key = SecretKey::from_bytes([7; 32]);
        assert_eq!(
            master_key_binding(None, &key).expect("unbound"),
            MasterKeyBinding::Candidate
        );
    }

    #[test]
    fn a_bound_connection_admits_only_its_own_key() {
        let key = SecretKey::from_bytes([7; 32]);
        let bound = zann_crypto::cache_key_fingerprint(&key);
        assert_eq!(
            master_key_binding(Some(&bound), &key).expect("own key"),
            MasterKeyBinding::Bound
        );
        let other = SecretKey::from_bytes([8; 32]);
        assert_eq!(
            master_key_binding(Some(&bound), &other)
                .expect_err("another key")
                .kind(),
            SyncStoreErrorKind::StaleKeyBinding
        );
        assert_eq!(
            master_key_binding(Some("NOT-CANONICAL"), &key)
                .expect_err("malformed binding")
                .kind(),
            SyncStoreErrorKind::InvalidData
        );
    }
}
