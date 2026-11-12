//! Checking a master key against the account's published personal vault
//! keys. A new device checks before it keeps anything derived from the key,
//! and a connection's first sync checks again before it binds the key's
//! fingerprint, so a mistyped master password is never bound.

use zann_crypto::vault_crypto;
use zann_crypto::SecretKey;

use super::engine::{await_remote, map_session_error, request_timeout, SyncAuthorizer};
use super::model::{CatalogSnapshot, SyncError, SyncErrorKind, SyncStage, VaultPlane};
use super::transport::{HttpSyncRemote, SyncRemote};
use crate::session::{AppSession, SessionOperation, SessionTarget};

/// What the account's personal vault key says about a master key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountKeyCheck {
    /// The key opens the account's personal vault.
    Matches,
    /// It does not: another master password.
    Mismatch,
    /// The account has published no personal vault key yet, so the first
    /// device to sync chooses it.
    Unpublished,
}

/// Checks `master_key` over the session's own authorization and transport.
pub(crate) async fn verify_with_session(
    session: &AppSession,
    target: &SessionTarget,
    master_key: &SecretKey,
    operation: SessionOperation,
) -> Result<AccountKeyCheck, SyncError> {
    let remote = HttpSyncRemote::new().map_err(|_| {
        SyncError::new(
            operation.operation_id(),
            SyncErrorKind::TransportUnavailable,
            SyncStage::Catalog,
        )
    })?;
    verify_account_key(session, &remote, target, master_key, operation).await
}

async fn verify_account_key(
    authorizer: &dyn SyncAuthorizer,
    remote: &dyn SyncRemote,
    target: &SessionTarget,
    master_key: &SecretKey,
    operation: SessionOperation,
) -> Result<AccountKeyCheck, SyncError> {
    let access = authorizer
        .authorize(target, operation.detached_copy())
        .await
        .map_err(map_session_error)?;
    let timeout = request_timeout(&operation, SyncStage::Catalog)?;
    let catalog = await_remote(
        &operation,
        SyncStage::Catalog,
        remote.fetch_catalog(&access, timeout),
    )
    .await?;
    Ok(check_catalog(master_key, &catalog))
}

/// What one catalog's personal vault keys say about `master_key`. Every
/// personal vault key of one account is wrapped by the same master key, so
/// the key must open each published one.
pub(super) fn check_catalog(master_key: &SecretKey, catalog: &CatalogSnapshot) -> AccountKeyCheck {
    let mut check = AccountKeyCheck::Unpublished;
    for vault in catalog.vaults() {
        if vault.plane() != VaultPlane::PersonalClient || vault.vault_key_envelope().is_empty() {
            continue;
        }
        if vault_crypto::decrypt_vault_key(master_key, vault.id(), vault.vault_key_envelope())
            .is_err()
        {
            return AccountKeyCheck::Mismatch;
        }
        check = AccountKeyCheck::Matches;
    }
    check
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use chrono::Utc;
    use uuid::Uuid;
    use zann_crypto::vault_crypto;
    use zann_crypto::SecretKey;

    use super::*;
    use crate::config::ConnectionId;
    use crate::session::SessionAccess;
    #[cfg(feature = "app")]
    use crate::session::{SessionError, SessionErrorKind};
    use crate::sync::engine::AuthorizeFuture;
    use crate::sync::model::{CatalogSnapshot, CatalogVault, PendingProof, ResolvedSyncVault};
    use crate::sync::transport::{RemoteError, RemoteErrorKind, RemoteFuture};
    use crate::sync::wire::{PullPageWire, PushResponseWire};
    use crate::sync::SyncCursor;

    const ENDPOINT: &str = "https://sync.example.test";

    struct Authorizer {
        refuse: bool,
    }

    impl SyncAuthorizer for Authorizer {
        fn authorize<'a>(
            &'a self,
            target: &'a SessionTarget,
            operation: SessionOperation,
        ) -> AuthorizeFuture<'a> {
            let target = target.clone();
            let refuse = self.refuse;
            Box::pin(async move {
                #[cfg(feature = "app")]
                if refuse {
                    return Err(SessionError::for_app(
                        operation.operation_id(),
                        SessionErrorKind::SessionExpired,
                    ));
                }
                #[cfg(not(feature = "app"))]
                let _ = refuse;
                Ok(SessionAccess::for_sync_test(
                    operation.operation_id(),
                    target,
                    ENDPOINT,
                    Some(Uuid::now_v7().to_string()),
                    "server-fingerprint",
                    (None, None),
                    true,
                ))
            })
        }
    }

    /// Serves one catalog of `(plane, envelope)` vaults, or fails.
    struct Remote(Result<Vec<(Uuid, VaultPlane, Vec<u8>)>, RemoteErrorKind>);

    impl SyncRemote for Remote {
        fn fetch_catalog<'a>(
            &'a self,
            _access: &'a SessionAccess,
            _timeout: Duration,
        ) -> RemoteFuture<'a, CatalogSnapshot> {
            let catalog = self.0.clone().map_err(RemoteError::new).map(|vaults| {
                CatalogSnapshot::validated(
                    vaults
                        .into_iter()
                        .map(|(id, plane, envelope)| {
                            CatalogVault::validated(
                                id,
                                format!("vault-{id}"),
                                "Vault".to_string(),
                                plane,
                                Vec::new(),
                                Utc::now(),
                                envelope,
                            )
                        })
                        .collect(),
                )
            });
            Box::pin(async move { catalog })
        }

        fn pull_page<'a>(
            &'a self,
            _access: &'a SessionAccess,
            _vault_id: Uuid,
            _plane: VaultPlane,
            _cursor: Option<&'a SyncCursor>,
            _timeout: Duration,
        ) -> RemoteFuture<'a, PullPageWire> {
            unreachable!("the check never pulls")
        }

        fn push<'a>(
            &'a self,
            _access: &'a SessionAccess,
            _vault: &'a ResolvedSyncVault,
            _pending: &'a [PendingProof],
            _timeout: Duration,
        ) -> RemoteFuture<'a, PushResponseWire> {
            unreachable!("the check never pushes")
        }
    }

    fn target() -> SessionTarget {
        SessionTarget::new(
            ConnectionId::deterministic("account-key", ENDPOINT),
            "default",
        )
        .expect("target")
    }

    fn operation() -> SessionOperation {
        SessionOperation::new(Instant::now() + Duration::from_secs(30)).0
    }

    /// A personal vault whose key is wrapped by `master_key`.
    fn personal(master_key: &SecretKey) -> (Uuid, VaultPlane, Vec<u8>) {
        let id = Uuid::now_v7();
        let envelope = vault_crypto::encrypt_vault_key(master_key, id, &SecretKey::generate())
            .expect("wrap the vault key");
        (id, VaultPlane::PersonalClient, envelope)
    }

    async fn check(
        authorizer: Authorizer,
        remote: Remote,
        master_key: &SecretKey,
    ) -> Result<AccountKeyCheck, SyncError> {
        verify_account_key(&authorizer, &remote, &target(), master_key, operation()).await
    }

    #[tokio::test]
    async fn the_account_key_opens_and_another_does_not() {
        let account = SecretKey::generate();
        let catalog = || Remote(Ok(vec![personal(&account)]));
        let open = Authorizer { refuse: false };
        assert_eq!(
            check(open, catalog(), &account).await.expect("check"),
            AccountKeyCheck::Matches
        );
        let typo = SecretKey::generate();
        assert_eq!(
            check(Authorizer { refuse: false }, catalog(), &typo)
                .await
                .expect("check"),
            AccountKeyCheck::Mismatch
        );
    }

    #[tokio::test]
    async fn every_personal_vault_must_open() {
        let account = SecretKey::generate();
        let remote = Remote(Ok(vec![
            personal(&account),
            personal(&SecretKey::generate()),
        ]));
        assert_eq!(
            check(Authorizer { refuse: false }, remote, &account)
                .await
                .expect("check"),
            AccountKeyCheck::Mismatch
        );
    }

    #[tokio::test]
    async fn nothing_published_leaves_the_key_to_the_first_device() {
        let key = SecretKey::generate();
        let remote = Remote(Ok(vec![
            (Uuid::now_v7(), VaultPlane::PersonalClient, Vec::new()),
            (Uuid::now_v7(), VaultPlane::SharedServer, vec![1, 2, 3]),
        ]));
        assert_eq!(
            check(Authorizer { refuse: false }, remote, &key)
                .await
                .expect("check"),
            AccountKeyCheck::Unpublished
        );
    }

    #[tokio::test]
    async fn an_unreachable_catalog_is_an_error_not_a_pass() {
        let key = SecretKey::generate();
        let unreachable = check(
            Authorizer { refuse: false },
            Remote(Err(RemoteErrorKind::Unavailable)),
            &key,
        )
        .await
        .expect_err("no catalog");
        assert_eq!(unreachable.stage(), SyncStage::Catalog);
    }

    #[cfg(feature = "app")]
    #[tokio::test]
    async fn an_expired_session_is_an_error_not_a_pass() {
        let key = SecretKey::generate();
        let expired = check(
            Authorizer { refuse: true },
            Remote(Ok(vec![personal(&key)])),
            &key,
        )
        .await
        .expect_err("no session");
        assert_eq!(expired.kind(), SyncErrorKind::SessionExpired);
    }
}
