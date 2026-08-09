//! The client half of the workflow tests, delegating to the real client.
//!
//! This file used to reimplement pull-apply and push-build against the JSON the
//! server returns. That made the workflow tests a test of this file: the
//! deletion bug in `zann-client` lived here in correct form the whole time it
//! was broken in the shipped client, and no test noticed.
//!
//! So nothing here decides anything any more. Each function deserializes the
//! server's response into the client's own wire types and hands it to
//! `zann_client::sync_helpers` — which means these tests also check the two
//! ends still agree on the shape, not just on the outcome.

#![allow(dead_code)]

use uuid::Uuid;
use zann_client::sync_helpers as client;
use zann_client::types::{SyncPullChange, SyncSharedPullChange};
use zann_crypto::crypto::SecretKey;
use zann_crypto::vault_crypto as core_crypto;
use zann_db::local::{LocalItemHistoryRepo, LocalItemRepo, LocalPendingChange, LocalVaultRepo};
use zann_db::SqlitePool;

pub(super) fn payload_checksum(payload_enc: &[u8]) -> String {
    core_crypto::payload_checksum(payload_enc)
}

async fn vault_key(
    pool: &SqlitePool,
    storage_id: Uuid,
    vault_id: Uuid,
    master_key: &SecretKey,
) -> SecretKey {
    let vault = LocalVaultRepo::new(pool)
        .get_by_id(storage_id, vault_id)
        .await
        .expect("vault")
        .expect("vault");
    core_crypto::decrypt_vault_key(master_key, vault_id, &vault.vault_key_enc)
        .expect("decrypt vault key")
}

/// Apply one change from `/v1/sync/shared/pull` exactly as the client would.
///
/// Returns whether it was applied, so a test can assert that the server sent
/// something the client actually accepted rather than silently dropped.
pub(super) async fn apply_shared_pull_change(
    pool: &SqlitePool,
    storage_id: Uuid,
    vault_id: Uuid,
    master_key: &SecretKey,
    change: serde_json::Value,
) -> bool {
    let change: SyncSharedPullChange = serde_json::from_value(change)
        .expect("the server sent a shared change the client cannot read");
    let item_repo = LocalItemRepo::new(pool);
    let history_repo = LocalItemHistoryRepo::new(pool);
    client::apply_shared_pull_change(
        &item_repo,
        &history_repo,
        master_key,
        storage_id,
        vault_id,
        &change,
    )
    .await
    .expect("apply shared pull change")
}

/// Apply one change from `/v1/sync/pull` exactly as the client would.
pub(super) async fn apply_personal_pull_change(
    pool: &SqlitePool,
    storage_id: Uuid,
    vault_id: Uuid,
    master_key: &SecretKey,
    change: serde_json::Value,
) -> bool {
    let change: SyncPullChange =
        serde_json::from_value(change).expect("the server sent a change the client cannot read");
    let vault_key = vault_key(pool, storage_id, vault_id, master_key).await;
    let item_repo = LocalItemRepo::new(pool);
    let history_repo = LocalItemHistoryRepo::new(pool);
    client::apply_pull_change(
        &item_repo,
        &history_repo,
        &vault_key,
        storage_id,
        vault_id,
        &change,
    )
    .await
    .expect("apply pull change")
}

/// Fold a push response back into the local rows, as the client does after
/// every push. Without this the local version never catches up to the server's
/// seq, and the next change is pushed with a stale `base_seq`.
pub(super) async fn apply_push_applied(
    pool: &SqlitePool,
    storage_id: Uuid,
    vault_id: Uuid,
    applied_changes: &serde_json::Value,
) {
    let Some(entries) = applied_changes.as_array() else {
        return;
    };
    if entries.is_empty() {
        return;
    }
    let changes: Vec<zann_client::types::SyncAppliedChange> =
        serde_json::from_value(applied_changes.clone())
            .expect("the server sent an applied change the client cannot read");
    let item_repo = LocalItemRepo::new(pool);
    client::apply_push_applied(&item_repo, storage_id, vault_id, &changes)
        .await
        .expect("apply push applied");
}

pub(super) async fn build_shared_push_changes(
    master_key: &SecretKey,
    vault_id: Uuid,
    pending: &[LocalPendingChange],
) -> Vec<serde_json::Value> {
    client::build_shared_push_changes(pending, master_key, vault_id)
        .expect("build shared push changes")
        .into_iter()
        .map(|change| serde_json::to_value(change).expect("push change json"))
        .collect()
}
