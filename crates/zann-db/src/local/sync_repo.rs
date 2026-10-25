use std::collections::HashSet;
use std::error::Error as StdError;
use std::fmt;

use chrono::{DateTime, Utc};
use sqlx_core::row::Row;
use sqlx_core::transaction::Transaction;
use sqlx_sqlite::Sqlite;
use uuid::Uuid;
use zann_core::{AuthMethod, ChangeType, StorageKind, SyncStatus};

use crate::local::vault_repo::{bounded_vault_preflight, bounded_vault_scope_membership};
use crate::local::{
    HistorySource, HistorySyncStatus, LocalItem, LocalItemHistory, LocalPendingChange, LocalStorage,
};
use crate::services::{
    MAX_ITEM_NAME_LEN, MAX_ITEM_PATH_LEN, MAX_ITEM_PATH_SEGMENTS, MAX_ITEM_PAYLOAD_BYTES,
};
use crate::SqlitePool;

const MAX_PUSH_BATCH_ITEMS: usize = 64;
const MAX_PULL_PAGE_ITEMS: usize = 16;
const MAX_HISTORY_PER_ITEM: usize = 5;
const MAX_HISTORY_PER_PAGE: usize = MAX_PULL_PAGE_ITEMS * MAX_HISTORY_PER_ITEM;
const MAX_PROJECTION_BYTES: usize = 32 * 1024 * 1024;
const MAX_ITEM_CIPHERTEXT_BYTES: usize = MAX_ITEM_PAYLOAD_BYTES + 256;
const MAX_CURSOR_BYTES: usize = 4_096;
const MAX_CHECKSUM_BYTES: usize = 256;
const MAX_TYPE_ID_BYTES: usize = 128;
const CACHE_KEY_FINGERPRINT_BYTES: usize = 12;
const MAX_EMAIL_BYTES: usize = 320;
const MAX_DISPLAY_NAME_BYTES: usize = 200;
const MAX_SERVER_URL_BYTES: usize = 2_048;
const MAX_SERVER_METADATA_BYTES: usize = 512;
const MAX_TIMESTAMP_BYTES: usize = 64;

mod model;
pub use model::*;
mod transaction;
use transaction::*;
mod storage;
use storage::*;
pub(crate) use storage::{
    claim_generation, ensure_bound_generation_and_advance, ensure_single_remote_storage,
    ensure_storage_proof, inspect_generation_binding, LocalGenerationBindingState,
};
mod checkpoint;
use checkpoint::*;
mod projection;
use projection::*;
mod validation;
pub(crate) use validation::validate_storage_proof;
use validation::*;

pub struct LocalSyncRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> LocalSyncRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Atomically publishes a push response after proving that its request
    /// cursor, items, and pending rows are still the exact local inputs used by
    /// the caller.
    pub async fn commit_push(&self, commit: &PushCommit) -> Result<PushReceipt, LocalSyncError> {
        validate_push(commit)?;
        let mut tx = self.begin_immediate().await?;
        let result = commit_push_in(&mut tx, commit).await;
        finish_transaction(tx, result).await
    }

    /// Commits a push response only while the exact endpoint/account binding
    /// and authorized configuration generation still match the local cache.
    pub async fn commit_push_leased(
        &self,
        commit: &PushCommit,
        expected_storage: &LocalStorageProof,
        generation: &LocalSyncGenerationProof,
    ) -> Result<PushReceipt, LocalSyncError> {
        validate_push(commit)?;
        validate_storage_proof(expected_storage)?;
        if expected_storage.id != commit.scope.storage_id {
            return invalid("push storage proof does not match its scope");
        }
        let mut tx = self.begin_immediate().await?;
        let result = commit_push_leased_in(&mut tx, commit, expected_storage, generation).await;
        finish_transaction(tx, result).await
    }

    /// Atomically installs a pull page and advances its cursor only after every
    /// item and complete history projection has been persisted.
    pub async fn commit_pull_page(&self, page: &PullPage) -> Result<PullReceipt, LocalSyncError> {
        validate_pull(page)?;
        let mut tx = self.begin_immediate().await?;
        let result = commit_pull_in(&mut tx, page).await;
        finish_transaction(tx, result).await
    }

    /// Commits a pull page only while the complete endpoint/account binding
    /// and the single-remote-cache invariant still match inside the same
    /// `BEGIN IMMEDIATE` transaction as the cursor and item CAS operations.
    pub async fn commit_pull_page_bound(
        &self,
        page: &PullPage,
        expected_storage: &LocalStorageProof,
    ) -> Result<PullReceipt, LocalSyncError> {
        validate_pull(page)?;
        validate_storage_proof(expected_storage)?;
        if expected_storage.id != page.scope.storage_id {
            return invalid("pull storage proof does not match its scope");
        }
        let mut tx = self.begin_immediate().await?;
        let result = commit_pull_bound_in(&mut tx, page, expected_storage).await;
        finish_transaction(tx, result).await
    }

    /// Commits a pull page only under an exact, already-claimed configuration
    /// generation.  A newer authorized revision advances the stored revision
    /// and content digest in the same writer transaction as the pull.  An
    /// equal revision must carry the exact same content digest; rollback and
    /// cross-repository/target reuse fail closed before projection writes.
    pub async fn commit_pull_page_leased(
        &self,
        page: &PullPage,
        expected_storage: &LocalStorageProof,
        generation: &LocalSyncGenerationProof,
    ) -> Result<PullReceipt, LocalSyncError> {
        validate_pull(page)?;
        validate_storage_proof(expected_storage)?;
        if expected_storage.id != page.scope.storage_id {
            return invalid("pull storage proof does not match its scope");
        }
        let mut tx = self.begin_immediate().await?;
        let result = commit_pull_leased_in(&mut tx, page, expected_storage, generation).await;
        finish_transaction(tx, result).await
    }

    /// Atomically removes only one storage's sync projection after checking the
    /// exact full storage row and proving that no pending, dirty-item, or local
    /// history state would be discarded.
    pub async fn reset_projection(
        &self,
        reset: &ResetProjection,
    ) -> Result<ResetReceipt, LocalSyncError> {
        validate_reset(reset)?;
        let mut tx = self.begin_immediate().await?;
        let result = reset_projection_in(&mut tx, reset).await;
        finish_transaction(tx, result).await
    }

    async fn begin_immediate(&self) -> Result<Transaction<'static, Sqlite>, LocalSyncError> {
        // SQLx 0.8 supports a custom SQLite begin statement. BEGIN IMMEDIATE
        // takes the single writer reservation before any CAS proof is read.
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(LocalSyncError::Database)
    }
}
