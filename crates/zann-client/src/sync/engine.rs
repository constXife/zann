use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use uuid::Uuid;
use zann_core::SyncStatus;

use super::model::{
    ItemState, PendingExpectation, PendingProof, PullCommitChange, PullPageCommit, PushCommitPlan,
    ReconciledCatalog, ResolvedSyncTarget, SyncCursor, SyncError, SyncErrorKind, SyncFuture,
    SyncLocalStore, SyncOutcome, SyncOutcomeStatus, SyncProgress, SyncProgressPhase,
    SyncProgressSink, SyncSeq, SyncStage, SyncStoreError, SyncStoreErrorKind, VaultPlane,
    MAX_CATALOG_VAULTS, MAX_PULL_CHANGES, MAX_PULL_PAGES,
};
use super::transport::{HttpSyncRemote, RemoteError, RemoteErrorKind, RemoteFuture, SyncRemote};
use super::wire::{
    validate_personal_page, validate_push_response, validate_shared_page, PullPageWire,
    ValidatedPullPage, WireError, WireErrorKind,
};
use crate::session::{
    AppSession, OperationCompletion, SessionAccess, SessionError, SessionErrorKind,
    SessionOperation, SessionTarget,
};
use zann_core::ChangeType;

const MAX_REQUEST_TIME: Duration = Duration::from_secs(30);

type AuthorizeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SessionAccess, SessionError>> + Send + 'a>>;

trait SyncAuthorizer: Send + Sync {
    fn authorize<'a>(
        &'a self,
        target: &'a SessionTarget,
        operation: SessionOperation,
    ) -> AuthorizeFuture<'a>;
}

impl SyncAuthorizer for AppSession {
    fn authorize<'a>(
        &'a self,
        target: &'a SessionTarget,
        operation: SessionOperation,
    ) -> AuthorizeFuture<'a> {
        Box::pin(async move { self.access(target, operation).await })
    }
}

struct NoopProgress;

impl SyncProgressSink for NoopProgress {
    fn report(&self, _progress: SyncProgress) {}
}

/// Persistence-independent bidirectional synchronization owner.
#[cfg_attr(not(feature = "app"), allow(dead_code))]
pub(crate) struct SyncEngine {
    authorizer: Arc<dyn SyncAuthorizer>,
    local: Arc<dyn SyncLocalStore>,
    remote: Result<Arc<dyn SyncRemote>, RemoteErrorKind>,
    progress: Arc<dyn SyncProgressSink>,
}

#[cfg_attr(not(feature = "app"), allow(dead_code))]
impl SyncEngine {
    #[must_use]
    pub(crate) fn new(session: AppSession, local: Arc<dyn SyncLocalStore>) -> Self {
        let remote = HttpSyncRemote::new()
            .map(|remote| Arc::new(remote) as Arc<dyn SyncRemote>)
            .map_err(RemoteError::kind);
        Self {
            authorizer: Arc::new(session),
            local,
            remote,
            progress: Arc::new(NoopProgress),
        }
    }

    /// Installs a metadata-only progress observer. It never receives item IDs,
    /// paths, payloads, keys, cursors or endpoint data.
    #[must_use]
    pub(crate) fn with_progress(mut self, progress: Arc<dyn SyncProgressSink>) -> Self {
        self.progress = progress;
        self
    }

    /// Synchronizes all full-cache vaults for one explicit target.
    pub(crate) fn pull<'a>(
        &'a self,
        target: &'a SessionTarget,
        operation: SessionOperation,
    ) -> SyncFuture<'a, SyncOutcome> {
        Box::pin(async move { self.pull_inner(target, operation).await })
    }

    async fn pull_inner(
        &self,
        target: &SessionTarget,
        operation: SessionOperation,
    ) -> Result<SyncOutcome, SyncError> {
        let operation_id = operation.operation_id();
        self.ensure_dispatchable(&operation, SyncStage::Authorization)?;
        self.report(operation_id, SyncProgressPhase::Authorizing, 0, 0, 0, 0);
        let access = self
            .authorizer
            .authorize(target, operation.detached_copy())
            .await
            .map_err(map_session_error)?;

        let access_storage_id = access
            .storage_id()
            .and_then(|value| Uuid::parse_str(value).ok())
            .filter(|value| !value.is_nil())
            .ok_or_else(|| {
                SyncError::new(
                    operation_id,
                    SyncErrorKind::NoLocalTarget,
                    SyncStage::ResolveTarget,
                )
            })?;
        let access_account_subject = access
            .account_subject()
            .filter(|subject| {
                Uuid::parse_str(subject).is_ok_and(|parsed| parsed.to_string() == *subject)
            })
            .ok_or_else(|| {
                SyncError::new(
                    operation_id,
                    SyncErrorKind::AccountBindingRequired,
                    SyncStage::ResolveTarget,
                )
            })?;
        let access_auth_method = access.auth_method().ok_or_else(|| {
            SyncError::new(
                operation_id,
                SyncErrorKind::AuthenticationBindingRequired,
                SyncStage::ResolveTarget,
            )
        })?;

        self.ensure_dispatchable(&operation, SyncStage::ResolveTarget)?;
        let authorized_target_generation = access.authorized_target_generation();
        let resolved = self
            .local
            .resolve_target(
                target,
                authorized_target_generation,
                access.personal_vaults_enabled(),
            )
            .await
            .map_err(|error| map_store_error(operation_id, SyncStage::ResolveTarget, error))?;
        if resolved.storage_id() != access_storage_id
            || resolved.binding().server_url() != access.endpoint()
            || resolved.binding().server_fingerprint() != access.server_fingerprint()
        {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::ConcurrentLocalChange,
                SyncStage::ResolveTarget,
            ));
        }
        if resolved.binding().account_subject() != Some(access_account_subject) {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::AccountBindingMismatch,
                SyncStage::ResolveTarget,
            ));
        }
        if resolved.binding().personal_vaults_enabled() != access.personal_vaults_enabled() {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::ServerCapabilityMismatch,
                SyncStage::ResolveTarget,
            ));
        }
        let local_auth_method = resolved.binding().auth_method().ok_or_else(|| {
            SyncError::new(
                operation_id,
                SyncErrorKind::AuthenticationBindingRequired,
                SyncStage::ResolveTarget,
            )
        })?;
        if local_auth_method != access_auth_method {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::AuthenticationBindingMismatch,
                SyncStage::ResolveTarget,
            ));
        }

        self.ensure_dispatchable(&operation, SyncStage::Catalog)?;
        self.report(operation_id, SyncProgressPhase::Catalog, 0, 0, 0, 0);
        let remote = self.remote.as_ref().map_err(|_| {
            SyncError::new(
                operation_id,
                SyncErrorKind::TransportUnavailable,
                SyncStage::Catalog,
            )
        })?;
        let timeout = request_timeout(&operation, SyncStage::Catalog)?;
        let mut catalog = self
            .await_remote(
                &operation,
                SyncStage::Catalog,
                remote.fetch_catalog(&access, timeout),
            )
            .await?;
        if !access.personal_vaults_enabled()
            && catalog
                .vaults()
                .iter()
                .any(|vault| vault.plane() == VaultPlane::PersonalClient)
        {
            return Err(SyncError::new(
                operation_id,
                SyncErrorKind::ServerCapabilityMismatch,
                SyncStage::Catalog,
            ));
        }
        let uninitialized_personal = catalog
            .vaults()
            .iter()
            .filter(|vault| {
                vault.plane() == VaultPlane::PersonalClient && vault.vault_key_envelope().is_empty()
            })
            .map(super::model::CatalogVault::id)
            .collect::<Vec<_>>();
        for vault_id in uninitialized_personal {
            self.ensure_dispatchable(&operation, SyncStage::ReconcileCatalog)?;
            let scope =
                super::model::SyncScope::new(resolved.storage_id(), vault_id).map_err(|_| {
                    SyncError::new(
                        operation_id,
                        SyncErrorKind::Protocol,
                        SyncStage::ReconcileCatalog,
                    )
                })?;
            let publication = Arc::clone(&self.local)
                .prepare_generated_key(scope, Vec::new())
                .await
                .map_err(|error| {
                    map_store_error(operation_id, SyncStage::ReconcileCatalog, error)
                })?;
            let published_envelope = publication.published_envelope().to_vec();
            let timeout = request_timeout(&operation, SyncStage::Catalog)?;
            self.await_remote(
                &operation,
                SyncStage::Catalog,
                remote.publish_personal_vault_key(&access, vault_id, &published_envelope, timeout),
            )
            .await?;
            tokio::spawn(Arc::clone(&self.local).commit_generated_key(publication))
                .await
                .map_err(|_| {
                    SyncError::new(
                        operation_id,
                        SyncErrorKind::Internal,
                        SyncStage::ReconcileCatalog,
                    )
                })?
                .map_err(|error| {
                    map_store_error(operation_id, SyncStage::ReconcileCatalog, error)
                })?;
            catalog
                .install_generated_envelope(vault_id, &[], published_envelope)
                .map_err(|_| {
                    SyncError::new(
                        operation_id,
                        SyncErrorKind::Internal,
                        SyncStage::ReconcileCatalog,
                    )
                })?;
        }
        let catalog = Arc::new(catalog);
        let resolved = Arc::new(resolved);

        self.ensure_dispatchable(&operation, SyncStage::ReconcileCatalog)?;
        // Reconciliation may be transactional. Its owned terminal task keeps
        // running if the caller cancels or drops the outer pull future.
        let reconciled = tokio::spawn(
            Arc::clone(&self.local).reconcile_catalog(Arc::clone(&resolved), Arc::clone(&catalog)),
        )
        .await
        .map_err(|_| {
            SyncError::new(
                operation_id,
                SyncErrorKind::Internal,
                SyncStage::ReconcileCatalog,
            )
        })?
        .map_err(|error| map_store_error(operation_id, SyncStage::ReconcileCatalog, error))?;
        validate_reconciled_catalog(&resolved, &catalog, &reconciled)
            .map_err(|kind| SyncError::new(operation_id, kind, SyncStage::ReconcileCatalog))?;

        let vault_count = reconciled.vaults().len();
        let mut pages_committed = 0_usize;
        let mut changes_committed = 0_usize;
        // Catalog reconciliation may already have committed metadata or key
        // state. Cancellation after it is therefore a successful partial
        // outcome even before the first pull page.
        if let Some(outcome) =
            self.partial_if_stopped(&operation, vault_count, pages_committed, changes_committed)?
        {
            return Ok(outcome);
        }
        for (vault_index, vault) in reconciled.vaults().iter().enumerate() {
            let mut vault_pages = 0_usize;
            if let Some(outcome) = self.partial_if_stopped(
                &operation,
                vault_count,
                pages_committed,
                changes_committed,
            )? {
                return Ok(outcome);
            }

            let checkpoint = self
                .local
                .load_checkpoint(vault.scope())
                .await
                .map_err(|error| map_store_error(operation_id, SyncStage::LoadCheckpoint, error))?;
            if checkpoint
                .pending()
                .iter()
                .any(|proof| proof.scope() != vault.scope())
            {
                return Err(SyncError::new(
                    operation_id,
                    SyncErrorKind::Local,
                    SyncStage::LoadCheckpoint,
                ));
            }
            let checkpoint_sequence = checkpoint.cursor().map(SyncCursor::sequence).unwrap_or(0);
            let durable_sequence = checkpoint.last_seq().map(SyncSeq::get).unwrap_or(0);
            if checkpoint_sequence != durable_sequence {
                return Err(SyncError::new(
                    operation_id,
                    SyncErrorKind::Local,
                    SyncStage::LoadCheckpoint,
                ));
            }
            let (cursor, last_seq, pending) = checkpoint.into_parts();
            if !pending.is_empty() {
                self.ensure_dispatchable(&operation, SyncStage::Push)?;
                self.report(
                    operation_id,
                    SyncProgressPhase::Pushing,
                    vault_index,
                    vault_count,
                    pages_committed,
                    changes_committed,
                );
                let item_ids = pending
                    .iter()
                    .map(super::model::PendingProof::item_id)
                    .collect::<Vec<_>>();
                let states = self
                    .local
                    .load_item_states(vault.scope(), &item_ids)
                    .await
                    .map_err(|error| {
                        map_store_error(operation_id, SyncStage::LoadItemStates, error)
                    })?;
                let states = validate_item_states_for_push(vault.scope(), &pending, states)
                    .map_err(|kind| {
                        SyncError::new(operation_id, kind, SyncStage::LoadItemStates)
                    })?;
                let timeout = request_timeout(&operation, SyncStage::Push)?;
                let response = self
                    .await_remote(
                        &operation,
                        SyncStage::Push,
                        remote.push(&access, vault, &pending, timeout),
                    )
                    .await?;
                let pushed_count = pending.len();
                let (server_head, pushed) = validate_push_response(
                    vault.scope(),
                    vault.payload_key(),
                    pending,
                    states.into_values().collect(),
                    response,
                )
                .map_err(|error| map_wire_error(operation_id, SyncStage::Push, error))?;
                let plan = PushCommitPlan::new(
                    vault.scope(),
                    cursor.clone(),
                    last_seq,
                    server_head.clone(),
                    pushed,
                )
                .map_err(|_| {
                    SyncError::new(operation_id, SyncErrorKind::Internal, SyncStage::Push)
                })?;
                let receipt = tokio::spawn(Arc::clone(&self.local).commit_push(plan))
                    .await
                    .map_err(|_| {
                        SyncError::new(operation_id, SyncErrorKind::Internal, SyncStage::Push)
                    })?
                    .map_err(|error| map_store_error(operation_id, SyncStage::Push, error))?;
                if receipt.pending_deleted() != pushed_count
                    || receipt.server_head_hint() != &server_head
                {
                    return Err(SyncError::new(
                        operation_id,
                        SyncErrorKind::Local,
                        SyncStage::Push,
                    ));
                }
                changes_committed =
                    changes_committed.checked_add(pushed_count).ok_or_else(|| {
                        SyncError::new(operation_id, SyncErrorKind::LimitExceeded, SyncStage::Push)
                    })?;
            }

            let mut cursor = cursor;
            let mut last_seq = last_seq;
            loop {
                if vault_pages >= MAX_PULL_PAGES || changes_committed >= MAX_PULL_CHANGES {
                    return Err(SyncError::new(
                        operation_id,
                        SyncErrorKind::LimitExceeded,
                        SyncStage::Pull,
                    ));
                }
                if let Some(outcome) = self.partial_if_stopped(
                    &operation,
                    vault_count,
                    pages_committed,
                    changes_committed,
                )? {
                    return Ok(outcome);
                }
                self.report(
                    operation_id,
                    SyncProgressPhase::Pulling,
                    vault_index,
                    vault_count,
                    pages_committed,
                    changes_committed,
                );
                let timeout = request_timeout(&operation, SyncStage::Pull)?;
                self.ensure_dispatchable(&operation, SyncStage::Pull)?;
                let pulled = self
                    .await_remote(
                        &operation,
                        SyncStage::Pull,
                        remote.pull_page(
                            &access,
                            vault.scope().vault_id(),
                            vault.plane(),
                            cursor.as_ref(),
                            timeout,
                        ),
                    )
                    .await;
                let page_wire = match pulled {
                    Ok(page) => page,
                    Err(error)
                        if matches!(
                            error.kind(),
                            SyncErrorKind::Cancelled | SyncErrorKind::DeadlineExceeded
                        ) =>
                    {
                        return Ok(partial_outcome(
                            &operation,
                            vault_count,
                            pages_committed,
                            changes_committed,
                            error.kind(),
                        ));
                    }
                    Err(error) => return Err(error),
                };

                // Every duplicate is validated before coalescing and before
                // the first local read or write for this page.
                let page = validate_page_for_vault(
                    vault.plane(),
                    vault.scope(),
                    cursor.as_ref(),
                    last_seq,
                    vault.payload_key(),
                    page_wire,
                )
                .map_err(|error| map_wire_error(operation_id, SyncStage::Pull, error))?;
                // This legacy authorization hint is not an idempotency
                // capability and therefore cannot activate clean push.
                let _legacy_push_authorized = page.push_available;
                let next_total = changes_committed
                    .checked_add(page.wire_change_count)
                    .ok_or_else(|| {
                        SyncError::new(operation_id, SyncErrorKind::LimitExceeded, SyncStage::Pull)
                    })?;
                if next_total > MAX_PULL_CHANGES {
                    return Err(SyncError::new(
                        operation_id,
                        SyncErrorKind::LimitExceeded,
                        SyncStage::Pull,
                    ));
                }

                let item_ids = page
                    .changes
                    .iter()
                    .map(|change| change.item.item_id())
                    .collect::<Vec<_>>();
                self.ensure_dispatchable(&operation, SyncStage::LoadItemStates)?;
                let states = self
                    .local
                    .load_item_states(vault.scope(), &item_ids)
                    .await
                    .map_err(|error| {
                        map_store_error(operation_id, SyncStage::LoadItemStates, error)
                    })?;
                let mut states =
                    validate_item_states(vault.scope(), &item_ids, states).map_err(|kind| {
                        SyncError::new(operation_id, kind, SyncStage::LoadItemStates)
                    })?;

                let mut changes = Vec::with_capacity(page.changes.len());
                for change in page.changes {
                    let item_id = change.item.item_id();
                    let expected = states.remove(&item_id).ok_or_else(|| {
                        SyncError::new(
                            operation_id,
                            SyncErrorKind::Local,
                            SyncStage::LoadItemStates,
                        )
                    })?;
                    if let Some(proof) = expected.exact_proof() {
                        if proof.sync_status() != SyncStatus::Synced
                            || proof.projection().seq() >= change.item.seq()
                        {
                            return Err(SyncError::new(
                                operation_id,
                                SyncErrorKind::ConcurrentLocalChange,
                                SyncStage::LoadItemStates,
                            ));
                        }
                    }
                    changes.push(PullCommitChange::validated(
                        expected,
                        change.item,
                        change.history,
                    ));
                }

                if let Some(outcome) = self.partial_if_stopped(
                    &operation,
                    vault_count,
                    pages_committed,
                    changes_committed,
                )? {
                    return Ok(outcome);
                }

                let has_more = page.has_more;
                let page_last_seq = page.last_seq;
                let next_cursor = page.next_cursor.clone();
                let expected_history_entries = changes
                    .iter()
                    .map(|change| change.history().len())
                    .sum::<usize>();
                let commit = PullPageCommit::validated(
                    vault.scope(),
                    vault.payload_key().cache_key_fingerprint().to_string(),
                    cursor.clone(),
                    last_seq,
                    page.next_cursor,
                    page_last_seq,
                    Utc::now(),
                    changes,
                )
                .map_err(|_| {
                    SyncError::new(
                        operation_id,
                        SyncErrorKind::Internal,
                        SyncStage::CommitPullPage,
                    )
                })?;
                self.report(
                    operation_id,
                    SyncProgressPhase::Committing,
                    vault_index,
                    vault_count,
                    pages_committed,
                    changes_committed,
                );
                let expected_items = commit.changes().len();
                // Once dispatched, the owned terminal task is not raced
                // against cancellation and survives Drop of the outer pull.
                let receipt = tokio::spawn(Arc::clone(&self.local).commit_pull_page(commit))
                    .await
                    .map_err(|_| {
                        SyncError::new(
                            operation_id,
                            SyncErrorKind::Internal,
                            SyncStage::CommitPullPage,
                        )
                    })?
                    .map_err(|error| {
                        map_store_error(operation_id, SyncStage::CommitPullPage, error)
                    })?;
                if receipt.items() != expected_items
                    || receipt.history_entries() != expected_history_entries
                    || receipt.cursor() != &next_cursor
                    || receipt.last_seq() != page_last_seq
                {
                    return Err(SyncError::new(
                        operation_id,
                        SyncErrorKind::Local,
                        SyncStage::CommitPullPage,
                    ));
                }
                vault_pages = vault_pages.checked_add(1).ok_or_else(|| {
                    SyncError::new(operation_id, SyncErrorKind::LimitExceeded, SyncStage::Pull)
                })?;
                pages_committed = pages_committed.checked_add(1).ok_or_else(|| {
                    SyncError::new(operation_id, SyncErrorKind::LimitExceeded, SyncStage::Pull)
                })?;
                changes_committed = next_total;
                cursor = Some(next_cursor);
                last_seq = page_last_seq;

                if !has_more {
                    break;
                }
            }
        }

        self.report(
            operation_id,
            SyncProgressPhase::Complete,
            vault_count,
            vault_count,
            pages_committed,
            changes_committed,
        );
        Ok(SyncOutcome::new(
            operation_id,
            SyncOutcomeStatus::Complete,
            operation.completion(),
            vault_count,
            pages_committed,
            changes_committed,
        ))
    }

    fn ensure_dispatchable(
        &self,
        operation: &SessionOperation,
        stage: SyncStage,
    ) -> Result<(), SyncError> {
        match operation.pre_dispatch_error() {
            Some(SessionErrorKind::Cancelled) => Err(SyncError::new(
                operation.operation_id(),
                SyncErrorKind::Cancelled,
                stage,
            )),
            Some(SessionErrorKind::DeadlineExceeded) => Err(SyncError::new(
                operation.operation_id(),
                SyncErrorKind::DeadlineExceeded,
                stage,
            )),
            Some(_) => Err(SyncError::new(
                operation.operation_id(),
                SyncErrorKind::Internal,
                stage,
            )),
            None => Ok(()),
        }
    }

    async fn await_remote<T>(
        &self,
        operation: &SessionOperation,
        stage: SyncStage,
        future: RemoteFuture<'_, T>,
    ) -> Result<T, SyncError> {
        let deadline = tokio::time::Instant::from_std(operation.deadline());
        tokio::select! {
            biased;
            () = operation.cancelled() => Err(SyncError::new(
                operation.operation_id(),
                SyncErrorKind::Cancelled,
                stage,
            )),
            () = tokio::time::sleep_until(deadline) => Err(SyncError::new(
                operation.operation_id(),
                SyncErrorKind::DeadlineExceeded,
                stage,
            )),
            result = future => result.map_err(|error| map_remote_error(operation.operation_id(), stage, error)),
        }
    }

    fn partial_if_stopped(
        &self,
        operation: &SessionOperation,
        vault_count: usize,
        pages_committed: usize,
        changes_committed: usize,
    ) -> Result<Option<SyncOutcome>, SyncError> {
        let Some(error) = operation.pre_dispatch_error() else {
            return Ok(None);
        };
        let kind = match error {
            SessionErrorKind::Cancelled => SyncErrorKind::Cancelled,
            SessionErrorKind::DeadlineExceeded => SyncErrorKind::DeadlineExceeded,
            _ => SyncErrorKind::Internal,
        };
        Ok(Some(partial_outcome(
            operation,
            vault_count,
            pages_committed,
            changes_committed,
            kind,
        )))
    }

    fn report(
        &self,
        operation_id: crate::session::SessionOperationId,
        phase: SyncProgressPhase,
        vault_index: usize,
        vault_count: usize,
        pages_committed: usize,
        changes_committed: usize,
    ) {
        self.progress.report(SyncProgress::new(
            operation_id,
            phase,
            vault_index,
            vault_count,
            pages_committed,
            changes_committed,
        ));
    }

    #[cfg(test)]
    fn with_components(
        authorizer: Arc<dyn SyncAuthorizer>,
        local: Arc<dyn SyncLocalStore>,
        remote: Arc<dyn SyncRemote>,
    ) -> Self {
        Self {
            authorizer,
            local,
            remote: Ok(remote),
            progress: Arc::new(NoopProgress),
        }
    }
}

impl std::fmt::Debug for SyncEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SyncEngine").finish_non_exhaustive()
    }
}

fn request_timeout(operation: &SessionOperation, stage: SyncStage) -> Result<Duration, SyncError> {
    let remaining = operation
        .deadline()
        .checked_duration_since(std::time::Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            SyncError::new(
                operation.operation_id(),
                SyncErrorKind::DeadlineExceeded,
                stage,
            )
        })?;
    Ok(remaining.min(MAX_REQUEST_TIME))
}

fn validate_reconciled_catalog(
    target: &ResolvedSyncTarget,
    catalog: &super::model::CatalogSnapshot,
    reconciled: &ReconciledCatalog,
) -> Result<(), SyncErrorKind> {
    if reconciled.vaults().len() != catalog.vaults().len()
        || reconciled.vaults().len() > MAX_CATALOG_VAULTS
    {
        return Err(SyncErrorKind::Local);
    }
    let expected = catalog
        .vaults()
        .iter()
        .map(|vault| (vault.id(), vault.plane()))
        .collect::<HashMap<_, _>>();
    let mut actual = HashSet::with_capacity(reconciled.vaults().len());
    for vault in reconciled.vaults() {
        if vault.scope().storage_id() != target.storage_id()
            || expected.get(&vault.scope().vault_id()) != Some(&vault.plane())
            || !actual.insert(vault.scope().vault_id())
        {
            return Err(SyncErrorKind::Local);
        }
    }
    Ok(())
}

fn validate_page_for_vault(
    plane: VaultPlane,
    scope: super::model::SyncScope,
    expected_cursor: Option<&super::model::SyncCursor>,
    prior_seq: Option<super::model::SyncSeq>,
    key: &super::model::VaultPayloadKey,
    page: PullPageWire,
) -> Result<ValidatedPullPage, WireError> {
    match (plane, page) {
        (VaultPlane::PersonalClient, PullPageWire::Personal(page)) => {
            validate_personal_page(scope, expected_cursor, prior_seq, key, page)
        }
        (VaultPlane::SharedServer, PullPageWire::Shared(page)) => {
            validate_shared_page(scope, expected_cursor, prior_seq, key, page)
        }
        _ => Err(WireError::from(super::model::SyncModelError::PageTooLarge)),
    }
}

fn validate_item_states(
    scope: super::model::SyncScope,
    requested: &[Uuid],
    states: Vec<ItemState>,
) -> Result<HashMap<Uuid, ItemState>, SyncErrorKind> {
    if requested.len() != states.len() {
        return Err(SyncErrorKind::Local);
    }
    let requested = requested.iter().copied().collect::<HashSet<_>>();
    let mut mapped = HashMap::with_capacity(states.len());
    for state in states {
        let item_id = state.item_id();
        if !requested.contains(&item_id)
            || !matches!(state.pending(), PendingExpectation::Absent)
            || state
                .exact_proof()
                .is_some_and(|proof| proof.projection().scope() != scope)
            || mapped.insert(item_id, state).is_some()
        {
            return Err(SyncErrorKind::ConcurrentLocalChange);
        }
    }
    Ok(mapped)
}

/// Push preparation accepts exactly the durable pending rows the checkpoint
/// observed: the store must still report each row under the same pending id,
/// and the projection expectation must match the operation (a create has no
/// prior row; every other operation rewrites an existing synced projection).
/// Anything else means a local edit raced this operation.
fn validate_item_states_for_push(
    scope: super::model::SyncScope,
    pending: &[PendingProof],
    states: Vec<ItemState>,
) -> Result<HashMap<Uuid, ItemState>, SyncErrorKind> {
    if pending.len() != states.len() {
        return Err(SyncErrorKind::Local);
    }
    let expected_by_item = pending
        .iter()
        .map(|proof| (proof.item_id(), proof))
        .collect::<HashMap<_, _>>();
    if expected_by_item.len() != pending.len() {
        return Err(SyncErrorKind::Local);
    }
    let mut mapped = HashMap::with_capacity(states.len());
    for state in states {
        let item_id = state.item_id();
        let expected = expected_by_item.get(&item_id).ok_or(SyncErrorKind::Local)?;
        match state.pending() {
            PendingExpectation::Exact(durable)
                if durable.pending_id() == expected.pending_id()
                    && durable.item_id() == expected.item_id() => {}
            _ => return Err(SyncErrorKind::ConcurrentLocalChange),
        }
        let creates_item = matches!(expected.operation(), ChangeType::Create);
        if creates_item != state.exact_proof().is_none()
            || state
                .exact_proof()
                .is_some_and(|proof| proof.projection().scope() != scope)
            || mapped.insert(item_id, state).is_some()
        {
            return Err(SyncErrorKind::ConcurrentLocalChange);
        }
    }
    Ok(mapped)
}

fn map_session_error(error: SessionError) -> SyncError {
    let kind = match error.kind() {
        SessionErrorKind::Cancelled => SyncErrorKind::Cancelled,
        SessionErrorKind::DeadlineExceeded => SyncErrorKind::DeadlineExceeded,
        SessionErrorKind::SessionExpired => SyncErrorKind::SessionExpired,
        SessionErrorKind::TransportUnavailable => SyncErrorKind::TransportUnavailable,
        SessionErrorKind::TransportRejected => SyncErrorKind::TransportRejected,
        SessionErrorKind::Protocol => SyncErrorKind::Protocol,
        _ => SyncErrorKind::Session,
    };
    SyncError::new(error.operation_id(), kind, SyncStage::Authorization).with_status(error.status())
}

fn map_remote_error(
    operation_id: crate::session::SessionOperationId,
    stage: SyncStage,
    error: RemoteError,
) -> SyncError {
    let kind = match error.kind() {
        RemoteErrorKind::Timeout => SyncErrorKind::Timeout,
        RemoteErrorKind::Unavailable | RemoteErrorKind::Server => {
            SyncErrorKind::TransportUnavailable
        }
        RemoteErrorKind::Rejected => SyncErrorKind::TransportRejected,
        RemoteErrorKind::Conflict => SyncErrorKind::ConcurrentRemoteChange,
        RemoteErrorKind::SessionExpired => SyncErrorKind::SessionExpired,
        RemoteErrorKind::BodyTooLarge => SyncErrorKind::BodyTooLarge,
        RemoteErrorKind::InvalidEndpoint | RemoteErrorKind::Protocol => SyncErrorKind::Protocol,
    };
    SyncError::new(operation_id, kind, stage).with_status(error.status())
}

fn map_wire_error(
    operation_id: crate::session::SessionOperationId,
    stage: SyncStage,
    error: WireError,
) -> SyncError {
    let kind = match error.kind() {
        WireErrorKind::Limit => SyncErrorKind::LimitExceeded,
        WireErrorKind::Crypto => SyncErrorKind::Crypto,
        WireErrorKind::Conflict => SyncErrorKind::ConcurrentRemoteChange,
        _ => SyncErrorKind::Protocol,
    };
    SyncError::new(operation_id, kind, stage)
}

fn map_store_error(
    operation_id: crate::session::SessionOperationId,
    stage: SyncStage,
    error: SyncStoreError,
) -> SyncError {
    let kind = match error.kind() {
        SyncStoreErrorKind::StaleCheckpoint
        | SyncStoreErrorKind::StaleKeyBinding
        | SyncStoreErrorKind::StaleItem
        | SyncStoreErrorKind::PendingChanged
        | SyncStoreErrorKind::PendingPresent => SyncErrorKind::ConcurrentLocalChange,
        SyncStoreErrorKind::CommitOutcomeUnknown => SyncErrorKind::CommitOutcomeUnknown,
        _ => SyncErrorKind::Local,
    };
    SyncError::new(operation_id, kind, stage)
}

fn partial_outcome(
    operation: &SessionOperation,
    vault_count: usize,
    pages_committed: usize,
    changes_committed: usize,
    kind: SyncErrorKind,
) -> SyncOutcome {
    let status = if kind == SyncErrorKind::DeadlineExceeded {
        SyncOutcomeStatus::DeadlinePartial
    } else {
        SyncOutcomeStatus::CancelledPartial
    };
    let completion = if kind == SyncErrorKind::DeadlineExceeded {
        OperationCompletion::AfterDeadline
    } else {
        OperationCompletion::AfterCancellation
    };
    SyncOutcome::new(
        operation.operation_id(),
        status,
        completion,
        vault_count,
        pages_committed,
        changes_committed,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Instant;

    use base64::Engine as _;
    use zann_core::{AuthMethod, CachePolicy, ChangeType, VaultEncryptionType, VaultKind};
    use zann_crypto::{EncryptedPayload, SecretKey};

    use super::*;
    use crate::config::ConnectionId;
    use crate::session::{SessionCancellationHandle, SessionOperationId};
    use crate::sync::model::{
        GeneratedVaultKeyCommit, PendingProof, ProjectionReset, PullCommitReceipt, PushCommitPlan,
        PushCommitReceipt, ResolvedSyncVault, StorageBindingProof, SyncCheckpoint, SyncCursor,
        SyncScope, SyncSeq, SyncStoreFuture, VaultPayloadKey,
    };
    use crate::sync::wire::{
        validate_catalog, AppliedPushChangeWire, PersonalHistoryWire, PersonalPullChangeWire,
        PersonalPullPageWire, PushConflictWire, PushResponseWire, SharedPullChangeWire,
        SharedPullPageWire, VaultDetailWire, VaultListWire, VaultSummaryWire,
    };

    const ENDPOINT: &str = "https://sync.example.test";
    const FINGERPRINT: &str = "server-fingerprint";
    const TIMESTAMP: &str = "2025-01-02T03:04:05Z";

    fn cursor_string(sequence: i64) -> String {
        base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(&serde_json::json!({ "seq": sequence }))
                .expect("serialize test cursor"),
        )
    }

    struct FakeAuthorizer {
        storage_id: Option<Uuid>,
        account_subject: Mutex<Option<String>>,
        auth_method: Mutex<Option<AuthMethod>>,
        personal_vaults_enabled: AtomicBool,
        calls: AtomicUsize,
    }

    impl SyncAuthorizer for FakeAuthorizer {
        fn authorize<'a>(
            &'a self,
            target: &'a SessionTarget,
            operation: SessionOperation,
        ) -> AuthorizeFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let target = target.clone();
            let storage_id = self.storage_id.map(|value| value.to_string());
            let account_subject = self
                .account_subject
                .lock()
                .expect("account subject lock")
                .clone();
            let auth_method = *self.auth_method.lock().expect("auth method lock");
            let personal_vaults_enabled = self.personal_vaults_enabled.load(Ordering::SeqCst);
            Box::pin(async move {
                Ok(SessionAccess::for_sync_test(
                    operation.operation_id(),
                    target,
                    ENDPOINT,
                    storage_id,
                    FINGERPRINT,
                    (account_subject, auth_method),
                    personal_vaults_enabled,
                ))
            })
        }
    }

    struct FakeRemote {
        vaults: Vec<(Uuid, VaultPlane)>,
        pages: Mutex<HashMap<Uuid, VecDeque<PullPageWire>>>,
        push_response: Mutex<Option<PushResponseWire>>,
        catalog_calls: AtomicUsize,
        pull_calls: AtomicUsize,
        push_calls: AtomicUsize,
    }

    impl FakeRemote {
        fn with_vaults(vaults: Vec<(Uuid, VaultPlane, Vec<PullPageWire>)>) -> Self {
            let catalog_vaults = vaults
                .iter()
                .map(|(vault_id, plane, _)| (*vault_id, *plane))
                .collect();
            let pages = vaults
                .into_iter()
                .map(|(vault_id, _, pages)| (vault_id, pages.into()))
                .collect();
            Self {
                vaults: catalog_vaults,
                pages: Mutex::new(pages),
                push_response: Mutex::new(None),
                catalog_calls: AtomicUsize::new(0),
                pull_calls: AtomicUsize::new(0),
                push_calls: AtomicUsize::new(0),
            }
        }

        fn catalog(&self) -> Result<crate::sync::CatalogSnapshot, RemoteError> {
            let mut summaries = Vec::with_capacity(self.vaults.len());
            let mut details = Vec::with_capacity(self.vaults.len());
            for (index, (vault_id, plane)) in self.vaults.iter().copied().enumerate() {
                let (kind, encryption) = match plane {
                    VaultPlane::PersonalClient => (
                        VaultKind::Personal.as_i32(),
                        VaultEncryptionType::Client.as_i32(),
                    ),
                    VaultPlane::SharedServer => (
                        VaultKind::Shared.as_i32(),
                        VaultEncryptionType::Server.as_i32(),
                    ),
                };
                let id = vault_id.to_string();
                let slug = format!("vault-{index}");
                let name = format!("Vault {index}");
                summaries.push(VaultSummaryWire {
                    id: id.clone(),
                    slug: slug.clone(),
                    name: name.clone(),
                    kind,
                    cache_policy: CachePolicy::Full.as_i32(),
                    tags: Some(vec!["test".to_string()]),
                });
                details.push(VaultDetailWire {
                    id: id.clone(),
                    slug,
                    name,
                    kind,
                    cache_policy: CachePolicy::Full.as_i32(),
                    vault_key_enc: vec![1, 2, 3],
                    encryption_type: encryption,
                    tags: Some(vec!["test".to_string()]),
                    created_at: TIMESTAMP.to_string(),
                });
            }
            validate_catalog(VaultListWire { vaults: summaries }, details)
                .map_err(|_| RemoteError::new(RemoteErrorKind::Protocol))
        }
    }

    impl SyncRemote for FakeRemote {
        fn fetch_catalog<'a>(
            &'a self,
            _access: &'a SessionAccess,
            _timeout: Duration,
        ) -> RemoteFuture<'a, crate::sync::CatalogSnapshot> {
            self.catalog_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { self.catalog() })
        }

        fn pull_page<'a>(
            &'a self,
            _access: &'a SessionAccess,
            vault_id: Uuid,
            plane: VaultPlane,
            _cursor: Option<&'a SyncCursor>,
            _timeout: Duration,
        ) -> RemoteFuture<'a, PullPageWire> {
            self.pull_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if !self.vaults.iter().any(|(expected_id, expected_plane)| {
                    *expected_id == vault_id && *expected_plane == plane
                }) {
                    return Err(RemoteError::new(RemoteErrorKind::Protocol));
                }
                self.pages
                    .lock()
                    .map_err(|_| RemoteError::new(RemoteErrorKind::Unavailable))?
                    .get_mut(&vault_id)
                    .ok_or_else(|| RemoteError::new(RemoteErrorKind::Protocol))?
                    .pop_front()
                    .ok_or_else(|| RemoteError::new(RemoteErrorKind::Protocol))
            })
        }

        fn push<'a>(
            &'a self,
            _access: &'a SessionAccess,
            _vault: &'a ResolvedSyncVault,
            _pending: &'a [PendingProof],
            _timeout: Duration,
        ) -> RemoteFuture<'a, PushResponseWire> {
            self.push_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                self.push_response
                    .lock()
                    .map_err(|_| RemoteError::new(RemoteErrorKind::Unavailable))?
                    .take()
                    .ok_or_else(|| RemoteError::new(RemoteErrorKind::Unavailable))
            })
        }
    }

    struct FakeStore {
        storage_id: Uuid,
        default_checkpoint: Mutex<(Option<String>, Option<i64>)>,
        committed_checkpoints: Mutex<HashMap<SyncScope, (String, Option<i64>)>>,
        checkpoint_pending: Mutex<HashMap<SyncScope, Vec<PendingProof>>>,
        stored_items: Mutex<HashMap<(SyncScope, Uuid), StoredProjection>>,
        commit_error: Mutex<Option<SyncStoreErrorKind>>,
        cancel_after_commit: Mutex<Option<SessionCancellationHandle>>,
        cancel_during_item_state_load: Mutex<Option<SessionCancellationHandle>>,
        receipt_history_mismatch: AtomicBool,
        reconcile_calls: AtomicUsize,
        auth_method_bound: AtomicBool,
        auth_method_override: Mutex<Option<AuthMethod>>,
        personal_vaults_enabled: AtomicBool,
        item_state_calls: AtomicUsize,
        commit_attempts: AtomicUsize,
        commits: AtomicUsize,
        push_commits: AtomicUsize,
        local_checksum_valid: AtomicBool,
        local_checksum_differs_from_server: AtomicBool,
        tombstone_seen: AtomicBool,
        restored_after_tombstone: AtomicBool,
        pulled_items_are_synced: AtomicBool,
        pulled_history_is_server_confirmed: AtomicBool,
        local_history_sentinel: AtomicUsize,
        last_commit_key_fingerprint: Mutex<Option<String>>,
    }

    #[derive(Clone)]
    struct StoredProjection {
        path: String,
        name: String,
        type_id: String,
        payload_enc: Vec<u8>,
        checksum: crate::sync::ContentChecksum,
        cache_key_fingerprint: String,
        seq: SyncSeq,
        updated_at: chrono::DateTime<chrono::Utc>,
        deleted_at: Option<chrono::DateTime<chrono::Utc>>,
        sync_status: SyncStatus,
    }

    impl StoredProjection {
        fn capture(item: &crate::sync::ItemProjection) -> Self {
            Self {
                path: item.path().to_string(),
                name: item.name().to_string(),
                type_id: item.type_id().to_string(),
                payload_enc: item.payload_enc().to_vec(),
                checksum: item.checksum(),
                cache_key_fingerprint: item.cache_key_fingerprint().to_string(),
                seq: item.seq(),
                updated_at: item.updated_at(),
                deleted_at: item.deleted_at(),
                sync_status: item.sync_status(),
            }
        }

        fn proof(
            &self,
            scope: SyncScope,
            item_id: Uuid,
        ) -> Result<crate::sync::ItemProof, SyncStoreError> {
            let projection = crate::sync::ItemProjection::new(
                scope,
                item_id,
                self.path.clone(),
                self.name.clone(),
                self.type_id.clone(),
                self.payload_enc.clone(),
                self.checksum,
                self.cache_key_fingerprint.clone(),
                self.seq,
                self.updated_at,
                self.deleted_at,
            )
            .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData))?;
            Ok(crate::sync::ItemProof::new(projection, self.sync_status))
        }
    }

    impl FakeStore {
        fn new(storage_id: Uuid) -> Self {
            Self {
                storage_id,
                default_checkpoint: Mutex::new((Some(cursor_string(1)), Some(1))),
                committed_checkpoints: Mutex::new(HashMap::new()),
                checkpoint_pending: Mutex::new(HashMap::new()),
                stored_items: Mutex::new(HashMap::new()),
                commit_error: Mutex::new(None),
                cancel_after_commit: Mutex::new(None),
                cancel_during_item_state_load: Mutex::new(None),
                receipt_history_mismatch: AtomicBool::new(false),
                reconcile_calls: AtomicUsize::new(0),
                auth_method_bound: AtomicBool::new(true),
                auth_method_override: Mutex::new(None),
                personal_vaults_enabled: AtomicBool::new(true),
                item_state_calls: AtomicUsize::new(0),
                commit_attempts: AtomicUsize::new(0),
                commits: AtomicUsize::new(0),
                push_commits: AtomicUsize::new(0),
                local_checksum_valid: AtomicBool::new(true),
                local_checksum_differs_from_server: AtomicBool::new(true),
                tombstone_seen: AtomicBool::new(false),
                restored_after_tombstone: AtomicBool::new(false),
                pulled_items_are_synced: AtomicBool::new(true),
                pulled_history_is_server_confirmed: AtomicBool::new(true),
                local_history_sentinel: AtomicUsize::new(1),
                last_commit_key_fingerprint: Mutex::new(None),
            }
        }

        fn binding(&self) -> Result<StorageBindingProof, SyncStoreError> {
            StorageBindingProof::new(
                self.storage_id,
                "Remote test",
                ENDPOINT,
                Some("Test server".to_string()),
                FINGERPRINT,
                Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001".to_string()),
                self.personal_vaults_enabled.load(Ordering::SeqCst),
                self.auth_method_bound.load(Ordering::SeqCst).then(|| {
                    self.auth_method_override
                        .lock()
                        .expect("auth method override lock")
                        .unwrap_or(AuthMethod::Password)
                }),
            )
            .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData))
        }
    }

    impl SyncLocalStore for FakeStore {
        fn resolve_target<'a>(
            &'a self,
            _target: &'a SessionTarget,
            _generation: Arc<crate::config::AuthorizedTargetGeneration>,
            _personal_vaults_enabled: bool,
        ) -> SyncStoreFuture<'a, ResolvedSyncTarget> {
            Box::pin(async move { self.binding().map(ResolvedSyncTarget::new) })
        }

        fn reconcile_catalog(
            self: Arc<Self>,
            _target: Arc<ResolvedSyncTarget>,
            catalog: Arc<crate::sync::CatalogSnapshot>,
        ) -> SyncStoreFuture<'static, ReconciledCatalog> {
            self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let vaults = catalog
                    .vaults()
                    .iter()
                    .map(|vault| {
                        SyncScope::new(self.storage_id, vault.id()).map(|scope| {
                            crate::sync::ResolvedSyncVault::new(
                                scope,
                                vault.plane(),
                                VaultPayloadKey::from_bytes([7_u8; 32]),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData))?;
                ReconciledCatalog::new(vaults)
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData))
            })
        }

        fn load_checkpoint<'a>(&'a self, scope: SyncScope) -> SyncStoreFuture<'a, SyncCheckpoint> {
            Box::pin(async move {
                let committed = self
                    .committed_checkpoints
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?
                    .get(&scope)
                    .cloned();
                let (cursor, seq) = match committed {
                    Some((cursor, seq)) => (Some(cursor), seq),
                    None => self
                        .default_checkpoint
                        .lock()
                        .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?
                        .clone(),
                };
                let cursor = cursor
                    .as_ref()
                    .map(|cursor| SyncCursor::new(cursor.to_owned()))
                    .transpose()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData))?;
                let seq = seq
                    .map(SyncSeq::new)
                    .transpose()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData))?;
                let pending = self
                    .checkpoint_pending
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?
                    .get(&scope)
                    .cloned()
                    .unwrap_or_default();
                SyncCheckpoint::new(cursor, seq, pending)
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData))
            })
        }

        fn load_item_states<'a>(
            &'a self,
            scope: SyncScope,
            item_ids: &'a [Uuid],
        ) -> SyncStoreFuture<'a, Vec<ItemState>> {
            self.item_state_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if let Some(handle) = self
                    .cancel_during_item_state_load
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?
                    .take()
                {
                    handle.cancel();
                }
                let stored = self
                    .stored_items
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?;
                let pending_by_item = self
                    .checkpoint_pending
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?
                    .get(&scope)
                    .cloned()
                    .unwrap_or_default();
                item_ids
                    .iter()
                    .copied()
                    .map(|item_id| {
                        let mut state = if let Some(projection) = stored.get(&(scope, item_id)) {
                            projection.proof(scope, item_id).map(ItemState::exact)?
                        } else {
                            ItemState::absent(item_id)
                                .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData))?
                        };
                        // Mirrors the sqlite adapter: an item referenced by a
                        // durable pending row reports that row exactly.
                        if let Some(proof) = pending_by_item
                            .iter()
                            .find(|proof| proof.item_id() == item_id)
                        {
                            state = state.clone().with_pending(proof.clone());
                        }
                        Ok(state)
                    })
                    .collect()
            })
        }

        fn commit_generated_key(
            self: Arc<Self>,
            _commit: GeneratedVaultKeyCommit,
        ) -> SyncStoreFuture<'static, ()> {
            Box::pin(async { Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable)) })
        }

        fn commit_push(
            self: Arc<Self>,
            commit: PushCommitPlan,
        ) -> SyncStoreFuture<'static, PushCommitReceipt> {
            self.push_commits.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let scope = commit.scope();
                let pushed_ids = commit
                    .changes()
                    .iter()
                    .map(|change| change.pending().pending_id())
                    .collect::<HashSet<_>>();
                let mut pending = self
                    .checkpoint_pending
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?;
                if let Some(rows) = pending.get_mut(&scope) {
                    rows.retain(|proof| !pushed_ids.contains(&proof.pending_id()));
                }
                let mut stored_items = self
                    .stored_items
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?;
                for change in commit.changes() {
                    let item = change.item();
                    stored_items.insert(
                        (scope, item.item_id()),
                        StoredProjection {
                            path: item.path().to_string(),
                            name: item.name().to_string(),
                            type_id: item.type_id().to_string(),
                            payload_enc: item.payload_enc().to_vec(),
                            checksum: item.checksum(),
                            cache_key_fingerprint: "001122aabbcc".to_string(),
                            seq: item.seq(),
                            updated_at: item.updated_at(),
                            deleted_at: item.deleted_at(),
                            sync_status: SyncStatus::Synced,
                        },
                    );
                }
                // A push never advances the pull cursor; the checkpoint keeps
                // its exact cursor and sequence.
                if let Some(cursor) = commit.expected_cursor() {
                    self.committed_checkpoints
                        .lock()
                        .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?
                        .insert(
                            scope,
                            (
                                cursor.as_str().to_string(),
                                commit.expected_last_seq().map(|seq| seq.get()),
                            ),
                        );
                }
                Ok(PushCommitReceipt::new(
                    commit.changes().len(),
                    commit.server_head_hint().clone(),
                ))
            })
        }

        fn commit_pull_page(
            self: Arc<Self>,
            commit: PullPageCommit,
        ) -> SyncStoreFuture<'static, PullCommitReceipt> {
            self.commit_attempts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if let Some(kind) = self
                    .commit_error
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?
                    .take()
                {
                    return Err(SyncStoreError::new(kind));
                }
                let mut history_entries = 0_usize;
                *self
                    .last_commit_key_fingerprint
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))? =
                    Some(commit.cache_key_fingerprint().to_string());
                let server_checksum = "11".repeat(32);
                let mut stored_items = self
                    .stored_items
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?;
                for change in commit.changes() {
                    let item = change.item();
                    self.pulled_items_are_synced
                        .fetch_and(item.sync_status() == SyncStatus::Synced, Ordering::SeqCst);
                    self.pulled_history_is_server_confirmed.fetch_and(
                        change.history().iter().all(|entry| {
                            entry.authority() == crate::sync::HistoryAuthority::ServerConfirmed
                        }),
                        Ordering::SeqCst,
                    );
                    let computed = zann_crypto::payload_checksum(item.payload_enc());
                    self.local_checksum_valid
                        .fetch_and(computed == item.checksum().to_hex(), Ordering::SeqCst);
                    self.local_checksum_differs_from_server.fetch_and(
                        item.checksum().to_hex() != server_checksum,
                        Ordering::SeqCst,
                    );
                    self.tombstone_seen.fetch_or(
                        item.is_tombstone()
                            && item.deleted_at() == Some(item.updated_at())
                            && item.payload_enc().is_empty(),
                        Ordering::SeqCst,
                    );
                    let was_tombstone = stored_items
                        .get(&(item.scope(), item.item_id()))
                        .is_some_and(|previous| previous.deleted_at.is_some());
                    self.restored_after_tombstone.fetch_or(
                        was_tombstone && item.deleted_at().is_none(),
                        Ordering::SeqCst,
                    );
                    stored_items.insert(
                        (item.scope(), item.item_id()),
                        StoredProjection::capture(item),
                    );
                    history_entries += change.history().len();
                }
                drop(stored_items);
                self.commits.fetch_add(1, Ordering::SeqCst);
                self.committed_checkpoints
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?
                    .insert(
                        commit.scope(),
                        (
                            commit.next_cursor().as_str().to_string(),
                            commit.next_last_seq().map(SyncSeq::get),
                        ),
                    );
                if let Some(handle) = self
                    .cancel_after_commit
                    .lock()
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::Internal))?
                    .take()
                {
                    handle.cancel();
                }
                let cursor = SyncCursor::new(commit.next_cursor().as_str())
                    .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData))?;
                let reported_history = if self.receipt_history_mismatch.load(Ordering::SeqCst) {
                    history_entries.saturating_add(1)
                } else {
                    history_entries
                };
                PullCommitReceipt::new(
                    commit.changes().len(),
                    reported_history,
                    cursor,
                    commit.next_last_seq(),
                )
                .map_err(|_| SyncStoreError::new(SyncStoreErrorKind::InvalidData))
            })
        }

        fn reset_projection_if_clean(
            self: Arc<Self>,
            _reset: ProjectionReset,
        ) -> SyncStoreFuture<'static, ()> {
            Box::pin(async { Err(SyncStoreError::new(SyncStoreErrorKind::Unavailable)) })
        }
    }

    struct Fixture {
        engine: SyncEngine,
        store: Arc<FakeStore>,
        remote: Arc<FakeRemote>,
        authorizer: Arc<FakeAuthorizer>,
        target: SessionTarget,
        operation: SessionOperation,
        cancel: SessionCancellationHandle,
    }

    fn fixture_from_vaults(vaults: Vec<(Uuid, VaultPlane, Vec<PullPageWire>)>) -> Fixture {
        fixture_from_vaults_with_anchor(vaults, true)
    }

    fn fixture_from_vaults_with_anchor(
        vaults: Vec<(Uuid, VaultPlane, Vec<PullPageWire>)>,
        has_local_anchor: bool,
    ) -> Fixture {
        let storage_id = Uuid::now_v7();
        let store = Arc::new(FakeStore::new(storage_id));
        let remote = Arc::new(FakeRemote::with_vaults(vaults));
        let authorizer = Arc::new(FakeAuthorizer {
            storage_id: has_local_anchor.then_some(storage_id),
            account_subject: Mutex::new(Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001".to_string())),
            auth_method: Mutex::new(Some(AuthMethod::Password)),
            personal_vaults_enabled: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        });
        let engine = SyncEngine::with_components(authorizer.clone(), store.clone(), remote.clone());
        let connection_id = ConnectionId::deterministic("sync-test", ENDPOINT);
        let target = match SessionTarget::new(connection_id, "default") {
            Ok(target) => target,
            Err(error) => panic!("static target must validate: {error}"),
        };
        let (operation, cancel) = SessionOperation::new(Instant::now() + Duration::from_secs(30));
        Fixture {
            engine,
            store,
            remote,
            authorizer,
            target,
            operation,
            cancel,
        }
    }

    fn fixture(plane: VaultPlane, pages: Vec<PullPageWire>) -> Fixture {
        let vault_id = Uuid::now_v7();
        fixture_from_vaults(vec![(vault_id, plane, pages)])
    }

    fn personal_change(vault_id: Uuid, item_id: Uuid, seq: i64) -> PersonalPullChangeWire {
        let key = SecretKey::from_bytes([7_u8; 32]);
        let payload = EncryptedPayload::new("login");
        let payload_enc = match zann_crypto::encrypt_payload(&key, vault_id, item_id, &payload) {
            Ok(payload) => payload,
            Err(error) => panic!("test encryption failed: {error}"),
        };
        PersonalPullChangeWire {
            item_id: item_id.to_string(),
            operation: ChangeType::Update.as_i32(),
            seq,
            updated_at: TIMESTAMP.to_string(),
            checksum: zann_crypto::payload_checksum(&payload_enc),
            payload_enc: Some(payload_enc),
            path: format!("items/{item_id}"),
            name: item_id.to_string(),
            type_id: "login".to_string(),
            history: Vec::new(),
        }
    }

    fn fixture_with_vault(
        plane: VaultPlane,
        make_pages: impl FnOnce(Uuid) -> Vec<PullPageWire>,
    ) -> Fixture {
        let vault_id = Uuid::now_v7();
        fixture_from_vaults(vec![(vault_id, plane, make_pages(vault_id))])
    }

    fn personal_page(
        changes: Vec<PersonalPullChangeWire>,
        cursor_sequence: i64,
        has_more: bool,
    ) -> PullPageWire {
        PullPageWire::Personal(PersonalPullPageWire {
            changes,
            next_cursor: cursor_string(cursor_sequence),
            has_more,
            push_available: true,
        })
    }

    #[tokio::test]
    async fn invalid_change_does_not_advance_cursor() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |_vault_id| {
            let item_id = Uuid::now_v7();
            vec![personal_page(
                vec![PersonalPullChangeWire {
                    item_id: item_id.to_string(),
                    operation: ChangeType::Update.as_i32(),
                    seq: 2,
                    updated_at: TIMESTAMP.to_string(),
                    checksum: zann_crypto::payload_checksum(&[1, 2, 3]),
                    payload_enc: Some(vec![1, 2, 3]),
                    path: format!("items/{item_id}"),
                    name: item_id.to_string(),
                    type_id: "login".to_string(),
                    history: Vec::new(),
                }],
                2,
                false,
            )]
        });
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("invalid ciphertext must fail");
        assert_eq!(error.kind(), SyncErrorKind::Crypto);
        assert_eq!(fixture.store.item_state_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.commit_attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pull_projection_carries_fingerprint_of_the_exact_payload_key() {
        let item_id = Uuid::now_v7();
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            vec![personal_page(
                vec![personal_change(vault_id, item_id, 2)],
                2,
                false,
            )]
        });
        fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect("valid projection must commit");

        let stored = fixture
            .store
            .stored_items
            .lock()
            .expect("stored items lock");
        let projection = stored.values().next().expect("committed projection");
        let exact_key = SecretKey::from_bytes([7_u8; 32]);
        assert_eq!(
            projection.cache_key_fingerprint,
            zann_crypto::cache_key_fingerprint(&exact_key)
        );
    }

    #[tokio::test]
    async fn nonempty_final_page_with_unchanged_cursor_is_rejected_before_store() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            vec![personal_page(
                vec![personal_change(vault_id, Uuid::now_v7(), 2)],
                1,
                false,
            )]
        });
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("a nonempty page must advance its cursor to the last sequence");
        assert_eq!(error.kind(), SyncErrorKind::Protocol);
        assert_eq!(fixture.store.item_state_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.commit_attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn empty_page_with_high_cursor_is_rejected_before_store() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |_vault_id| {
            vec![personal_page(Vec::new(), 1_000, false)]
        });
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("empty page cursor must equal the durable sequence");
        assert_eq!(error.kind(), SyncErrorKind::Protocol);
        assert_eq!(fixture.store.item_state_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.commit_attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn checkpoint_cursor_sequence_mismatch_stops_before_pull() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            vec![personal_page(
                vec![personal_change(vault_id, Uuid::now_v7(), 2)],
                2,
                false,
            )]
        });
        *fixture
            .store
            .default_checkpoint
            .lock()
            .expect("checkpoint lock") = (Some(cursor_string(2)), Some(1));
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("cursor and durable last_seq must agree");
        assert_eq!(error.kind(), SyncErrorKind::Local);
        assert_eq!(error.stage(), SyncStage::LoadCheckpoint);
        assert_eq!(fixture.remote.pull_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.commit_attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn initial_empty_seq_zero_cursor_roundtrips_on_restart() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |_vault_id| {
            vec![
                personal_page(Vec::new(), 0, false),
                personal_page(Vec::new(), 0, false),
            ]
        });
        *fixture
            .store
            .default_checkpoint
            .lock()
            .expect("checkpoint lock") = (None, None);

        let first = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect("initial empty page is a valid seq-zero checkpoint");
        assert_eq!(first.pages_committed(), 1);
        let exact_key = SecretKey::from_bytes([7_u8; 32]);
        assert_eq!(
            fixture
                .store
                .last_commit_key_fingerprint
                .lock()
                .expect("commit fingerprint lock")
                .as_deref(),
            Some(zann_crypto::cache_key_fingerprint(&exact_key).as_str())
        );

        let (restart, _cancel) = SessionOperation::new(Instant::now() + Duration::from_secs(5));
        let second = fixture
            .engine
            .pull(&fixture.target, restart)
            .await
            .expect("stored seq-zero cursor must load consistently");
        assert_eq!(second.pages_committed(), 1);
        assert_eq!(fixture.store.commits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn two_pages_commit_one_transaction_per_page() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            vec![
                personal_page(vec![personal_change(vault_id, Uuid::now_v7(), 2)], 2, true),
                personal_page(vec![personal_change(vault_id, Uuid::now_v7(), 3)], 3, false),
            ]
        });
        let outcome = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect("two valid pages");
        assert_eq!(outcome.status(), SyncOutcomeStatus::Complete);
        assert_eq!(outcome.pages_committed(), 2);
        assert_eq!(fixture.store.commits.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.remote.pull_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn page_limit_is_scoped_per_vault() {
        fn pages(vault_id: Uuid, count: usize) -> Vec<PullPageWire> {
            (0..count)
                .map(|index| {
                    let sequence = i64::try_from(index).expect("test page index fits i64") + 2;
                    personal_page(
                        vec![personal_change(vault_id, Uuid::now_v7(), sequence)],
                        sequence,
                        index + 1 < count,
                    )
                })
                .collect()
        }

        let first_vault = Uuid::now_v7();
        let second_vault = Uuid::now_v7();
        let fixture = fixture_from_vaults(vec![
            (
                first_vault,
                VaultPlane::PersonalClient,
                pages(first_vault, MAX_PULL_PAGES),
            ),
            (
                second_vault,
                VaultPlane::PersonalClient,
                pages(second_vault, 2),
            ),
        ]);
        let outcome = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect("a new vault receives its own page budget");
        assert_eq!(outcome.pages_committed(), MAX_PULL_PAGES + 2);
        assert_eq!(
            fixture.remote.pull_calls.load(Ordering::SeqCst),
            MAX_PULL_PAGES + 2
        );
    }

    #[tokio::test]
    async fn store_error_rolls_back_and_prevents_next_dispatch() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            vec![
                personal_page(vec![personal_change(vault_id, Uuid::now_v7(), 2)], 2, true),
                personal_page(vec![personal_change(vault_id, Uuid::now_v7(), 3)], 3, false),
            ]
        });
        *fixture
            .store
            .commit_error
            .lock()
            .expect("commit error lock") = Some(SyncStoreErrorKind::StaleKeyBinding);
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("store CAS failure must stop sync");
        assert_eq!(error.kind(), SyncErrorKind::ConcurrentLocalChange);
        assert_eq!(fixture.store.commit_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.commits.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.remote.pull_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unknown_commit_outcome_is_typed_and_never_retried() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            vec![
                personal_page(vec![personal_change(vault_id, Uuid::now_v7(), 2)], 2, true),
                personal_page(vec![personal_change(vault_id, Uuid::now_v7(), 3)], 3, false),
            ]
        });
        *fixture
            .store
            .commit_error
            .lock()
            .expect("commit error lock") = Some(SyncStoreErrorKind::CommitOutcomeUnknown);
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("ambiguous COMMIT result must surface without retry");
        assert_eq!(error.kind(), SyncErrorKind::CommitOutcomeUnknown);
        assert_eq!(fixture.store.commit_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.remote.pull_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mismatched_history_receipt_stops_before_next_dispatch() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            vec![
                personal_page(vec![personal_change(vault_id, Uuid::now_v7(), 2)], 2, true),
                personal_page(vec![personal_change(vault_id, Uuid::now_v7(), 3)], 3, false),
            ]
        });
        fixture
            .store
            .receipt_history_mismatch
            .store(true, Ordering::SeqCst);
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("store receipt must account for every history row");
        assert_eq!(error.kind(), SyncErrorKind::Local);
        assert_eq!(fixture.remote.pull_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancel_before_dispatch_makes_zero_remote_calls() {
        let fixture = fixture(VaultPlane::PersonalClient, Vec::new());
        fixture.cancel.cancel();
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("pre-cancelled sync must stop");
        assert_eq!(error.kind(), SyncErrorKind::Cancelled);
        assert_eq!(fixture.authorizer.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.remote.catalog_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.remote.pull_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancel_between_pages_returns_partial_outcome() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            vec![
                personal_page(vec![personal_change(vault_id, Uuid::now_v7(), 2)], 2, true),
                personal_page(vec![personal_change(vault_id, Uuid::now_v7(), 3)], 3, false),
            ]
        });
        *fixture
            .store
            .cancel_after_commit
            .lock()
            .expect("cancel lock") = Some(fixture.cancel.clone());
        let outcome = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect("committed page must be reported as partial");
        assert_eq!(outcome.status(), SyncOutcomeStatus::CancelledPartial);
        assert_eq!(outcome.pages_committed(), 1);
        assert_eq!(fixture.remote.pull_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancel_during_slow_local_read_prevents_commit() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            vec![personal_page(
                vec![personal_change(vault_id, Uuid::now_v7(), 2)],
                2,
                false,
            )]
        });
        *fixture
            .store
            .cancel_during_item_state_load
            .lock()
            .expect("cancel-during-read lock") = Some(fixture.cancel.clone());
        let outcome = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect("catalog reconciliation makes cancellation a partial outcome");
        assert_eq!(outcome.status(), SyncOutcomeStatus::CancelledPartial);
        assert_eq!(fixture.store.item_state_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.commit_attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn remote_only_session_fails_before_catalog_dispatch() {
        let vault_id = Uuid::now_v7();
        let fixture = fixture_from_vaults_with_anchor(
            vec![(vault_id, VaultPlane::PersonalClient, Vec::new())],
            false,
        );
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("remote-only config has no local sync projection");
        assert_eq!(error.kind(), SyncErrorKind::NoLocalTarget);
        assert_eq!(fixture.remote.catalog_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.remote.pull_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn absent_account_subject_fails_before_catalog_or_reconcile() {
        let fixture = fixture_from_vaults(Vec::new());
        *fixture
            .authorizer
            .account_subject
            .lock()
            .expect("account subject lock") = None;
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("an authenticated account subject is mandatory");
        assert_eq!(error.kind(), SyncErrorKind::AccountBindingRequired);
        assert_eq!(fixture.remote.catalog_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.reconcile_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mismatched_account_subject_fails_before_catalog_or_reconcile() {
        let fixture = fixture_from_vaults(Vec::new());
        *fixture
            .authorizer
            .account_subject
            .lock()
            .expect("account subject lock") =
            Some("018f4f08-7f1d-7d57-bd43-bb4b7c520002".to_string());
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("account binding mismatch must fail closed");
        assert_eq!(error.kind(), SyncErrorKind::AccountBindingMismatch);
        assert_eq!(fixture.remote.catalog_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.reconcile_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mismatched_personal_vault_capability_fails_before_catalog_or_reconcile() {
        let fixture = fixture_from_vaults(Vec::new());
        fixture
            .authorizer
            .personal_vaults_enabled
            .store(false, Ordering::SeqCst);
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("verified server capability mismatch must fail closed");
        assert_eq!(error.kind(), SyncErrorKind::ServerCapabilityMismatch);
        assert_eq!(fixture.remote.catalog_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.reconcile_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn disabled_personal_capability_rejects_personal_catalog_before_reconcile() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |_vault_id| Vec::new());
        fixture
            .authorizer
            .personal_vaults_enabled
            .store(false, Ordering::SeqCst);
        fixture
            .store
            .personal_vaults_enabled
            .store(false, Ordering::SeqCst);

        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("a verified disabled capability cannot yield personal vaults");
        assert_eq!(error.kind(), SyncErrorKind::ServerCapabilityMismatch);
        assert_eq!(error.stage(), SyncStage::Catalog);
        assert_eq!(fixture.remote.catalog_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.reconcile_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn absent_auth_method_binding_fails_before_catalog_or_reconcile() {
        let fixture = fixture_from_vaults(Vec::new());
        fixture
            .store
            .auth_method_bound
            .store(false, Ordering::SeqCst);
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("an explicit local auth-method binding is required");
        assert_eq!(error.kind(), SyncErrorKind::AuthenticationBindingRequired);
        assert_eq!(fixture.remote.catalog_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.reconcile_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn legacy_session_without_auth_method_fails_before_local_or_catalog_dispatch() {
        let fixture = fixture_from_vaults(Vec::new());
        *fixture
            .authorizer
            .auth_method
            .lock()
            .expect("auth method lock") = None;
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("legacy session without auth method must fail closed");
        assert_eq!(error.kind(), SyncErrorKind::AuthenticationBindingRequired);
        assert_eq!(fixture.remote.catalog_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.reconcile_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mismatched_auth_method_binding_fails_before_catalog_or_reconcile() {
        let fixture = fixture_from_vaults(Vec::new());
        *fixture
            .store
            .auth_method_override
            .lock()
            .expect("auth method override lock") = Some(AuthMethod::Oidc);
        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("the exact local auth method must match the session capability");
        assert_eq!(error.kind(), SyncErrorKind::AuthenticationBindingMismatch);
        assert_eq!(fixture.remote.catalog_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.reconcile_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn shared_plaintext_is_encrypted_and_checksum_is_recomputed() {
        let fixture = fixture_with_vault(VaultPlane::SharedServer, |_vault_id| {
            let item_id = Uuid::now_v7();
            let payload = EncryptedPayload::new("login");
            vec![PullPageWire::Shared(SharedPullPageWire {
                changes: vec![SharedPullChangeWire {
                    item_id: item_id.to_string(),
                    operation: ChangeType::Update.as_i32(),
                    seq: 2,
                    updated_at: TIMESTAMP.to_string(),
                    checksum: "11".repeat(32),
                    payload: Some(payload),
                    path: format!("items/{item_id}"),
                    name: item_id.to_string(),
                    type_id: "login".to_string(),
                    history: Vec::new(),
                }],
                next_cursor: cursor_string(2),
                has_more: false,
                push_available: true,
            })]
        });
        fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect("valid shared page");
        assert!(fixture.store.local_checksum_valid.load(Ordering::SeqCst));
        assert!(fixture
            .store
            .local_checksum_differs_from_server
            .load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn delete_operation_becomes_tombstone() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |_vault_id| {
            let item_id = Uuid::now_v7();
            vec![personal_page(
                vec![PersonalPullChangeWire {
                    item_id: item_id.to_string(),
                    operation: ChangeType::Delete.as_i32(),
                    seq: 2,
                    updated_at: TIMESTAMP.to_string(),
                    checksum: "11".repeat(32),
                    payload_enc: None,
                    path: format!("items/{item_id}"),
                    name: item_id.to_string(),
                    type_id: "login".to_string(),
                    history: Vec::new(),
                }],
                2,
                false,
            )]
        });
        fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect("valid delete page");
        assert!(fixture.store.tombstone_seen.load(Ordering::SeqCst));
        assert!(fixture.store.local_checksum_valid.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn confirmed_delete_then_later_update_restores_synced_projection() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            let item_id = Uuid::now_v7();
            let delete = PersonalPullChangeWire {
                item_id: item_id.to_string(),
                operation: ChangeType::Delete.as_i32(),
                seq: 2,
                updated_at: TIMESTAMP.to_string(),
                checksum: "11".repeat(32),
                payload_enc: None,
                path: format!("items/{item_id}"),
                name: item_id.to_string(),
                type_id: "login".to_string(),
                history: Vec::new(),
            };
            let mut restored = personal_change(vault_id, item_id, 3);
            let restored_payload = restored
                .payload_enc
                .as_ref()
                .expect("live update payload")
                .clone();
            restored.history = vec![PersonalHistoryWire {
                version: 2,
                checksum: zann_crypto::payload_checksum(&restored_payload),
                change_type: ChangeType::Delete.as_i32(),
                changed_by_name: Some("Server actor".to_string()),
                changed_by_email: "actor@example.test".to_string(),
                created_at: TIMESTAMP.to_string(),
                payload_enc: restored_payload,
            }];
            vec![
                personal_page(vec![delete], 2, true),
                personal_page(vec![restored], 3, false),
            ]
        });

        let outcome = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect("later authoritative update restores the deleted item");

        assert_eq!(outcome.pages_committed(), 2);
        assert!(fixture.store.tombstone_seen.load(Ordering::SeqCst));
        assert!(fixture
            .store
            .restored_after_tombstone
            .load(Ordering::SeqCst));
        assert!(fixture.store.pulled_items_are_synced.load(Ordering::SeqCst));
        assert!(fixture
            .store
            .pulled_history_is_server_confirmed
            .load(Ordering::SeqCst));
        // The fake adapter's local-only sentinel models UI/pending/conflict
        // history that server-confirmed reconciliation has no authority over.
        assert_eq!(
            fixture.store.local_history_sentinel.load(Ordering::SeqCst),
            1
        );
    }

    fn pending_update_proof(
        scope: SyncScope,
        item_id: Uuid,
        base_seq: i64,
        payload: Vec<u8>,
    ) -> PendingProof {
        PendingProof::new(
            Uuid::now_v7(),
            scope,
            item_id,
            ChangeType::Update,
            Some(payload.clone()),
            Some(
                crate::sync::ContentChecksum::parse(&zann_crypto::payload_checksum(&payload))
                    .expect("valid checksum"),
            ),
            Some(format!("items/{item_id}")),
            Some(item_id.to_string()),
            Some("login".to_string()),
            Some(SyncSeq::new(base_seq).expect("valid base sequence")),
            chrono::Utc::now(),
        )
        .expect("valid pending proof")
    }

    fn synced_projection(seq: i64) -> StoredProjection {
        StoredProjection {
            path: "items/synced".to_string(),
            name: "synced".to_string(),
            type_id: "login".to_string(),
            payload_enc: vec![7, 8, 9],
            checksum: crate::sync::ContentChecksum::parse(&zann_crypto::payload_checksum(&[
                7, 8, 9,
            ]))
            .expect("valid checksum"),
            cache_key_fingerprint: "001122aabbcc".to_string(),
            seq: SyncSeq::new(seq).expect("valid sequence"),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
            sync_status: SyncStatus::Synced,
        }
    }

    #[tokio::test]
    async fn push_conflict_keeps_the_pending_edit_for_the_next_sync() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |_vault_id| Vec::new());
        let vault_id = fixture.remote.vaults.first().expect("one vault").0;
        let item_id = Uuid::now_v7();
        let scope = SyncScope::new(fixture.store.storage_id, vault_id).expect("valid scope");
        let edit = pending_update_proof(scope, item_id, 5, vec![42]);
        fixture
            .store
            .default_checkpoint
            .lock()
            .expect("default checkpoint")
            .clone_from(&(Some(cursor_string(5)), Some(5)));
        fixture
            .store
            .checkpoint_pending
            .lock()
            .expect("checkpoint pending")
            .insert(scope, vec![edit]);
        fixture
            .store
            .stored_items
            .lock()
            .expect("stored items")
            .insert((scope, item_id), synced_projection(5));
        *fixture.remote.push_response.lock().expect("push response") = Some(PushResponseWire {
            applied: Vec::new(),
            applied_changes: Vec::new(),
            conflicts: vec![PushConflictWire {
                item_id: item_id.to_string(),
                reason: "conflict".to_string(),
                server_seq: 6,
                server_updated_at: TIMESTAMP.to_string(),
            }],
            new_cursor: cursor_string(6),
        });

        let error = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect_err("a conflicted push must fail the whole sync");
        assert_eq!(error.kind(), SyncErrorKind::ConcurrentRemoteChange);
        assert_eq!(error.stage(), SyncStage::Push);
        assert_eq!(fixture.remote.push_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.store.push_commits.load(Ordering::SeqCst),
            0,
            "a conflicted push must never commit locally"
        );

        // The user edit survives untouched: same durable pending row, same
        // local projection, ready for the next sync attempt.
        let checkpoint = fixture
            .store
            .load_checkpoint(scope)
            .await
            .expect("checkpoint");
        assert_eq!(checkpoint.pending().len(), 1);
        assert_eq!(checkpoint.pending()[0].item_id(), item_id);
        let stored = fixture
            .store
            .stored_items
            .lock()
            .expect("stored items")
            .get(&(scope, item_id))
            .cloned()
            .expect("edited item survives");
        assert_eq!(stored.seq.get(), 5);
        assert_eq!(stored.payload_enc, vec![7, 8, 9]);

        // A later sync retries the same edit instead of silently dropping it.
        *fixture.remote.push_response.lock().expect("push response") = Some(PushResponseWire {
            applied: Vec::new(),
            applied_changes: Vec::new(),
            conflicts: vec![PushConflictWire {
                item_id: item_id.to_string(),
                reason: "conflict".to_string(),
                server_seq: 6,
                server_updated_at: TIMESTAMP.to_string(),
            }],
            new_cursor: cursor_string(6),
        });
        let (retry_operation, _) = SessionOperation::new(Instant::now() + Duration::from_secs(30));
        let retry = fixture
            .engine
            .pull(&fixture.target, retry_operation)
            .await
            .expect_err("the conflict persists until the server accepts the edit");
        assert_eq!(retry.kind(), SyncErrorKind::ConcurrentRemoteChange);
        assert_eq!(fixture.remote.push_calls.load(Ordering::SeqCst), 2);
        let checkpoint = fixture
            .store
            .load_checkpoint(scope)
            .await
            .expect("checkpoint");
        assert_eq!(
            checkpoint.pending().len(),
            1,
            "the retried edit must still be pending"
        );
    }

    #[test]
    fn item_state_validation_rejects_a_projection_with_a_pending_edit() {
        let scope = SyncScope::new(Uuid::now_v7(), Uuid::now_v7()).expect("valid scope");
        let item_id = Uuid::now_v7();
        let proof = synced_projection(5).proof(scope, item_id).expect("proof");
        let state =
            ItemState::exact(proof).with_pending(pending_update_proof(scope, item_id, 5, vec![9]));

        let error = validate_item_states(scope, &[item_id], vec![state]);

        assert_eq!(
            error.expect_err("a pending edit must block page preparation"),
            SyncErrorKind::ConcurrentLocalChange
        );
    }

    #[tokio::test]
    async fn successful_push_applies_creates_and_updates_without_advancing_the_pull_cursor() {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |_vault_id| {
            // A final empty page at the current cursor ends the pull loop.
            vec![personal_page(Vec::new(), 5, false)]
        });
        let vault_id = fixture.remote.vaults.first().expect("one vault").0;
        let updated_id = Uuid::now_v7();
        let created_id = Uuid::now_v7();
        let scope = SyncScope::new(fixture.store.storage_id, vault_id).expect("valid scope");
        let update = pending_update_proof(scope, updated_id, 5, vec![7, 8, 9]);
        let create = PendingProof::new(
            Uuid::now_v7(),
            scope,
            created_id,
            ChangeType::Create,
            Some(vec![42]),
            Some(
                crate::sync::ContentChecksum::parse(&zann_crypto::payload_checksum(&[42]))
                    .expect("valid checksum"),
            ),
            Some(format!("items/{created_id}")),
            Some(created_id.to_string()),
            Some("login".to_string()),
            None,
            chrono::Utc::now(),
        )
        .expect("valid create proof");
        fixture
            .store
            .default_checkpoint
            .lock()
            .expect("default checkpoint")
            .clone_from(&(Some(cursor_string(5)), Some(5)));
        fixture
            .store
            .checkpoint_pending
            .lock()
            .expect("checkpoint pending")
            .insert(scope, vec![update, create]);
        fixture
            .store
            .stored_items
            .lock()
            .expect("stored items")
            .insert((scope, updated_id), synced_projection(5));
        *fixture.remote.push_response.lock().expect("push response") = Some(PushResponseWire {
            applied: vec![updated_id.to_string(), created_id.to_string()],
            applied_changes: vec![
                AppliedPushChangeWire {
                    item_id: updated_id.to_string(),
                    seq: 6,
                    updated_at: TIMESTAMP.to_string(),
                    deleted_at: None,
                },
                AppliedPushChangeWire {
                    item_id: created_id.to_string(),
                    seq: 7,
                    updated_at: TIMESTAMP.to_string(),
                    deleted_at: None,
                },
            ],
            conflicts: Vec::new(),
            new_cursor: cursor_string(7),
        });

        let outcome = fixture
            .engine
            .pull(&fixture.target, fixture.operation)
            .await
            .expect("a fully applied push must succeed");

        assert_eq!(outcome.status(), SyncOutcomeStatus::Complete);
        assert_eq!(fixture.remote.push_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.push_commits.load(Ordering::SeqCst), 1);

        let checkpoint = fixture
            .store
            .load_checkpoint(scope)
            .await
            .expect("checkpoint");
        assert!(
            checkpoint.pending().is_empty(),
            "applied pending rows must be deleted"
        );
        // The push server head is only a hint: the durable pull cursor must
        // stay exactly where the last applied pull page left it.
        assert_eq!(checkpoint.cursor().map(|cursor| cursor.sequence()), Some(5));
        assert_eq!(checkpoint.last_seq().map(|seq| seq.get()), Some(5));

        let stored = fixture.store.stored_items.lock().expect("stored items");
        let updated = stored
            .get(&(scope, updated_id))
            .expect("updated item persists");
        assert_eq!(updated.seq.get(), 6);
        assert_eq!(updated.sync_status, SyncStatus::Synced);
        assert_eq!(updated.payload_enc, vec![7, 8, 9]);
        let created = stored
            .get(&(scope, created_id))
            .expect("created item persists");
        assert_eq!(created.seq.get(), 7);
        assert_eq!(created.sync_status, SyncStatus::Synced);
        assert_eq!(created.payload_enc, vec![42]);
        assert_eq!(created.path, format!("items/{created_id}"));
    }

    #[tokio::test]
    async fn invalid_timestamp_history_and_oversized_page_are_rejected_before_store() {
        let invalid_timestamp = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            let mut change = personal_change(vault_id, Uuid::now_v7(), 2);
            change.updated_at = "not-a-timestamp".to_string();
            vec![personal_page(vec![change], 2, false)]
        });
        assert!(invalid_timestamp
            .engine
            .pull(&invalid_timestamp.target, invalid_timestamp.operation)
            .await
            .is_err());
        assert_eq!(
            invalid_timestamp
                .store
                .item_state_calls
                .load(Ordering::SeqCst),
            0
        );

        let invalid_history = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            let item_id = Uuid::now_v7();
            let key = SecretKey::from_bytes([7_u8; 32]);
            let payload = zann_crypto::encrypt_payload(
                &key,
                vault_id,
                item_id,
                &EncryptedPayload::new("login"),
            )
            .expect("history encryption");
            let mut change = personal_change(vault_id, item_id, 3);
            change.history = vec![
                PersonalHistoryWire {
                    version: 1,
                    checksum: zann_crypto::payload_checksum(&payload),
                    change_type: ChangeType::Update.as_i32(),
                    changed_by_name: None,
                    changed_by_email: "actor@example.test".to_string(),
                    created_at: TIMESTAMP.to_string(),
                    payload_enc: payload.clone(),
                },
                PersonalHistoryWire {
                    version: 2,
                    checksum: zann_crypto::payload_checksum(&payload),
                    change_type: ChangeType::Update.as_i32(),
                    changed_by_name: None,
                    changed_by_email: "actor@example.test".to_string(),
                    created_at: TIMESTAMP.to_string(),
                    payload_enc: payload,
                },
            ];
            vec![personal_page(vec![change], 3, false)]
        });
        assert!(invalid_history
            .engine
            .pull(&invalid_history.target, invalid_history.operation)
            .await
            .is_err());
        assert_eq!(
            invalid_history
                .store
                .item_state_calls
                .load(Ordering::SeqCst),
            0
        );

        let oversized = fixture_with_vault(VaultPlane::PersonalClient, |vault_id| {
            let changes = (2..=6)
                .map(|seq| personal_change(vault_id, Uuid::now_v7(), seq))
                .collect();
            vec![personal_page(changes, 6, false)]
        });
        assert!(oversized
            .engine
            .pull(&oversized.target, oversized.operation)
            .await
            .is_err());
        assert_eq!(oversized.store.item_state_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn bearer_is_not_exposed_or_rendered() {
        let target = SessionTarget::new(
            ConnectionId::deterministic("sync-test", ENDPOINT),
            "default",
        )
        .expect("static target");
        let storage_id = Uuid::now_v7().to_string();
        let access = SessionAccess::for_sync_test(
            SessionOperationId::new(),
            target,
            ENDPOINT,
            Some(storage_id),
            FINGERPRINT,
            (
                Some("018f4f08-7f1d-7d57-bd43-bb4b7c520001".to_string()),
                Some(AuthMethod::Password),
            ),
            true,
        );
        assert!(!format!("{access:?}").contains("sync-test-access"));
        assert!(!include_str!("../session.rs").contains("pub fn bearer"));
    }
}
