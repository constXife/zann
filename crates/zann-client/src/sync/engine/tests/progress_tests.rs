use super::*;

struct DurableObserver {
    store: Arc<FakeStore>,
    notices: Mutex<Vec<SyncProgress>>,
    cancel_after_page: Option<SessionCancellationHandle>,
}

impl SyncProgressSink for DurableObserver {
    fn report(&self, progress: SyncProgress) {
        match progress.phase() {
            SyncProgressPhase::CatalogCommitted => {
                assert_eq!(self.store.reconcile_calls.load(Ordering::SeqCst), 1);
                assert_eq!(self.store.commits.load(Ordering::SeqCst), 0);
            }
            SyncProgressPhase::PageCommitted => {
                assert_eq!(
                    self.store.commits.load(Ordering::SeqCst),
                    progress.pages_committed()
                );
                assert!(!self.store.committed_checkpoints.lock().unwrap().is_empty());
                assert!(!self.store.stored_items.lock().unwrap().is_empty());
                if let Some(cancel) = &self.cancel_after_page {
                    cancel.cancel();
                }
            }
            _ => return,
        }
        assert_eq!(progress.storage_id(), Some(self.store.storage_id));
        self.notices.lock().unwrap().push(progress);
    }
}

#[tokio::test]
async fn committed_page_is_observable_before_the_remaining_pull() {
    let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault| {
        vec![
            personal_page(vec![personal_change(vault, Uuid::now_v7(), 2)], 2, true),
            personal_page(vec![personal_change(vault, Uuid::now_v7(), 3)], 3, false),
        ]
    });
    let observer = Arc::new(DurableObserver {
        store: fixture.store.clone(),
        notices: Mutex::new(Vec::new()),
        cancel_after_page: Some(fixture.cancel),
    });
    let engine = fixture.engine.with_progress(observer.clone());
    let outcome = engine
        .pull(&fixture.target, fixture.operation)
        .await
        .expect("partial pull");
    assert_eq!(outcome.status(), SyncOutcomeStatus::CancelledPartial);
    assert_eq!(fixture.remote.pull_calls.load(Ordering::SeqCst), 1);
    let notices = observer.notices.lock().unwrap();
    assert_eq!(
        notices.iter().map(SyncProgress::phase).collect::<Vec<_>>(),
        [
            SyncProgressPhase::CatalogCommitted,
            SyncProgressPhase::PageCommitted
        ]
    );
    assert_eq!(notices[1].changes_committed(), 1);
}

#[tokio::test]
async fn failed_ambiguous_or_invalid_commit_never_publishes_a_page() {
    for failure in 0..3 {
        let fixture = fixture_with_vault(VaultPlane::PersonalClient, |vault| {
            vec![personal_page(
                vec![personal_change(vault, Uuid::now_v7(), 2)],
                2,
                false,
            )]
        });
        if failure == 2 {
            fixture
                .store
                .receipt_history_mismatch
                .store(true, Ordering::SeqCst);
        } else {
            *fixture.store.commit_error.lock().unwrap() = Some(if failure == 0 {
                SyncStoreErrorKind::StaleKeyBinding
            } else {
                SyncStoreErrorKind::CommitOutcomeUnknown
            });
        }
        let observer = Arc::new(DurableObserver {
            store: fixture.store.clone(),
            notices: Mutex::new(Vec::new()),
            cancel_after_page: None,
        });
        let engine = fixture.engine.with_progress(observer.clone());
        assert!(engine
            .pull(&fixture.target, fixture.operation)
            .await
            .is_err());
        let notices = observer.notices.lock().unwrap();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].phase(), SyncProgressPhase::CatalogCommitted);
    }
}
