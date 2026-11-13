use super::*;
use std::time::{Duration, Instant};

fn operation() -> (
    SessionOperation,
    zann_client::app::SessionCancellationHandle,
) {
    SessionOperation::new(Instant::now() + Duration::from_secs(5))
}

#[test]
fn cancelled_and_expired_reads_stop_before_opening_an_item() {
    let (_dir, core, _, _) = context_tests::fixture();
    let (op, cancel) = operation();
    cancel.cancel();
    assert!(matches!(
        core.item_read("invalid".into(), op),
        Err(LocalError::Cancelled)
    ));
    let (op, _) = SessionOperation::new(Instant::now());
    assert!(matches!(
        core.item_read("invalid".into(), op),
        Err(LocalError::DeadlineExceeded)
    ));
    assert_eq!(core.item_reads.len(), 0);
}

#[test]
fn waiting_read_cancels_and_releases_key_without_waiting_for_sqlite() {
    for locking in [false, true] {
        let (_dir, core, _, _) = context_tests::fixture();
        let id = core
            .debug_create_kv_item("Example".into(), "key".into(), "fixture value".into())
            .expect("item");
        let pool = core.pool();
        let key = core.master_key().expect("key");
        // Exhaust the adapter's five connections so item reading cannot finish.
        let _entered = core.runtime.enter();
        let permits = core.runtime.block_on(async {
            let mut permits = Vec::new();
            for _ in 0..5 {
                permits.push(pool.acquire().await.expect("connection"));
            }
            permits
        });
        let (op, cancel) = operation();
        let (tx, rx) = std::sync::mpsc::channel();
        let other = core.clone();
        let worker = std::thread::spawn(move || tx.send(other.item_read(id, op)).expect("result"));
        let until = Instant::now() + Duration::from_secs(2);
        while core.item_reads.len() == 0 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(core.item_reads.len(), 1);
        if locking {
            core.lock().expect("lock");
        } else {
            cancel.cancel();
        }
        let result = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("cancellation must not wait for SQLite");
        assert!(matches!(result, Err(LocalError::Cancelled)));
        worker.join().expect("worker");
        assert_eq!(core.item_reads.len(), 0);
        assert_eq!(Arc::strong_count(&key), if locking { 1 } else { 2 });
        drop(permits);
    }
}

#[test]
fn typed_read_is_bound_to_selected_storage_and_reports_source_errors() {
    let (_dir, core, _, remote) = context_tests::fixture();
    let id = core
        .debug_create_kv_item("Local".into(), "key".into(), "fixture value".into())
        .expect("item");
    let item = core
        .item_read(id.clone(), operation().0)
        .expect("typed item");
    assert_eq!(item.name, "Local");
    assert_eq!(item.payload.fields["value"].value, "fixture value");
    core.set_current_storage(remote.to_string())
        .expect("switch");
    let error = core
        .item_read(id, operation().0)
        .expect_err("other storage cannot read it");
    assert!(matches!(&error, LocalError::ItemRead(_)));
    assert!(std::error::Error::source(&error).is_some());
}
