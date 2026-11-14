use super::*;

fn remote() -> (tempfile::TempDir, crate::session::Session, Arc<Remote>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let (session, _) =
        crate::session::Session::open_at(dir.path().join("local.sqlite")).expect("session");
    let remote = Arc::new(Remote::new().expect("remote"));
    (dir, session, remote)
}
#[test]
fn cancel_before_worker_start_is_registered_and_sticky() {
    let (_dir, _session, remote) = remote();
    let id = OperationId {
        instance: 1,
        sequence: 1,
    };
    let plan = remote
        .plan(Effect::Probe {
            id,
            url: "https://must-not-be-contacted.invalid".into(),
        })
        .expect("plan");
    let cancellation = remote
        .state
        .lock()
        .expect("lock")
        .active
        .as_ref()
        .expect("active")
        .1
        .clone();
    remote.cancel(id);
    assert!(cancellation.is_cancelled());
    assert!(matches!(
        remote.accept(plan.run()),
        Some(Completion::Probed(Err(Failure::Cancelled)))
    ));
    remote.close();
    assert!(remote
        .plan(Effect::Probe {
            id,
            url: "https://must-not-be-contacted.invalid".into()
        })
        .is_err());
}
#[test]
fn cancelling_an_old_operation_cannot_cancel_a_new_one() {
    let (_dir, _session, remote) = remote();
    let old = OperationId {
        instance: 1,
        sequence: 1,
    };
    let next = OperationId {
        instance: 1,
        sequence: 2,
    };
    let _old = remote
        .plan(Effect::Probe {
            id: old,
            url: "https://old.invalid".into(),
        })
        .expect("old plan");
    let next_plan = remote
        .plan(Effect::Probe {
            id: next,
            url: "https://new.invalid".into(),
        })
        .expect("new plan");
    remote.cancel(old);
    assert!(!remote
        .state
        .lock()
        .expect("lock")
        .active
        .as_ref()
        .expect("active")
        .1
        .is_cancelled());
    remote.close();
    assert!(remote.accept(next_plan.run()).is_none());
}
