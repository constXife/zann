use super::*;

#[test]
fn cancel_before_worker_registration_is_sticky() {
    let mut state = LoginState::default();
    state.cancel();
    assert!(state.start().is_err());
    assert!(state.cancellation.is_none());
}

#[test]
fn cancel_during_begin_cancels_operation_and_rejects_late_receiver() {
    let state = Arc::new(Mutex::new(LoginState::default()));
    let operation = state.lock().expect("lock").start().expect("start");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let worker_state = Arc::clone(&state);
    let worker = std::thread::spawn(move || {
        ready_tx.send(()).expect("ready");
        resume_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("resume");
        assert!(operation.is_cancelled());
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(worker_state
            .lock()
            .expect("lock")
            .install_receiver(rx)
            .is_err());
        assert!(tx.send(OidcStatus::Pending).is_err());
    });
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("registered");
    state.lock().expect("lock").cancel();
    resume_tx.send(()).expect("resume worker");
    worker.join().expect("worker");
    let state = state.lock().expect("lock");
    assert!(state.receiver.is_none());
    assert!(state.cancellation.is_none());
}

#[test]
fn cancel_after_receiver_registration_drops_pending_results_and_is_idempotent() {
    let mut state = LoginState::default();
    let operation = state.start().expect("start");
    let (tx, rx) = std::sync::mpsc::channel();
    state.install_receiver(rx).expect("install");
    tx.send(OidcStatus::Success {
        storage_id: "old".into(),
        has_personal_keys: false,
    })
    .expect("queue");
    state.cancel();
    state.cancel();
    assert!(operation.is_cancelled());
    assert!(state.receiver.is_none());
    assert!(tx.send(OidcStatus::Pending).is_err());
    assert!(state.start().is_err());
}
