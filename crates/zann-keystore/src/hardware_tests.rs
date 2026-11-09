use crate::{
    FakeHardwareAuthenticator, FidoError, HardwareAuthenticator, RememberedUnlock, UnlockSource,
};

fn enroll(store: &mut RememberedUnlock, auth: &FakeHardwareAuthenticator) {
    let pending = RememberedUnlock::begin_enroll(auth, " Primary ").expect("touch 1");
    store
        .confirm_enroll(auth, pending, &[7; 32], "2026-11-09T00:00:00Z".into())
        .expect("touch 2");
    store.unlock_source = UnlockSource::HardwareKey;
}

#[test]
fn two_touches_then_one_touch_unlock_and_silent_presence() {
    let auth = FakeHardwareAuthenticator::new(1);
    let mut store = RememberedUnlock::default();
    assert_eq!(
        auth.status().unwrap().product_name.as_deref(),
        Some("Fake token 1")
    );
    let pending = RememberedUnlock::begin_enroll(&auth, " Primary ").unwrap();
    assert_eq!(auth.touch_requests(), 1);
    assert!(!store.is_armed());
    assert!(store.hardware_keys.is_empty());
    let entry = store
        .confirm_enroll(&auth, pending, &[7; 32], "date".into())
        .unwrap();
    assert_eq!(entry.label, "Primary");
    store.unlock_source = UnlockSource::HardwareKey;
    assert_eq!(auth.touch_requests(), 2);
    for _ in 0..10 {
        assert!(store.connected_hardware_key(&auth).is_some());
    }
    assert_eq!(auth.touch_requests(), 2, "polling must not ask for a touch");
    let recovered = store.unlock_with_hardware_key(&auth).unwrap();
    assert!(recovered == [7; 32]);
    assert_eq!(auth.touch_requests(), 3);
    // Persistence contains enough public metadata to re-derive the same DWK.
    let reopened: RememberedUnlock =
        serde_json::from_str(&serde_json::to_string(&store).unwrap()).unwrap();
    assert!(reopened.unlock_with_hardware_key(&auth).unwrap() == [7; 32]);
}

#[test]
fn failed_confirmation_preserves_existing_state() {
    for failure in [FidoError::Timeout, FidoError::NoHmacSecret, FidoError::Busy] {
        let auth = FakeHardwareAuthenticator::new(1);
        let mut store = RememberedUnlock::default();
        enroll(&mut store, &auth);
        let before = store.clone();
        let pending = RememberedUnlock::begin_enroll(&auth, "backup").unwrap();
        let expected_kind = failure.kind();
        auth.fail_next_derive(failure);
        let error = store
            .confirm_enroll(&auth, pending, &[7; 32], "date".into())
            .unwrap_err();
        assert_eq!(error.kind(), expected_kind);
        assert_eq!(store, before);
    }
}

#[test]
fn absent_wrong_and_swapped_tokens_fail_closed() {
    let auth = FakeHardwareAuthenticator::new(1);
    let mut store = RememberedUnlock::default();
    enroll(&mut store, &auth);
    let pending = RememberedUnlock::begin_enroll(&auth, "backup").unwrap();
    auth.connect(2);
    assert!(store.connected_hardware_key(&auth).is_none());
    assert_eq!(
        store.unlock_with_hardware_key(&auth).unwrap_err().kind(),
        "hardware_key_not_enrolled"
    );
    assert_eq!(
        store
            .confirm_enroll(&auth, pending, &[7; 32], "date".into())
            .unwrap_err()
            .kind(),
        "hardware_key_not_enrolled"
    );
    assert_eq!(store.hardware_keys.len(), 1);
    auth.disconnect();
    assert!(store.connected_hardware_key(&auth).is_none());
    assert_eq!(
        store.unlock_with_hardware_key(&auth).unwrap_err().kind(),
        "hardware_key_absent"
    );
    assert!(matches!(auth.status(), Err(FidoError::NoDevice)));
    auth.connect(1);
    assert!(store.connected_hardware_key(&auth).is_some());
}

#[test]
fn first_touch_failure_or_abandonment_never_arms_unlock() {
    let auth = FakeHardwareAuthenticator::new(1);
    let store = RememberedUnlock::default();
    auth.fail_next_create(FidoError::Timeout);
    assert!(
        matches!(RememberedUnlock::begin_enroll(&auth, "key"), Err(error) if error.kind() == "hardware_key_timeout")
    );
    drop(RememberedUnlock::begin_enroll(&auth, "key").unwrap());
    assert!(!store.is_armed());
    assert!(store.hardware_keys.is_empty());
}

#[test]
fn credential_and_salt_both_bind_derivation() {
    let auth = FakeHardwareAuthenticator::new(1);
    let first = auth.create_credential([1; 32]).unwrap();
    let second = auth.create_credential([1; 32]).unwrap();
    let mut different_salt = first.clone();
    different_salt.salt = [2; 32];
    let key = auth.derive_dwk(&first).unwrap();
    assert!(key == auth.derive_dwk(&first).unwrap());
    assert!(key != auth.derive_dwk(&second).unwrap());
    assert!(key != auth.derive_dwk(&different_salt).unwrap());
}
