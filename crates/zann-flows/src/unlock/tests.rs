use super::*;
#[test]
fn role_matrix_and_restart_only_ask_for_known_credentials() {
    assert_eq!(
        after_connection(false, false, false, true),
        Route::Password(Phase::Create)
    );
    assert_eq!(
        after_connection(true, false, true, true),
        Route::Password(Phase::Unlock)
    );
    assert_eq!(after_connection(true, true, true, true), Route::Open);
    assert_eq!(
        after_connection(true, true, false, false),
        Route::Password(Phase::AccountCreate)
    );
    assert_eq!(
        after_connection(true, true, false, true),
        Route::Password(Phase::AccountUnlock)
    );
    assert_eq!(after_device_unlock(false, None), Route::ChooseAccount);
    assert_eq!(after_device_unlock(true, None), Route::Open);
    assert_eq!(for_account(true, true), Route::Open);
    assert_eq!(for_account(true, false), Route::Password(Phase::Unlock));
    assert_eq!(for_account(false, true), Route::Connect);
}
#[test]
fn cancelled_and_replaced_operations_never_reopen_a_locked_ui() {
    let mut old = Operations::new(1);
    let delayed = old.begin().expect("operation");
    assert!(old.begin().is_none());
    old.cancel();
    let lock = old.begin().expect("lock");
    assert!(!old.finish(delayed));
    assert!(old.finish(lock));
    let mut next = Operations::new(2);
    let current = next.begin().expect("new screen");
    assert!(!next.finish(delayed));
    assert!(next.finish(current));
}
#[test]
fn deadlines_and_platform_prompts_preserve_unlock_policy() {
    assert!(!idle_lock_due(true, 0, i64::MAX));
    assert!(!idle_lock_due(false, 1, 60_000));
    assert!(!idle_lock_due(true, 1, -1));
    assert!(!idle_lock_due(true, 1, 59_999));
    assert!(idle_lock_due(true, 1, 60_000));
    assert!(!focus_lock_required(false, true, true));
    assert!(focus_lock_required(false, true, false));
    assert!(focus_lock_required(true, false, false));
    assert!(attempt_remembered_at_startup(true, true, Phase::Unlock));
    assert!(!attempt_remembered_at_startup(false, true, Phase::Unlock));
    assert!(!attempt_remembered_at_startup(
        true,
        true,
        Phase::AccountUnlock
    ));
}
