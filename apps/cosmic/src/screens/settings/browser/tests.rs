use super::*;
use cosmic::iced::{
    futures::StreamExt,
    runtime::{task::into_stream, Action},
};

fn fixture() -> (tempfile::TempDir, Session, State) {
    let directory = tempfile::tempdir().unwrap();
    let (session, _) = Session::open_at(directory.path().join("local.sqlite")).unwrap();
    let state = State::new(DevicePreferences::default(), false, directory.path().into());
    (directory, session, state)
}

fn completion(outcome: Outcome) -> super::super::Message {
    let Outcome::Task(task) = outcome else {
        panic!("expected settings task");
    };
    let mut stream = into_stream(task).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            while let Some(action) = stream.next().await {
                if let Action::Output(message) = action {
                    return message;
                }
            }
            panic!("expected completion");
        })
}

fn begin(state: &mut State, session: &Session) {
    let message = completion(state.update_browser(Message::Begin, session));
    state.update(message, session);
}

#[test]
fn copies_current_code_through_the_shell_and_feedback_is_transient() {
    let (_dir, session, mut state) = fixture();
    begin(&mut state, &session);
    let expected = state.browser_code.as_ref().unwrap().code.value.clone();
    let message = completion(state.update_browser(Message::Copy, &session));
    let diagnostic = Message::Code(Ok(PairingCode {
        id: "public-id".into(),
        value: "pairing-code-sentinel".to_string().into(),
        expires_in_seconds: 120,
    }));
    assert!(!format!("{diagnostic:?}").contains("pairing-code-sentinel"));
    assert!(
        matches!(state.update(message, &session), Outcome::Copy(value) if value == expected.as_str())
    );
    assert!(state.browser_code.as_ref().unwrap().copied());
    state.browser_code.as_mut().unwrap().copied_until =
        Some(Instant::now() - Duration::from_secs(1));
    assert!(!state.browser_code.as_ref().unwrap().copied());
    let _ = state.browser_section();
}

#[test]
fn absent_expired_and_consumed_codes_cannot_be_copied() {
    let (_dir, session, mut state) = fixture();
    assert!(matches!(
        state.update_browser(Message::Copy, &session),
        Outcome::None
    ));
    begin(&mut state, &session);
    state.browser_code.as_mut().unwrap().expires = Instant::now() - Duration::from_secs(1);
    assert!(matches!(
        state.update_browser(Message::Copy, &session),
        Outcome::None
    ));
    begin(&mut state, &session);
    // The native owner can consume/replace the code before the UI refresh arrives.
    session.browser_control().begin_pairing().unwrap();
    let message = completion(state.update_browser(Message::Copy, &session));
    assert!(matches!(state.update(message, &session), Outcome::None));
    assert!(state.browser_code.is_none());
}

#[test]
fn replacement_rejects_old_copy_and_metadata_completions() {
    let (_dir, session, mut state) = fixture();
    begin(&mut state, &session);
    let old_copy = completion(state.update_browser(Message::Copy, &session));
    let old_metadata = completion(state.update_browser(Message::Refresh, &session));
    begin(&mut state, &session);
    let current = state.code_id();
    assert!(matches!(state.update(old_copy, &session), Outcome::None));
    state.update(old_metadata, &session);
    assert_eq!(state.code_id(), current);
    assert!(!state.browser_code.as_ref().unwrap().copied());
}

#[test]
fn timer_expires_the_view_and_coalesces_native_status_reads() {
    let (_dir, session, mut state) = fixture();
    begin(&mut state, &session);
    let pending = state.update_browser(Message::Tick, &session);
    assert!(matches!(
        state.update_browser(Message::Tick, &session),
        Outcome::None
    ));
    state.update(completion(pending), &session);
    state.browser_code.as_mut().unwrap().expires = Instant::now() - Duration::from_secs(1);
    state.update_browser(Message::Tick, &session);
    assert!(state.browser_code.is_none());
}

#[test]
fn code_expiring_while_copy_is_checked_is_not_released() {
    let (_dir, session, mut state) = fixture();
    begin(&mut state, &session);
    let checked = completion(state.update_browser(Message::Copy, &session));
    state.browser_code.as_mut().unwrap().expires = Instant::now() - Duration::from_secs(1);
    assert!(matches!(state.update(checked, &session), Outcome::None));
    assert!(state.browser_code.is_none());
}

#[test]
fn failed_copy_check_preserves_the_error_and_allows_retry() {
    let (_dir, session, mut state) = fixture();
    begin(&mut state, &session);
    let _pending = state.update_browser(Message::Copy, &session);
    let id = state.code_id().unwrap();
    assert!(matches!(
        state.update_browser(
            Message::CopyChecked {
                id,
                result: Err("native status check failed".into()),
            },
            &session
        ),
        Outcome::None
    ));
    assert_eq!(state.error.as_deref(), Some("native status check failed"));
    assert!(!state.browser_code.as_ref().unwrap().copying);
    assert!(matches!(
        state.update_browser(Message::Copy, &session),
        Outcome::Task(_)
    ));
}
