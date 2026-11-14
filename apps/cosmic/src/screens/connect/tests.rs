use cosmic::iced::futures::{executor::block_on, StreamExt};
use cosmic::iced::runtime::{task::into_stream, Action};

use super::*;

fn send(state: &mut State, message: Message) -> Outcome {
    state.update(state.event(message))
}

fn queued(outcome: Outcome) -> Event {
    let Outcome::Task(task) = outcome else {
        panic!("expected a queued Connect event");
    };
    let mut stream = into_stream(task).expect("task stream");
    match block_on(stream.next()).expect("queued event") {
        Action::Output(event) => event,
        _ => panic!("expected output, not an OS effect"),
    }
}

fn probe(methods: Vec<Method>) -> ServerProbe {
    ServerProbe {
        methods,
        register: false,
        server_name: None,
        fingerprint_changed: None,
    }
}

#[test]
fn old_screen_events_cannot_mutate_a_reopened_connect() {
    let mut old = State::default();
    let mut reopened = State::with_server_url("https://new.example".into());
    for message in [
        Message::Probed(Ok(probe(vec![Method::Password]))),
        Message::Probed(Err("old probe failure".into())),
        Message::Outcome(Ok(LoginOutcome::Success {
            storage_id: "old".into(),
            has_personal_keys: true,
        })),
        Message::Outcome(Err("old login failure".into())),
        Message::OidcStarted(Ok("https://old.example/authorize".into())),
        Message::FingerprintTrusted(Ok(())),
        Message::StartOidc,
        Message::Probe,
        Message::Poll,
        Message::Cancel,
        Message::UrlInput("https://old.example".into()),
    ] {
        let late = old.event(message);
        assert!(matches!(reopened.update(late.clone()), Outcome::None));
        send(&mut old, Message::Cancel);
        assert!(matches!(old.update(late), Outcome::None));
        assert_eq!(reopened.stage, Stage::Server);
        assert_eq!(reopened.url, "https://new.example");
        assert!(!reopened.busy);
        assert!(reopened.error.is_none());
        assert!(reopened.remote.is_none());
        assert!(reopened.authorization_url.is_none());
    }
    assert!(
        matches!(send(&mut reopened, Message::Outcome(Ok(LoginOutcome::Success {
        storage_id: "current".into(), has_personal_keys: false,
    }))), Outcome::Connected { storage_id, .. } if storage_id == "current")
    );
}

#[test]
fn queued_continuations_keep_the_originating_screen() {
    for completion in [
        Message::Probed(Ok(probe(vec![Method::Oidc]))),
        Message::FingerprintTrusted(Ok(())),
        Message::OidcStarted(Ok("https://issuer.example/authorize?state=private".into())),
    ] {
        let mut old = State::default();
        old.busy = true;
        old.stage = match &completion {
            Message::FingerprintTrusted(_) => Stage::Fingerprint {
                old: "old".into(),
                new: "new".into(),
            },
            Message::OidcStarted(_) => Stage::Oidc,
            _ => Stage::Server,
        };
        let continuation = queued(send(&mut old, completion));
        assert!(old.accepts(&continuation.message));
        send(&mut old, Message::Cancel);
        assert!(matches!(old.update(continuation.clone()), Outcome::None));
        let mut reopened = State::default();
        assert!(matches!(reopened.update(continuation), Outcome::None));
        assert!(reopened.remote.is_none());
    }
}

#[test]
fn an_async_task_keeps_its_origin_after_the_screen_is_dropped() {
    let old = State::default();
    let (tx, rx) = cosmic::iced::futures::channel::oneshot::channel();
    let task = old.task(Task::future(async move { rx.await.expect("completion") }));
    drop(old);
    tx.send(Message::Outcome(Ok(LoginOutcome::Success {
        storage_id: "old".into(),
        has_personal_keys: false,
    })))
    .expect("send completion");
    let mut reopened = State::default();
    assert!(matches!(reopened.update(queued(task)), Outcome::None));
    assert_eq!(reopened.stage, Stage::Server);
}

#[test]
fn current_oidc_completion_opens_only_after_a_scoped_continuation() {
    let mut state = State::default();
    let open = queued(send(
        &mut state,
        Message::OidcStarted(Ok("https://issuer.example/authorize".into())),
    ));
    assert!(
        matches!(state.update(open), Outcome::OpenUrl(url) if url == "https://issuer.example/authorize")
    );
}

#[test]
fn busy_forms_do_not_admit_duplicate_submits_or_change_inputs() {
    let mut state = State::default();
    state.busy = true;
    // An empty URL makes this safe even if the admission guard regresses:
    // the duplicate must not replace the in-flight operation's error/state.
    assert!(matches!(send(&mut state, Message::Probe), Outcome::None));
    send(
        &mut state,
        Message::UrlInput("https://replacement.example".into()),
    );
    assert!(state.error.is_none());
    assert!(state.url.is_empty());
    assert!(state.busy);

    state.stage = Stage::Password;
    state.email = "person@example.test".into();
    state.password = "synthetic-password".into();
    assert!(!state.accepts(&Message::SubmitPassword));
    send(&mut state, Message::PasswordInput("replacement".into()));
    assert_eq!(state.password, "synthetic-password");
    state.busy = false;
    assert!(state.accepts(&Message::SubmitPassword));

    state.stage = Stage::Oidc;
    state.authorization_url = Some("https://issuer.example/authorize".into());
    assert!(!state.accepts(&Message::StartOidc));
    state.stage = Stage::Fingerprint {
        old: "old".into(),
        new: "new".into(),
    };
    state.busy = true;
    assert!(!state.accepts(&Message::TrustFingerprint));
}

#[test]
fn success_is_terminal_and_clears_sensitive_screen_state() {
    let mut state = State::default();
    state.password = "synthetic-password".into();
    state.authorization_url = Some("https://issuer.example/authorize".into());
    let success = state.event(Message::Outcome(Ok(LoginOutcome::Success {
        storage_id: "current".into(),
        has_personal_keys: true,
    })));
    assert!(matches!(
        state.update(success.clone()),
        Outcome::Connected { .. }
    ));
    assert!(matches!(state.update(success), Outcome::None));
    assert!(state.password.is_empty());
    assert!(state.authorization_url.is_none());
}
