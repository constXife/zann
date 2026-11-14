use super::*;
use cosmic::iced::futures::{executor::block_on, StreamExt};
use cosmic::iced::runtime::{task::into_stream, Action as RuntimeAction};

fn send(state: &mut State, message: Message) -> Vec<Outcome> {
    state.update(state.event(message))
}
fn result(outcomes: Vec<Outcome>) -> Event {
    let Outcome::Task(task) = outcomes.into_iter().next().expect("task") else {
        panic!("task expected")
    };
    let mut stream = into_stream(task).expect("stream");
    match block_on(stream.next()).expect("output") {
        RuntimeAction::Output(event) => event,
        _ => panic!("only typed completions come back from Connect tasks"),
    }
}
#[test]
fn cancel_before_a_task_runs_suppresses_its_result_and_a_reopened_screen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_session, _) =
        crate::session::Session::open_at(dir.path().join("local.sqlite")).expect("session");
    let mut old = State::with_server_url("https://must-not-be-contacted.invalid".into());
    let pending = send(&mut old, Message::Probe);
    assert!(old.flow.snapshot().busy);
    assert!(matches!(
        send(&mut old, Message::Cancel).as_slice(),
        [Outcome::Cancelled]
    ));
    let completion = result(pending);
    assert!(old.update(completion.clone()).is_empty());
    let mut reopened = State::default();
    assert!(reopened.update(completion).is_empty());
    assert_eq!(reopened.stage(), &Stage::Server);
    assert!(reopened.remote.is_none());
}
#[test]
fn dropping_a_screen_cancels_work_already_captured_by_its_task() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_session, _) =
        crate::session::Session::open_at(dir.path().join("local.sqlite")).expect("session");
    let mut old = State::with_server_url("https://must-not-be-contacted.invalid".into());
    let pending = send(&mut old, Message::Probe);
    drop(old);
    let completion = result(pending);
    let mut reopened = State::default();
    assert!(reopened.update(completion).is_empty());
}
#[test]
fn stale_inputs_cannot_dispatch_work_into_a_reopened_screen() {
    let mut old = State::default();
    let mut reopened = State::with_server_url("https://new.example".into());
    for message in [
        Message::Probe,
        Message::StartOidc,
        Message::TrustFingerprint,
        Message::Cancel,
        Message::UrlInput("https://old.example".into()),
        Message::OpenAuthUrl,
    ] {
        assert!(reopened.update(old.event(message)).is_empty());
    }
    assert_eq!(reopened.server_url(), "https://new.example");
    assert!(reopened.remote.is_none());
    assert!(matches!(
        send(&mut old, Message::Back).as_slice(),
        [Outcome::Cancelled]
    ));
}

#[test]
fn duplicate_submit_preserves_the_password_draft_until_admitted() {
    use zann_core::AuthMethod;
    use zann_flows::connect::{Probe, ServerInfo};
    let mut state = State::default();
    let effects = state.flow.dispatch(Action::Probe {
        url: "https://fixture.example".into(),
    });
    let id = effects
        .iter()
        .find_map(|effect| effect.operation().map(|(id, _)| id))
        .expect("probe ID");
    state.flow.complete(
        id,
        Completion::Probed(Ok(Probe::Ready(ServerInfo {
            methods: vec![AuthMethod::Password],
            registration_available: false,
            server_name: None,
        }))),
    );
    state.email = "person@example.test".into();
    state.flow.dispatch(Action::SubmitPassword {
        email: state.email.clone(),
        password: "in-flight".into(),
        full_name: None,
    });
    send(&mut state, Message::PasswordInput("retry-draft".into()));
    assert!(send(&mut state, Message::SubmitPassword).is_empty());
    assert_eq!(state.password, "retry-draft");
    assert!(
        state.remote.is_none(),
        "rejected input must not initialize an executor"
    );
}
