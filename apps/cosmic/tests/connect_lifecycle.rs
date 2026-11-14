use zann_cosmic::backend::remote::LoginOutcome;
use zann_cosmic::screens::{connect, master};

#[test]
fn cancelled_connect_rejects_late_success() {
    let mut state = connect::State::default();
    let cancelled = state.event(connect::Message::Cancel);
    let late = state.event(connect::Message::Outcome(Ok(LoginOutcome::Success {
        storage_id: "stale-storage".into(),
        has_personal_keys: false,
    })));
    state.update(cancelled);
    let outcome = state.update(late);
    assert!(matches!(outcome, connect::Outcome::None));
}

#[test]
fn password_messages_redact_debug() {
    let secret = "synthetic-password-debug-sentinel";
    assert!(!format!("{:?}", connect::Message::PasswordInput(secret.into())).contains(secret));
    assert!(!format!(
        "{:?}",
        connect::State::default().event(connect::Message::PasswordInput(secret.into()))
    )
    .contains(secret));
}

#[test]
fn master_password_message_redacts_debug() {
    let secret = "synthetic-master-password-debug-sentinel";
    assert!(!format!("{:?}", master::Message::PasswordInput(secret.into())).contains(secret));
}

#[test]
fn scoped_oidc_completion_redacts_debug() {
    let secret = "synthetic-oidc-state-sentinel";
    let state = connect::State::default();
    let event = state.event(connect::Message::OidcStarted(Ok(format!(
        "https://issuer.example/authorize?state={secret}"
    ))));
    assert!(!format!("{event:?}").contains(secret));
}
