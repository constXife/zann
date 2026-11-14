use zann_cosmic::screens::{connect, master};

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
