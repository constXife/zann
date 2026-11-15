use super::*;

#[test]
fn creation_refuses_mismatched_passwords_even_when_submit_is_injected() {
    let (_dir, session) = vault_with_items();
    let mut state = master::State::new(master::Mode::Create, Some("new-server".into()));
    state.update(
        master::Message::PasswordInput("correct horse".into()),
        &session,
    );
    for confirmation in ["", "correct horses"] {
        state.update(
            master::Message::ConfirmationInput(confirmation.into()),
            &session,
        );
        assert!(!state.can_submit());
        assert!(matches!(
            state.update(master::Message::Submit, &session),
            master::Outcome::None
        ));
    }
    state.update(
        master::Message::ConfirmationInput("correct horse".into()),
        &session,
    );
    assert!(state.can_submit());
    assert!(matches!(
        state.update(master::Message::Submit, &session),
        master::Outcome::Task(_)
    ));
    assert!(!state.can_submit());
    assert!(matches!(
        state.update(master::Message::Submit, &session),
        master::Outcome::None
    ));
    assert!(!format!(
        "{:?}",
        master::Message::ConfirmationInput("sentinel-secret".into())
    )
    .contains("sentinel-secret"));
}

#[test]
fn unlocking_needs_one_password_without_starting_network_sync() {
    let (_dir, session) = vault_with_items();
    session.lock();
    let mut state = master::State::new(master::Mode::Unlock, None);
    state.update(
        master::Message::PasswordInput("demo-password".into()),
        &session,
    );
    assert!(state.can_submit());
    let master::Outcome::Task(task) = state.update(master::Message::PasswordSubmitted, &session)
    else {
        panic!("unlock task");
    };
    let mut stream = cosmic::iced::runtime::task::into_stream(task).unwrap();
    use cosmic::iced::{futures::StreamExt, runtime::Action};
    let completion = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            while let Some(action) = stream.next().await {
                if let Action::Output(message) = action {
                    return message;
                }
            }
            panic!("unlock completion");
        });
    match state.update(completion, &session) {
        master::Outcome::Opened { page, sync_after } => {
            assert_eq!(page.total, 2);
            assert_eq!(sync_after, None);
        }
        _ => panic!("unlock must succeed without starting network sync"),
    }
}

#[test]
fn enter_advances_to_confirmation_without_starting_either_creation_operation() {
    let (_dir, session) = vault_with_items();
    for mode in [master::Mode::Create, master::Mode::AccountCreate] {
        let mut state = master::State::new(mode, None);
        state.update(
            master::Message::PasswordInput("correct horse".into()),
            &session,
        );
        state.update(
            master::Message::ConfirmationInput("correct horse".into()),
            &session,
        );
        assert!(matches!(
            state.update(master::Message::PasswordSubmitted, &session),
            master::Outcome::Task(_)
        ));
        assert!(state.current_operation().is_none());
        assert!(state.can_submit());
    }
}

#[test]
fn search_and_editor_commands_are_blocked_while_a_draft_is_open() {
    let (_dir, session) = vault_with_items();
    let mut state = vault::State::new(local::items(&session.facade(), None, None).unwrap(), None);
    load_vault_context(&mut state, &session);
    assert!(state.can_focus_search());
    assert!(matches!(
        state.update(vault::Message::FocusSearch, &session),
        vault::Outcome::Task(_)
    ));
    state.update(vault::Message::OpenCreate, &session);
    let draft = state.editing_request_id();
    assert!(!state.can_focus_search());
    assert!(!state.can_create());
    assert!(!state.can_edit());
    for message in [
        vault::Message::FocusSearch,
        vault::Message::OpenCreate,
        vault::Message::OpenEdit,
    ] {
        assert!(matches!(
            state.update(message, &session),
            vault::Outcome::None
        ));
        assert_eq!(state.editing_request_id(), draft);
    }
}

#[test]
fn a_connected_unlock_completion_hands_sync_to_the_workspace() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let mut state = master::State::new(master::Mode::Unlock, Some("configured-server".into()));
    state.update(
        master::Message::PasswordInput("demo-password".into()),
        &session,
    );
    state.update(master::Message::Submit, &session);
    let operation = state.current_operation().unwrap();
    let completed = master::Message::Opened(operation, Ok(master::OpenResult::Vault { page }));
    match state.update(completed, &session) {
        master::Outcome::Opened { page, sync_after } => {
            assert_eq!(page.total, 2);
            assert_eq!(sync_after.as_deref(), Some("configured-server"));
        }
        _ => panic!("the unlock completion must hand synchronization to the workspace"),
    }
}
