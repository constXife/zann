use super::*;
use cosmic::iced::futures::StreamExt;
use cosmic::iced::runtime::{task::into_stream, Action};

fn read_completion(outcome: vault::Outcome) -> vault::Message {
    let vault::Outcome::Task(task) = outcome else {
        panic!("card read task")
    };
    let mut stream = into_stream(task).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            while let Some(action) = stream.next().await {
                if let Action::Output(message @ vault::Message::Loaded { .. }) = action {
                    return message;
                }
            }
            panic!("card read completion")
        })
}

#[test]
fn replacement_cancels_the_real_core_read_and_current_read_projects_typed_fields() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let old_id = page
        .items
        .iter()
        .find(|item| item.type_id != "login")
        .unwrap()
        .id
        .clone();
    let current_id = page
        .items
        .iter()
        .find(|item| item.type_id == "login")
        .unwrap()
        .id
        .clone();
    let mut state = vault::State::new(page, None);
    let old = state.update(vault::Message::Select(old_id), &session);
    let current = state.update(vault::Message::Select(current_id.clone()), &session);
    let cancelled = read_completion(old);
    assert!(
        matches!(&cancelled, vault::Message::Loaded { result: Err(error), .. } if error.contains("cancelled"))
    );
    state.update(cancelled, &session);
    assert_eq!(state.selected_item_id(), Some(current_id.as_str()));
    state.update(read_completion(current), &session);
    assert!(state.detail_ready());
    let detail = state.detail().unwrap();
    assert_eq!(detail.id, current_id);
    assert_eq!(
        detail
            .fields
            .iter()
            .map(|field| field.key.as_str())
            .collect::<Vec<_>>(),
        ["username", "password", "otp"]
    );
    assert!(
        detail
            .fields
            .iter()
            .find(|field| field.key == "password")
            .unwrap()
            .masked
    );
    assert!(detail.has_totp());
    // The retained payload still opens the canonical edit draft.
    assert!(matches!(
        state.update(vault::Message::OpenEdit, &session),
        vault::Outcome::None
    ));
    let _ = state.view();
}

#[test]
fn dropping_the_screen_cancels_a_worker_already_captured_by_its_task() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let id = page.items[0].id.clone();
    let mut state = vault::State::new(page, None);
    let pending = state.update(vault::Message::Select(id), &session);
    drop(state);
    assert!(
        matches!(read_completion(pending), vault::Message::Loaded { result: Err(error), .. } if error.contains("cancelled"))
    );
}
