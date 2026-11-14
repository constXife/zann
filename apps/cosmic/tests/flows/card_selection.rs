use super::*;
use zann_cosmic::screens::detail::Message as FieldMessage;

fn card(session: &Session, id: &str) -> Detail {
    Detail::parse(local::item_get(&session.facade(), id.to_owned()).unwrap()).unwrap()
}

fn complete(state: &mut vault::State, session: &Session, request: u64, detail: Detail) {
    state.update(
        vault::Message::Loaded {
            request,
            result: Ok(detail),
        },
        session,
    );
}

#[test]
fn replacement_selects_immediately_masks_retained_card_and_blocks_actions() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let first = page
        .items
        .iter()
        .find(|item| item.type_id == "login")
        .unwrap()
        .id
        .clone();
    let second = page
        .items
        .iter()
        .find(|item| item.id != first)
        .unwrap()
        .id
        .clone();
    let mut state = vault::State::new(page, None);
    load_vault_context(&mut state, &session);
    let _first = state.update(vault::Message::Select(first.clone()), &session);
    let request = state.detail_request_id();
    complete(&mut state, &session, request, card(&session, &first));
    let password = state
        .detail()
        .unwrap()
        .fields
        .iter()
        .position(|field| field.key == "password")
        .unwrap();
    state.update(
        vault::Message::Detail(FieldMessage::ToggleReveal(password)),
        &session,
    );
    state.update(
        vault::Message::Detail(FieldMessage::Copy {
            index: password,
            value: "fixture".into(),
        }),
        &session,
    );
    assert!(state.detail().unwrap().fields[password].revealed);

    let _pending = state.update(vault::Message::Select(second.clone()), &session);
    assert_eq!(state.selected_item_id(), Some(second.as_str()));
    assert_eq!(state.detail().unwrap().id, first);
    assert!(!state.detail_ready());
    assert!(!state.detail().unwrap().fields[password].revealed);
    assert!(state.detail().unwrap().copied_field().is_none());
    for message in [
        vault::Message::OpenEdit,
        vault::Message::OpenHistory,
        vault::Message::Detail(FieldMessage::ToggleReveal(password)),
        vault::Message::Detail(FieldMessage::Copy {
            index: password,
            value: "fixture".into(),
        }),
    ] {
        assert!(matches!(
            state.update(message, &session),
            vault::Outcome::None
        ));
    }
    let request = state.detail_request_id();
    complete(&mut state, &session, request, card(&session, &second));
    assert!(state.detail_ready());
    assert_eq!(state.detail().unwrap().id, second);
    let _ = state.view();
}

#[test]
fn latest_selection_wins_even_when_returning_to_the_same_item() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let a = page.items[0].id.clone();
    let b = page.items[1].id.clone();
    let mut state = vault::State::new(page, None);
    load_vault_context(&mut state, &session);
    let _first = state.update(vault::Message::Select(a.clone()), &session);
    let old = state.detail_request_id();
    let _second = state.update(vault::Message::Select(b.clone()), &session);
    let middle = state.detail_request_id();
    let _third = state.update(vault::Message::Select(a.clone()), &session);
    let current = state.detail_request_id();
    complete(&mut state, &session, old, card(&session, &a));
    state.update(
        vault::Message::Loaded {
            request: middle,
            result: Err("late failure".into()),
        },
        &session,
    );
    assert!(state.detail().is_none());
    complete(&mut state, &session, current, card(&session, &a));
    complete(&mut state, &session, middle, card(&session, &b));
    assert_eq!(state.detail().unwrap().id, a);
    assert!(state.detail_ready());
}

#[test]
fn filtered_or_replaced_context_cannot_receive_a_late_card() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let id = page.items[0].id.clone();
    let mut state = vault::State::new(page.clone(), None);
    load_vault_context(&mut state, &session);
    let _pending = state.update(vault::Message::Select(id.clone()), &session);
    let old = state.detail_request_id();
    state.update(vault::Message::QueryInput("no-such-item".into()), &session);
    complete(&mut state, &session, old, card(&session, &id));
    assert!(state.selected_item_id().is_none());
    assert!(state.detail().is_none());
    state.replace_page(page.clone());
    let _pending = state.update(vault::Message::Select(id.clone()), &session);
    let old = state.detail_request_id();
    state.replace_page(page);
    complete(&mut state, &session, old, card(&session, &id));
    assert!(state.detail().is_none());
}

#[test]
fn a_destroyed_screen_and_a_failed_read_cannot_restore_an_old_card() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let id = page.items[0].id.clone();
    let mut old = vault::State::new(page.clone(), None);
    load_vault_context(&mut old, &session);
    let _pending = old.update(vault::Message::Select(id.clone()), &session);
    let previous = old.detail_request_id();
    drop(old);
    let mut state = vault::State::new(page, None);
    load_vault_context(&mut state, &session);
    let _pending = state.update(vault::Message::Select(id.clone()), &session);
    let current = state.detail_request_id();
    assert_ne!(previous, current);
    complete(&mut state, &session, previous, card(&session, &id));
    assert!(state.detail().is_none());
    state.update(
        vault::Message::Loaded {
            request: current,
            result: Err("read failed".into()),
        },
        &session,
    );
    assert!(!state.detail_ready());
    let _ = state.view();
    let _retry = state.update(vault::Message::Select(id.clone()), &session);
    let retry = state.detail_request_id();
    complete(&mut state, &session, retry, card(&session, &id));
    assert!(state.detail_ready());
}
