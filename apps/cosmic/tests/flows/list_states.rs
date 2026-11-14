use super::*;
use vault::ListEmptyState;

fn activate(state: &mut vault::State, category: &str) {
    let id = state
        .nav_model()
        .iter()
        .find(|id| {
            state
                .nav_model()
                .data::<String>(*id)
                .is_some_and(|value| value == category)
        })
        .unwrap();
    state.activate_nav(id);
}

fn empty_page() -> local::ItemsPage {
    local::ItemsPage {
        items: vec![],
        next_cursor: None,
        total: 0,
        counts: ItemCounts::default(),
    }
}

#[test]
fn empty_search_waits_for_completion_and_offers_clear_instead_of_creation() {
    let (_dir, session) = vault_with_items();
    let mut state = vault::State::new(empty_page(), None);
    state.update(vault::Message::QueryInput("missing".into()), &session);
    assert_eq!(state.empty_state(), Some(ListEmptyState::Loading));
    state.update(
        vault::Message::SearchLoaded {
            generation: 1,
            query: "missing".into(),
            result: Ok(empty_page()),
        },
        &session,
    );
    assert_eq!(state.empty_state(), Some(ListEmptyState::NoSearchResults));
    let _ = state.view();
    assert!(matches!(
        state.update(vault::Message::ClearQuery, &session),
        vault::Outcome::Task(_)
    ));
    assert_eq!(state.empty_state(), Some(ListEmptyState::Loading));
    state.update(
        vault::Message::SearchLoaded {
            generation: 2,
            query: String::new(),
            result: Ok(empty_page()),
        },
        &session,
    );
    assert_eq!(state.empty_state(), Some(ListEmptyState::EmptyCategory));
    // A superseded search cannot replace the cleared query's state.
    state.update(
        vault::Message::SearchLoaded {
            generation: 1,
            query: "missing".into(),
            result: Err("old failure".into()),
        },
        &session,
    );
    assert_eq!(state.empty_state(), Some(ListEmptyState::EmptyCategory));
}

#[test]
fn categories_use_shared_creation_actions_and_trash_has_none() {
    let (_dir, session) = vault_with_items();
    let mut state = vault::State::new(empty_page(), None);
    state.update(
        vault::Message::VaultsLoaded(Ok(local::vault_context(&session.facade()).unwrap())),
        &session,
    );
    for category in ["all", "note", "trash"] {
        activate(&mut state, category);
        assert_eq!(state.empty_state(), Some(ListEmptyState::EmptyCategory));
        let expected = zann_ui_core::category_views(
            &ItemCounts::default(),
            zann_ui_core::VaultScope::Personal,
        )
        .into_iter()
        .find(|view| view.id == category)
        .unwrap()
        .create_action;
        assert_eq!(
            state
                .empty_create_action()
                .as_ref()
                .map(|action| (&action.type_id, &action.label_key)),
            expected
                .as_ref()
                .map(|action| (&action.type_id, &action.label_key))
        );
        let _ = state.view();
    }
    assert!(state.empty_create_action().is_none());
}

#[test]
fn category_changes_discard_pending_card_reads() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let id = page
        .items
        .iter()
        .find(|item| item.type_id == "login")
        .unwrap()
        .id
        .clone();
    let mut state = vault::State::new(page, None);
    state.update(
        vault::Message::VaultsLoaded(Ok(local::vault_context(&session.facade()).unwrap())),
        &session,
    );
    let _pending = state.update(vault::Message::Select(id.clone()), &session);
    let request = state.detail_request_id();
    activate(&mut state, "note");
    let detail = Detail::parse(local::item_get(&session.facade(), id).unwrap()).unwrap();
    state.update(
        vault::Message::Loaded {
            request,
            result: Ok(detail),
        },
        &session,
    );
    assert!(state.detail().is_none());
    assert!(state.selected_item_id().is_none());
}

#[test]
fn search_supersedes_pagination_without_waiting_for_the_old_page() {
    let (_dir, session) = vault_with_items();
    let mut page = local::items(&session.facade(), None, None).unwrap();
    page.next_cursor = Some("next".into());
    let mut state = vault::State::new(page.clone(), None);
    let _pagination = state.update(vault::Message::LoadMore, &session);
    assert!(matches!(
        state.update(vault::Message::QueryInput("missing".into()), &session),
        vault::Outcome::Task(_)
    ));
    assert_eq!(state.empty_state(), Some(ListEmptyState::Loading));
    state.update(
        vault::Message::MoreLoaded {
            generation: 0,
            result: Ok(page),
        },
        &session,
    );
    state.update(
        vault::Message::SearchLoaded {
            generation: 1,
            query: "missing".into(),
            result: Ok(empty_page()),
        },
        &session,
    );
    assert_eq!(state.empty_state(), Some(ListEmptyState::NoSearchResults));
    let _ = state.view();
}

#[test]
fn failed_reads_and_pending_category_pages_are_not_empty_categories() {
    let (_dir, session) = vault_with_items();
    let mut state = vault::State::new(empty_page(), Some("offline".into()));
    assert_eq!(state.empty_state(), Some(ListEmptyState::EmptyCategory));
    let mut page = empty_page();
    page.next_cursor = Some("next".into());
    state = vault::State::new(page, None);
    assert_eq!(state.empty_state(), Some(ListEmptyState::Loading));
    let _ = state.view();
    let _pagination = state.update(vault::Message::LoadMore, &session);
    state.update(
        vault::Message::MoreLoaded {
            generation: 0,
            result: Err("page failed".into()),
        },
        &session,
    );
    assert_eq!(state.empty_state(), Some(ListEmptyState::Failed));
}

#[test]
fn background_sync_failure_preserves_empty_state_actions_and_list_errors_keep_their_scope() {
    use std::time::Instant;
    let (_dir, session) = vault_with_items();
    let mut state = vault::State::new(empty_page(), None);
    state.update(vault::Message::QueryInput("missing".into()), &session);
    state.update(
        vault::Message::SearchLoaded {
            generation: 1,
            query: "missing".into(),
            result: Ok(empty_page()),
        },
        &session,
    );
    let now = Instant::now();
    session.auto_sync().unlocked(now, false);
    let ticket = session.auto_sync().take_due(now).unwrap();
    state.update(
        vault::Message::AutoSynced {
            ticket,
            storage_id: "remote-storage".into(),
            list_generation: 1,
            result: Err(local::SyncFailure::Other("offline".into())),
        },
        &session,
    );
    assert_eq!(state.empty_state(), Some(ListEmptyState::NoSearchResults));
    let _ = state.view();
    state.update(vault::Message::ClearQuery, &session);
    state.update(
        vault::Message::SearchLoaded {
            generation: 2,
            query: String::new(),
            result: Ok(empty_page()),
        },
        &session,
    );
    assert_eq!(state.empty_state(), Some(ListEmptyState::EmptyCategory));
    assert!(matches!(state.update(vault::Message::CopyError, &session),
        vault::Outcome::Copy { value, .. } if value.contains("offline")));
    state.update(vault::Message::QueryInput("retry".into()), &session);
    state.update(
        vault::Message::SearchLoaded {
            generation: 3,
            query: "retry".into(),
            result: Err("list read failed".into()),
        },
        &session,
    );
    assert_eq!(state.empty_state(), Some(ListEmptyState::Failed));
    assert!(matches!(state.update(vault::Message::CopyError, &session),
        vault::Outcome::Copy { value, .. } if value == "list read failed"));
}
