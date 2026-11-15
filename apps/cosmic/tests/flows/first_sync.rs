use super::*;

fn refresh(state: &mut vault::State, session: &Session, storage: &str) -> vault::Message {
    let outcome = state.update(
        vault::Message::SyncCommitted {
            run: state.sync_run_id(),
            storage_id: storage.into(),
        },
        session,
    );
    sync_navigation::completion(outcome, |message| {
        matches!(message, vault::Message::ProgressWorkspaceLoaded { .. })
    })
}

#[test]
fn first_catalog_and_committed_items_are_visible_before_network_completion() {
    let (_dir, session) = vault_with_items();
    let storage = local::current_storage_id(&session.facade()).unwrap();
    let mut state = vault::State::new(list_states::empty_page(), None);
    state.set_initial_sync_target(Some(storage.clone()), true);
    assert_eq!(state.empty_state(), Some(vault::ListEmptyState::FirstSync));
    assert!(!state.can_create());
    session
        .auto_sync()
        .unlocked(std::time::Instant::now(), true);
    let _network = state.update(vault::Message::SyncNow, &session);
    let message = refresh(&mut state, &session, &storage);
    state.update(message, &session);
    assert_eq!(state.selected_storage_id(), Some(storage.as_str()));
    assert_eq!(state.visible().len(), 2);
    assert!(state.can_create());
    assert_eq!(state.empty_state(), None);
    assert!(
        session.auto_sync().next_due().is_none(),
        "a commit notice does not complete or start network work"
    );
}

#[test]
fn first_catalog_initializes_the_vault_after_the_server_is_already_selected() {
    let (_dir, session) = vault_with_items();
    let facade = session.facade();
    let mut context = local::vault_context(&facade).unwrap();
    let storage = context.current_storage_id.clone().unwrap();
    // Before the first catalog commit, login already selected the server,
    // while there is no local vault to select yet.
    context.vaults.clear();
    context.current_vault_id = None;
    for first_sync in [false, true] {
        let mut state = vault::State::new(list_states::empty_page(), None);
        state.set_initial_sync_target(Some(storage.clone()), first_sync);
        state.update(
            vault::Message::VaultsLoaded {
                request: state.context_request_id(),
                result: Ok(context.clone()),
            },
            &session,
        );
        assert_eq!(state.selected_storage_id(), Some(storage.as_str()));
        assert!(state.visible().is_empty());
        let completion = refresh(&mut state, &session, &storage);
        state.update(completion, &session);
        if first_sync {
            assert_eq!(state.visible().len(), 2);
            assert!(state.can_create());
            assert!(!state.awaiting_first_sync());
            assert_eq!(state.empty_state(), None);
        } else {
            assert!(
                state.visible().is_empty(),
                "ordinary reads cannot change the selected vault"
            );
        }
    }
}

#[test]
fn repeated_commit_notices_coalesce_and_a_reopened_screen_rejects_old_reads() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let storage = local::current_storage_id(&session.facade()).unwrap();
    let mut state = vault::State::new(page.clone(), None);
    load_vault_context(&mut state, &session);
    let message = refresh(&mut state, &session, &storage);
    for _ in 0..100 {
        let vault::Outcome::Task(task) = state.update(
            vault::Message::SyncCommitted {
                run: state.sync_run_id(),
                storage_id: storage.clone(),
            },
            &session,
        ) else {
            panic!("coalesced task");
        };
        assert!(
            cosmic::iced::runtime::task::into_stream(task).is_none(),
            "no additional reader while one is pending"
        );
    }
    let follow_up = state.update(message.clone(), &session);
    let _ = sync_navigation::completion(follow_up, |m| {
        matches!(m, vault::Message::ProgressWorkspaceLoaded { .. })
    });
    let mut reopened = vault::State::new(list_states::empty_page(), None);
    load_vault_context(&mut reopened, &session);
    reopened.update(message, &session);
    assert!(reopened.visible().is_empty());
}

#[test]
fn a_committed_read_cannot_overwrite_a_newer_search_or_navigation() {
    let (_dir, session) = vault_with_items();
    let storage = local::current_storage_id(&session.facade()).unwrap();
    let mut state = vault::State::new(list_states::empty_page(), None);
    load_vault_context(&mut state, &session);
    let message = refresh(&mut state, &session, &storage);
    state.update(vault::Message::QueryInput("missing".into()), &session);
    state.update(message, &session);
    assert!(state.visible().is_empty());
    assert_eq!(state.empty_state(), Some(vault::ListEmptyState::Loading));
    let mut other = local::vault_context(&session.facade()).unwrap();
    other.current_storage_id = Some("other-server".into());
    state.update(
        vault::Message::VaultsLoaded {
            request: state.context_request_id(),
            result: Ok(other),
        },
        &session,
    );
    assert!(matches!(
        state.update(
            vault::Message::SyncCommitted {
                run: state.sync_run_id(),
                storage_id: storage,
            },
            &session
        ),
        vault::Outcome::None
    ));
    assert_eq!(state.selected_storage_id(), Some("other-server"));
}

#[test]
fn failed_first_sync_stays_explicit_and_retry_starts_a_new_operation() {
    let (_dir, session) = vault_with_items();
    let mut state = vault::State::new(list_states::empty_page(), None);
    state.set_initial_sync_target(None, true);
    session
        .auto_sync()
        .unlocked(std::time::Instant::now(), true);
    let started = state.update(vault::Message::SyncNow, &session);
    let run = state.sync_run_id();
    let message =
        sync_navigation::completion(started, |m| matches!(m, vault::Message::AutoSynced { .. }));
    assert!(matches!(
        &message,
        vault::Message::AutoSynced { result: Err(_), .. }
    ));
    state.update(message, &session);
    assert_eq!(state.empty_state(), Some(vault::ListEmptyState::FirstSync));
    let _ = state.view();
    assert!(matches!(
        state.update(vault::Message::SyncNow, &session),
        vault::Outcome::Task(_)
    ));
    assert_ne!(state.sync_run_id(), run);
}

#[test]
fn committed_refresh_preserves_loaded_pages_and_supersedes_older_catalog_reads() {
    let (_dir, session) = vault_with_items();
    let facade = session.facade();
    for i in 0..205 {
        facade
            .debug_create_kv_item(format!("many/{i:04}"), "key".into(), "value".into())
            .unwrap();
    }
    let storage = local::current_storage_id(&facade).unwrap();
    let mut state = vault::State::new(local::items(&facade, None, None).unwrap(), None);
    load_vault_context(&mut state, &session);
    let old_catalog_request = state.context_request_id();
    let more = state.update(vault::Message::LoadMore, &session);
    let message =
        sync_navigation::completion(more, |m| matches!(m, vault::Message::MoreLoaded { .. }));
    state.update(message, &session);
    assert_eq!(state.visible().len(), 207);
    let selected = state.visible().last().unwrap().id.clone();
    state.update(vault::Message::Select(selected.clone()), &session);
    let message = refresh(&mut state, &session, &storage);
    state.update(message, &session);
    assert_eq!(state.visible().len(), 207);
    assert_eq!(state.selected_item_id(), Some(selected.as_str()));
    state.update(
        vault::Message::VaultsLoaded {
            request: old_catalog_request,
            result: Ok(local::VaultContext {
                storages: vec![],
                current_storage_id: None,
                vaults: vec![],
                current_vault_id: None,
            }),
        },
        &session,
    );
    assert_eq!(state.selected_storage_id(), Some(storage.as_str()));
}
