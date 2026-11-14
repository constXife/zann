use super::*;
use cosmic::iced::futures::StreamExt;
use cosmic::iced::runtime::{task::into_stream, Action};
use zann_client::app::local::{StorageLink, StorageSyncState};

pub(super) fn completion(
    outcome: vault::Outcome,
    wanted: fn(&vault::Message) -> bool,
) -> vault::Message {
    let vault::Outcome::Task(task) = outcome else {
        panic!("expected task")
    };
    let mut stream = into_stream(task).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            while let Some(action) = stream.next().await {
                if let Action::Output(message) = action {
                    if wanted(&message) {
                        return message;
                    }
                }
            }
            panic!("expected completion")
        })
}

fn status(
    state: &mut vault::State,
    session: &Session,
    storage: &str,
    result: Result<StorageSyncState, String>,
) {
    state.update(
        vault::Message::SyncStateLoaded {
            storage_id: storage.into(),
            request: state.sync_state_request_id(storage).unwrap(),
            result,
        },
        session,
    );
}

fn connected() -> StorageSyncState {
    StorageSyncState {
        link: StorageLink::Connected,
        server_url: Some("https://a.example.test".into()),
        pending_changes: 2,
        last_synced_at: None,
    }
}

fn context(state: &mut vault::State, session: &Session, value: local::VaultContext) {
    state.update(
        vault::Message::VaultsLoaded {
            request: state.context_request_id(),
            result: Ok(value),
        },
        session,
    );
}

fn switched(
    state: &mut vault::State,
    session: &Session,
    value: local::VaultContext,
    page: local::ItemsPage,
) {
    state.update(
        vault::Message::ContextSwitched {
            request: state.context_request_id(),
            change: local::ContextChange {
                storage_id: value.current_storage_id.clone(),
                vault_id: value.current_vault_id.clone(),
                result: Ok((value, Ok(page))),
            },
        },
        session,
    );
}

#[test]
fn details_refresh_is_local_and_escape_preserves_the_search() {
    let (_dir, session) = vault_with_items();
    let mut state = vault::State::new(local::items(&session.facade(), None, None).unwrap(), None);
    load_vault_context(&mut state, &session);
    session
        .auto_sync()
        .unlocked(std::time::Instant::now(), true);
    state.update(vault::Message::QueryInput("mail".into()), &session);
    let opened = state.update(vault::Message::SyncIndicatorPressed, &session);
    assert!(state.sync_details_open());
    let metadata = completion(opened, |m| {
        matches!(m, vault::Message::SyncStateLoaded { .. })
    });
    state.update(metadata, &session);
    assert!(!state.syncing());
    assert!(
        session.auto_sync().take_now().is_some(),
        "opening details did not admit network work"
    );
    let _ = state.nav_header();
    state.update(vault::Message::EscapeClearQuery, &session);
    assert!(!state.sync_details_open());
    assert!(
        matches!(
            state.update(vault::Message::QueryInput("mail".into()), &session),
            vault::Outcome::None
        ),
        "Escape kept the search query"
    );
}

#[test]
fn late_metadata_cannot_overwrite_a_newer_request_and_failure_keeps_cached_state() {
    let (_dir, session) = vault_with_items();
    let mut state = vault::State::new(local::items(&session.facade(), None, None).unwrap(), None);
    load_vault_context(&mut state, &session);
    let id = state.selected_storage_id().unwrap().to_owned();
    status(&mut state, &session, &id, Ok(connected()));
    let old = state.sync_state_request_id(&id).unwrap();
    state.update(vault::Message::SyncIndicatorPressed, &session);
    status(
        &mut state,
        &session,
        &id,
        Err("metadata unavailable".into()),
    );
    state.update(
        vault::Message::SyncStateLoaded {
            storage_id: id.clone(),
            request: old,
            result: Ok(connected()),
        },
        &session,
    );
    assert!(matches!(
        state.sync_indicator_state(),
        Some(zann_ui_core::SyncIndicator::Failed { .. })
    ));
    assert_eq!(state.sync_error().as_deref(), Some("metadata unavailable"));
    assert_eq!(state.visible().len(), 2);
    let retry = state.update(vault::Message::RefreshSyncDetails, &session);
    assert!(matches!(retry, vault::Outcome::Task(_)));
    status(&mut state, &session, &id, Ok(connected()));
    assert!(state.sync_error().is_none());
}

#[test]
fn navigation_during_sync_scopes_feedback_to_the_source_even_after_returning() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let mut a = local::vault_context(&session.facade()).unwrap();
    let a_id = a.current_storage_id.clone().unwrap();
    let mut storage_b = a.storages[0].clone();
    storage_b.id = "server-b".into();
    storage_b.server_url = Some("https://b.example.test".into());
    a.storages.push(storage_b);
    let mut b = a.clone();
    b.current_storage_id = Some("server-b".into());
    b.vaults[0].id = "vault-b".into();
    b.current_vault_id = Some("vault-b".into());
    let mut state = vault::State::new(page.clone(), None);
    context(&mut state, &session, a.clone());
    status(&mut state, &session, &a_id, Ok(connected()));
    session
        .auto_sync()
        .unlocked(std::time::Instant::now(), true);
    let pending = state.update(vault::Message::SyncNow, &session);
    assert!(state.syncing());
    state.update(vault::Message::SyncIndicatorPressed, &session);
    assert!(
        state.sync_details_open(),
        "details stay available during sync"
    );
    assert!(
        matches!(
            state.update(vault::Message::SelectStorage(1), &session),
            vault::Outcome::Task(_)
        ),
        "network never owns navigation admission"
    );
    switched(&mut state, &session, b, list_states::empty_page());
    assert!(!state.syncing());
    assert!(!state.sync_details_open());
    let mut finished = completion(pending, |m| matches!(m, vault::Message::AutoSynced { .. }));
    if let vault::Message::AutoSynced { result, .. } = &mut finished {
        *result = Err(local::SyncFailure::Other("offline A".into()));
    }
    state.update(finished, &session);
    assert_eq!(state.selected_storage_id(), Some("server-b"));
    assert!(state.sync_error().is_none());
    assert!(state.visible().is_empty());
    state.update(vault::Message::SelectStorage(0), &session);
    switched(&mut state, &session, a.clone(), page);
    assert!(state.sync_error().unwrap().contains("offline A"));
    state.update(
        vault::Message::SyncedWorkspaceLoaded {
            storage_id: a_id,
            list_generation: 0,
            result: Ok((a, list_states::empty_page())),
        },
        &session,
    );
    assert_eq!(
        state.visible().len(),
        2,
        "away and back still supersedes the old list revision"
    );
    assert!(
        matches!(
            state.update(vault::Message::CopyError, &session),
            vault::Outcome::None
        ),
        "sync errors never become workspace banners"
    );
}

#[test]
fn native_vault_switch_executes_the_existing_core_selection_port() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let mut value = local::vault_context(&session.facade()).unwrap();
    let selected = value.current_vault_id.clone().unwrap();
    // A stale native selection is corrected by the core, not by a shell rollback.
    value.current_vault_id = Some("stale-vault".into());
    let mut state = vault::State::new(page, None);
    context(&mut state, &session, value);
    let pending = state.update(vault::Message::SelectVault(0), &session);
    let request = state.context_request_id();
    let _metadata = state.load_vaults(&session);
    assert_eq!(
        state.context_request_id(),
        request,
        "a metadata refresh cannot orphan an admitted selection"
    );
    state.update(
        completion(pending, |m| {
            matches!(m, vault::Message::ContextSwitched { .. })
        }),
        &session,
    );
    assert_eq!(session.facade().current_vault_id(), Some(selected));
    assert_eq!(state.visible().len(), 2);
    assert!(
        matches!(
            state.update(vault::Message::QueryInput("mail".into()), &session),
            vault::Outcome::Task(_)
        ),
        "context completion releases navigation"
    );
}

#[test]
fn a_successful_sync_cannot_replace_the_vault_selected_during_network_work() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let mut original = local::vault_context(&session.facade()).unwrap();
    let storage = original.current_storage_id.clone().unwrap();
    let mut other = original.vaults[0].clone();
    other.id = "another-vault".into();
    original.vaults.push(other);
    let mut selected = original.clone();
    selected.current_vault_id = Some("another-vault".into());
    let mut state = vault::State::new(page.clone(), None);
    context(&mut state, &session, original.clone());
    status(&mut state, &session, &storage, Ok(connected()));
    session
        .auto_sync()
        .unlocked(std::time::Instant::now(), true);
    let pending = state.update(vault::Message::SyncNow, &session);
    assert!(matches!(
        state.update(vault::Message::SelectVault(1), &session),
        vault::Outcome::Task(_)
    ));
    switched(&mut state, &session, selected, list_states::empty_page());
    let mut finished = completion(pending, |m| matches!(m, vault::Message::AutoSynced { .. }));
    let vault::Message::AutoSynced { result, .. } = &mut finished else {
        unreachable!()
    };
    *result = Ok(sync_outcome(true));
    state.update(finished, &session);
    state.update(
        vault::Message::SyncedWorkspaceLoaded {
            storage_id: storage,
            list_generation: 0,
            result: Ok((original, page)),
        },
        &session,
    );
    assert!(state.visible().is_empty());
    assert!(!state.syncing());
    assert!(state.sync_error().is_none());
    assert!(
        matches!(
            state.update(vault::Message::SelectVault(1), &session),
            vault::Outcome::None
        ),
        "the newer vault remains selected"
    );
}
