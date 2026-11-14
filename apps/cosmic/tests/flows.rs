//! The screens are plain state machines, so the flows can be driven without a
//! compositor. Anything that needs a real server (probing, logging in) stops at
//! the message boundary: the response is fed in as a message.

use zann_client::app::local::{ItemCreate, ItemSummary, ItemUpdate, VaultSummary};
use zann_cosmic::backend::local;
use zann_cosmic::backend::remote::Remote;
use zann_cosmic::screens::detail::Detail;
use zann_cosmic::screens::{connect, master, settings, vault};
use zann_cosmic::session::Session;
use zann_ui_core::{DevicePreferences, ItemCounts};

static DB_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct DbUrlOverride(Option<std::ffi::OsString>);

impl DbUrlOverride {
    fn set(value: &str) -> Self {
        let previous = std::env::var_os("ZANN_DB_URL");
        std::env::set_var("ZANN_DB_URL", value);
        Self(previous)
    }
}

impl Drop for DbUrlOverride {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => std::env::set_var("ZANN_DB_URL", value),
            None => std::env::remove_var("ZANN_DB_URL"),
        }
    }
}

fn seed_session(session: &Session, password: &str) -> Result<(), String> {
    let fixture = zann_client_sqlite::local_vault::open_vault_at_path(
        session.database_location().path(),
        zann_client_sqlite::local_vault::LocalVaultPorts::system_default(),
    )
    .map_err(|err| err.to_string())?;
    fixture
        .seed_offline_fixture(password.to_string())
        .map_err(|err| err.to_string())?;
    drop(fixture);
    local::unlock(&session.facade(), password.to_string())
}

const LOGIN_PAYLOAD: &str = r#"{
  "v": 1,
  "typeId": "login",
  "fields": {
    "username": { "kind": "text", "value": "demo@example.com" },
    "password": { "kind": "password", "value": "hunter2" },
    "otp": { "kind": "otp", "value": "JBSWY3DPEHPK3PXP" }
  }
}"#;

/// A vault in a temporary directory with one kv item and one login.
fn vault_with_items() -> (tempfile::TempDir, Session) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("local.sqlite");
    let (session, status) = Session::open_at(db_path).expect("open");
    assert!(!status.initialized);

    let facade = session.facade();
    seed_session(&session, "demo-password").expect("initialize");
    facade
        .debug_create_kv_item(
            "work/aws".to_string(),
            "access_key".to_string(),
            "AKIA".to_string(),
        )
        .expect("kv item");
    let id = facade
        .debug_create_kv_item(
            "personal/mail".to_string(),
            "placeholder".to_string(),
            String::new(),
        )
        .expect("placeholder");
    facade
        .item_update(
            id,
            ItemUpdate {
                title: "mail".to_string(),
                path: "personal/mail".to_string(),
                type_id: "login".to_string(),
                payload_json: LOGIN_PAYLOAD.to_string(),
            },
        )
        .expect("login item");

    (dir, session)
}

#[test]
fn session_keeps_the_explicit_database_instead_of_reresolving_the_environment() {
    let _env = DB_ENV_LOCK.lock().expect("environment lock");
    let explicit = tempfile::tempdir().expect("explicit tempdir");
    let fallback = tempfile::tempdir().expect("fallback tempdir");
    let explicit_path = explicit
        .path()
        .join("literal # ? %")
        .join("local # ? %.sqlite");
    let fallback_path = fallback.path().join("wrong.sqlite");
    let fallback_value = fallback_path.to_str().expect("UTF-8 test path");
    let _override = DbUrlOverride::set(fallback_value);

    let result = (|| {
        let (session, _) = Session::open_at(explicit_path.clone())?;
        seed_session(&session, "explicit-password")?;
        let status = session
            .facade()
            .app_status()
            .map_err(|err| err.to_string())?;
        if !status.initialized {
            return Err("the session opened a different database".to_string());
        }
        Ok::<(), String>(())
    })();

    result.expect("explicit session");
    assert!(
        explicit_path.exists(),
        "literal URI delimiter characters must stay in the filesystem path"
    );
    assert!(
        !fallback_path.exists(),
        "reload must not open the environment fallback"
    );
}

#[test]
fn remote_reuses_the_active_session_location_without_reresolving_environment() {
    let _env = DB_ENV_LOCK.lock().expect("environment lock");
    let explicit = tempfile::tempdir().expect("explicit tempdir");
    let fallback = tempfile::tempdir().expect("fallback tempdir");
    let explicit_path = explicit.path().join("local # ? %.sqlite");
    let fallback_path = fallback.path().join("wrong.sqlite");
    let fallback_value = fallback_path.to_str().expect("UTF-8 test path");
    let _override = DbUrlOverride::set(fallback_value);

    let (_session, _) = Session::open_at(explicit_path.clone()).expect("open explicit session");
    let _remote = Remote::new().expect("remote shares the active session root");

    assert!(explicit_path.exists());
    assert!(
        !fallback_path.exists(),
        "Remote::new must not resolve ZANN_DB_URL a second time"
    );
}

#[test]
fn remote_fails_closed_outside_the_session_composition_thread() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_session, _) = Session::open_at(dir.path().join("local.sqlite")).expect("open session");

    let error = std::thread::spawn(|| match Remote::new() {
        Ok(_) => "remote unexpectedly opened without its session location".to_string(),
        Err(error) => error,
    })
    .join()
    .expect("remote probe thread");

    assert!(
        error.contains("until the local database session is open"),
        "unexpected error: {error}"
    );
}

#[test]
fn detail_masks_secrets_and_reads_totp() {
    let (_dir, session) = vault_with_items();
    let facade = session.facade();
    let page = local::items(&facade, None, None).expect("items");
    let login = page
        .items
        .iter()
        .find(|item| item.type_id == "login")
        .expect("login in the page");

    let mut detail = Detail::parse(local::item_get(&facade, login.id.clone()).expect("item_get"))
        .expect("parse");

    let password = detail
        .fields
        .iter()
        .find(|field| field.key == "password")
        .expect("password field");
    assert!(password.masked, "a password field is masked by default");
    assert_ne!(password.display_value(false), "hunter2");
    assert_eq!(password.display_value(true), "hunter2");

    let otp = detail
        .fields
        .iter()
        .find(|field| field.key == "otp")
        .expect("otp field");
    assert!(otp.masked);
    assert_eq!(
        otp.totp.as_ref().map(|params| params.secret.as_str()),
        Some("JBSWY3DPEHPK3PXP")
    );
    assert!(detail.has_totp());

    // Fields come out in reading order, not hash order.
    let keys: Vec<&str> = detail.fields.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(keys, ["username", "password", "otp"]);

    detail.update(zann_cosmic::screens::detail::Message::Copy {
        index: 1,
        value: "hunter2".to_string(),
    });
    assert_eq!(detail.copied_field(), Some(1));
    detail.clear_copy_feedback();
    assert_eq!(detail.copied_field(), None);
}

#[test]
fn facade_creates_and_edits_items_for_cosmic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (session, status) =
        Session::open_at(dir.path().join("local.sqlite")).expect("open session");
    assert!(!status.initialized);
    let facade = session.facade();
    seed_session(&session, "demo-password").expect("initialize");

    let created = local::item_create(
        &facade,
        ItemCreate {
            title: "service".to_string(),
            path: "work/service".to_string(),
            type_id: "api".to_string(),
            payload_json:
                r#"{"v":1,"typeId":"wrong","fields":{"token":{"kind":"password","value":"first"}}}"#
                    .to_string(),
        },
    )
    .expect("create item");
    assert_eq!(created.title, "service");
    assert_eq!(created.type_id, "api");
    let created_payload: serde_json::Value =
        serde_json::from_str(&created.payload_json).expect("created payload");
    assert_eq!(created_payload["typeId"], "api");
    assert_eq!(created_payload["fields"]["token"]["value"], "first");

    let updated = local::item_update(
        &facade,
        created.id,
        ItemUpdate {
            title: "renamed".to_string(),
            path: "work/renamed".to_string(),
            type_id: "login".to_string(),
            payload_json: r#"{"v":1,"typeId":"stale","fields":{"password":{"kind":"password","value":"second"}}}"#
                .to_string(),
        },
    )
    .expect("update item");
    assert_eq!(updated.title, "renamed");
    assert_eq!(updated.path, "work/renamed");
    assert_eq!(updated.type_id, "login");
    let updated_payload: serde_json::Value =
        serde_json::from_str(&updated.payload_json).expect("updated payload");
    assert_eq!(updated_payload["typeId"], "login");
    assert_eq!(updated_payload["fields"]["password"]["value"], "second");

    let history = local::item_history(&facade, updated.id.clone()).expect("list history");
    assert!(!history.is_empty());
    assert_eq!(history[0].version, 1);
    let previous = local::item_history_get(&facade, updated.id.clone(), history[0].version)
        .expect("get history version");
    let previous_payload: serde_json::Value =
        serde_json::from_str(&previous.payload_json).expect("history payload");
    assert_eq!(previous_payload["fields"]["token"]["value"], "first");

    let restored = local::item_history_restore(&facade, updated.id, history[0].version)
        .expect("restore history version");
    let restored_payload: serde_json::Value =
        serde_json::from_str(&restored.payload_json).expect("restored payload");
    assert_eq!(restored_payload["fields"]["token"]["value"], "first");
}

#[test]
fn vault_context_exposes_the_active_personal_vault() {
    let (_dir, session) = vault_with_items();
    let facade = session.facade();
    let context = local::vault_context(&facade).expect("vault context");

    assert_eq!(context.vaults.len(), 1);
    assert_eq!(context.vaults[0].kind, zann_core::VaultKind::Personal);
    assert_eq!(
        context.current_vault_id.as_deref(),
        Some(context.vaults[0].id.as_str())
    );
    assert_eq!(context.vaults[0].item_count, 2);

    let page =
        local::switch_vault(&facade, context.vaults[0].id.clone()).expect("switch current vault");
    assert_eq!(page.total, 2);
}

#[test]
fn search_finds_an_item_beyond_the_first_loaded_page() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (session, status) =
        Session::open_at(dir.path().join("local.sqlite")).expect("open session");
    assert!(!status.initialized);

    let facade = session.facade();
    seed_session(&session, "demo-password").expect("initialize");
    facade
        .debug_create_kv_item(
            "Hetzner".to_string(),
            "username".to_string(),
            "demo".to_string(),
        )
        .expect("target item");
    for index in 0..local::PAGE_LIMIT {
        facade
            .debug_create_kv_item(
                format!("newer/item-{index:03}"),
                "key".to_string(),
                index.to_string(),
            )
            .expect("filler item");
    }

    let first_page = local::items(&facade, None, None).expect("first page");
    assert_eq!(first_page.items.len(), local::PAGE_LIMIT as usize);
    assert_eq!(first_page.total, u64::from(local::PAGE_LIMIT) + 1);
    assert!(
        first_page.items.iter().all(|item| item.title != "Hetzner"),
        "the regression needs Hetzner to be outside the first loaded page"
    );

    let second_page = local::items(&facade, first_page.next_cursor.clone(), None)
        .expect("second page without a skipped lookahead row");
    assert!(
        second_page.items.iter().any(|item| item.title == "Hetzner"),
        "cursor pagination must not skip the first row of the next page"
    );

    let search =
        local::items(&facade, None, Some("Hetzner".to_string())).expect("search whole vault");
    assert_eq!(search.total, 1);
    assert_eq!(search.items.len(), 1);
    assert_eq!(search.items[0].title, "Hetzner");
    assert!(search.next_cursor.is_none());
}

#[test]
fn infinite_scroll_prefetches_and_caps_the_summary_cache() {
    let (_dir, session) = vault_with_items();
    let page_size = local::PAGE_LIMIT as usize;
    let make_page = |page: usize| local::ItemsPage {
        items: (0..page_size)
            .map(|index| ItemSummary {
                id: format!("{page}-{index}"),
                title: format!("item-{page}-{index}"),
                path: format!("items/{page}/{index}"),
                type_id: "login".to_string(),
                subtitle: None,
                deleted: false,
            })
            .collect(),
        next_cursor: Some(format!("cursor-{page}")),
        total: 10_000,
        counts: ItemCounts::default(),
    };

    let mut state = vault::State::new(make_page(0), None);
    let prefetch = state.update(
        vault::Message::ListScrolled {
            remaining: 100.0,
            viewport_height: 600.0,
        },
        &session,
    );
    assert!(matches!(prefetch, vault::Outcome::Task(_)));

    // Simulate completed pages. The list keeps at most five backend pages,
    // even if more scroll notifications arrive afterwards.
    for page in 1..=6 {
        state.update(
            vault::Message::MoreLoaded {
                generation: 0,
                result: Ok(make_page(page)),
            },
            &session,
        );
    }
    assert_eq!(state.visible().len(), page_size * 5);

    let capped = state.update(
        vault::Message::ListScrolled {
            remaining: 0.0,
            viewport_height: 600.0,
        },
        &session,
    );
    assert!(matches!(capped, vault::Outcome::None));
}

#[test]
fn detail_reads_otpauth_uri_parameters() {
    let params = Detail::parse(zann_client::app::local::ItemDetail {
        id: "id".to_string(),
        title: "t".to_string(),
        path: "p".to_string(),
        type_id: "login".to_string(),
        payload_json: r#"{"v":1,"typeId":"login","fields":{"otp":{"kind":"otp",
            "value":"otpauth://totp/zann:demo?secret=NBSWY3DP&algorithm=SHA256&digits=8&period=60"}}}"#
            .to_string(),
    })
    .expect("parse")
    .fields
    .remove(0)
    .totp
    .expect("totp params");

    assert_eq!(params.secret, "NBSWY3DP");
    assert_eq!(params.algorithm.as_deref(), Some("SHA256"));
    assert_eq!(params.digits, Some(8));
    assert_eq!(params.period, Some(60));
}

#[test]
fn master_hands_the_open_vault_to_the_shell() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).expect("items");
    let mut state = master::State::new(master::Mode::Unlock, None);

    let failed = state.update(
        master::Message::Opened(Err("invalid password".to_string())),
        &session,
    );
    assert!(matches!(failed, master::Outcome::None));

    let opened = state.update(
        master::Message::Opened(Ok((page, Some(Err("offline".to_string()))))),
        &session,
    );
    match opened {
        master::Outcome::Opened { page, synced } => {
            assert_eq!(page.total, 2);
            assert_eq!(synced, Some(Err("offline".to_string())));
        }
        _ => panic!("a successful unlock hands the page over"),
    }
}

#[test]
fn vault_filters_the_list_and_forwards_copies() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).expect("items");
    let mut state = vault::State::new(page, None);

    assert_eq!(state.visible().len(), 2);

    state.update(vault::Message::QueryInput("mail".to_string()), &session);
    let visible = state.visible();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].title, "mail");

    state.update(vault::Message::ClearQuery, &session);
    assert_eq!(state.visible().len(), 2);

    // The clipboard belongs to the shell, so the detail column's copy travels up.
    let outcome = state.update(
        vault::Message::Detail(zann_cosmic::screens::detail::Message::Copy {
            index: 0,
            value: "s3cret".into(),
        }),
        &session,
    );
    assert!(matches!(
        outcome,
        vault::Outcome::Copy { value, .. } if value == "s3cret"
    ));
}

#[test]
fn the_nav_header_offers_a_vault_picker_only_for_multiple_vaults() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).expect("items");
    let mut state = vault::State::new(page, None);
    assert!(!state.offers_vault_picker());

    state.update(
        vault::Message::VaultsLoaded(Ok(local::VaultContext {
            current_vault_id: Some("personal".to_string()),
            vaults: vec![
                VaultSummary {
                    id: "personal".to_string(),
                    name: "Personal".to_string(),
                    kind: zann_core::VaultKind::Personal,
                    is_default: false,
                    item_count: 399,
                },
                VaultSummary {
                    id: "shared".to_string(),
                    name: "infra".to_string(),
                    kind: zann_core::VaultKind::Shared,
                    is_default: false,
                    item_count: 15,
                },
            ],
        })),
        &session,
    );

    assert!(state.offers_vault_picker());
}

#[test]
fn the_splitter_stays_within_native_panel_limits() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).expect("items");
    let mut state = vault::State::new(page, None);
    state.set_content_width(1200.0);
    assert_eq!(state.list_width(), 400.0);

    // The first move fixes the pointer origin; later moves resize from it.
    state.update(vault::Message::ResizeStart, &session);
    state.update(vault::Message::ResizeMove(700.0), &session);
    assert_eq!(state.list_width(), 400.0);
    state.update(vault::Message::ResizeMove(800.0), &session);
    assert_eq!(state.list_width(), 500.0);

    // Overshoot clamps at the native list maximum without banking the excess.
    state.update(vault::Message::ResizeMove(1400.0), &session);
    assert_eq!(state.list_width(), 560.0);
    state.update(vault::Message::ResizeMove(760.0), &session);
    assert_eq!(state.list_width(), 460.0);

    // A narrow window temporarily clamps the list, then restores the user's
    // preferred split when room returns.
    state.set_content_width(800.0);
    assert_eq!(state.list_width(), 320.0);
    state.set_content_width(1200.0);
    assert_eq!(state.list_width(), 460.0);

    state.update(vault::Message::ResizeEnd, &session);
    state.update(vault::Message::ResizeMove(200.0), &session);
    assert_eq!(state.list_width(), 460.0);
}

#[test]
fn detail_and_copy_diagnostics_redact_payloads() {
    let sentinel = "sentinel-private-payload";
    let detail = Detail::parse(zann_client::app::local::ItemDetail {
        id: "id".into(), title: "title".into(), path: "path".into(), type_id: "login".into(),
        payload_json: format!(r#"{{"v":1,"typeId":"login","fields":{{"password":{{"kind":"password","value":"{sentinel}"}}}}}}"#),
    }).expect("parse");
    let message = zann_cosmic::screens::detail::Message::Copy {
        index: 0,
        value: sentinel.into(),
    };
    assert!(!format!("{detail:?} {:?} {message:?}", detail.fields).contains(sentinel));
}

#[test]
fn closed_history_requests_cannot_populate_a_new_history_view() {
    use zann_cosmic::screens::history;
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let first = local::item_get(&session.facade(), page.items[0].id.clone()).unwrap();
    let mut vault = vault::State::new(page, None);
    vault.update(
        vault::Message::Loaded(Ok(Detail::parse(first).unwrap())),
        &session,
    );
    vault.update(vault::Message::OpenHistory, &session);
    let old_request = vault.editing_request_id();
    vault.update(vault::Message::History(history::Message::Close), &session);
    vault.update(vault::Message::OpenHistory, &session);
    // A previous open must not be routed to the new history view.
    assert!(matches!(
        vault.update(
            vault::Message::HistoryResponse(
                old_request,
                history::Message::EntriesLoaded(Ok(vec![]))
            ),
            &session
        ),
        vault::Outcome::None
    ));
    assert!(vault.history().unwrap().is_loading());
    // The current request reaches history; its failure is visible but does not
    // replace the selected item or reopen a closed editor.
    vault.update(
        vault::Message::HistoryResponse(
            vault.editing_request_id(),
            history::Message::EntriesLoaded(Err("request failed".into())),
        ),
        &session,
    );
    assert!(!vault.history().unwrap().is_loading());
}

#[test]
fn saved_item_from_a_destroyed_screen_cannot_replace_the_new_screen_detail() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let detail =
        Detail::parse(local::item_get(&session.facade(), page.items[0].id.clone()).unwrap())
            .unwrap();
    let mut old = vault::State::new(page.clone(), None);
    old.update(vault::Message::OpenCreate, &session);
    let old_request = old.editing_request_id();
    let mut current = vault::State::new(page, None);
    current.update(vault::Message::OpenCreate, &session);
    let current_request = current.editing_request_id();
    assert_ne!(old_request, current_request);
    current.update(
        vault::Message::Saved(old_request, Ok(detail.clone())),
        &session,
    );
    assert!(current.detail().is_none());
    current.update(vault::Message::Saved(current_request, Ok(detail)), &session);
    assert!(current.detail().is_some());
}

#[test]
fn a_save_schedules_a_push_and_a_lock_drops_it() {
    use std::time::Instant;
    use zann_client::app::local::AUTO_SYNC_DEBOUNCE;

    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let detail =
        Detail::parse(local::item_get(&session.facade(), page.items[0].id.clone()).unwrap())
            .unwrap();
    // Opening ran a sync, so the next one waits the full interval.
    session.auto_sync().unlocked(Instant::now(), true);
    let mut vault = vault::State::new(page, None);
    vault.update(vault::Message::OpenCreate, &session);
    let request = vault.editing_request_id();
    let before = Instant::now();
    vault.update(vault::Message::Saved(request, Ok(detail)), &session);

    let due = session.auto_sync().next_due().expect("the save is pushed");
    assert!(due <= Instant::now() + AUTO_SYNC_DEBOUNCE);
    assert!(due >= before);

    session.lock();
    assert_eq!(session.auto_sync().next_due(), None);
}

#[test]
fn a_sync_from_before_a_lock_never_reaches_the_next_vault() {
    use std::time::Instant;

    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let empty = local::ItemsPage {
        items: Vec::new(),
        next_cursor: None,
        total: 0,
        counts: ItemCounts::default(),
    };
    let now = Instant::now();
    session.auto_sync().unlocked(now, false);
    let stale = session.auto_sync().take_due(now).expect("due on unlock");
    session.lock();

    session.auto_sync().unlocked(now, false);
    let mut vault = vault::State::new(page, None);
    let ignored = vault.update(
        vault::Message::AutoSynced {
            ticket: stale,
            storage_id: local::current_storage_id(&session.facade()).expect("selected storage"),
            list_generation: 0,
            result: Ok(Some(empty.clone())),
        },
        &session,
    );
    assert!(matches!(ignored, vault::Outcome::None));
    assert_eq!(vault.visible().len(), 2);

    // This unlock's own sync lands, and the schedule waits for the next one.
    let current = session.auto_sync().take_due(now).expect("due on unlock");
    vault.update(
        vault::Message::AutoSynced {
            ticket: current,
            storage_id: local::current_storage_id(&session.facade()).expect("selected storage"),
            list_generation: 0,
            result: Ok(Some(empty)),
        },
        &session,
    );
    assert!(vault.visible().is_empty());
    assert!(session.auto_sync().next_due().is_some());
}

#[test]
fn a_sync_started_under_an_older_search_keeps_the_newer_list() {
    use std::time::Instant;

    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let empty = local::ItemsPage {
        items: Vec::new(),
        next_cursor: None,
        total: 0,
        counts: ItemCounts::default(),
    };
    let now = Instant::now();
    session.auto_sync().unlocked(now, false);
    let ticket = session.auto_sync().take_due(now).expect("due on unlock");
    let mut vault = vault::State::new(page, None);
    vault.update(vault::Message::QueryInput("mail".to_string()), &session);

    vault.update(
        vault::Message::AutoSynced {
            ticket,
            storage_id: local::current_storage_id(&session.facade()).expect("selected storage"),
            list_generation: 0,
            result: Ok(Some(empty)),
        },
        &session,
    );
    assert!(!vault.visible().is_empty());
}

fn settings_for(dir: &tempfile::TempDir) -> settings::State {
    settings::State::new(
        DevicePreferences::default(),
        false,
        dir.path().to_path_buf(),
    )
}

#[test]
fn a_changed_server_identity_offers_to_forget_it_after_counting_local_changes() {
    let (dir, session) = vault_with_items();
    let mut state = settings_for(&dir);
    const STORAGE: &str = "remote-storage";

    assert!(matches!(
        state.update(settings::Message::SyncNow(STORAGE.to_string()), &session),
        settings::Outcome::Sync(storage) if storage == STORAGE
    ));
    let refused = state.update(
        settings::Message::Synced(
            STORAGE.to_string(),
            Err(local::SyncFailure::IdentityChanged),
        ),
        &session,
    );
    assert!(
        matches!(refused, settings::Outcome::Task(_)),
        "the refusal counts what forgetting would leave behind"
    );
    assert_eq!(state.error(), None, "the account row carries the error");
    let stale = state.stale_server().expect("stale server");
    assert_eq!(stale.storage_id, STORAGE);
    assert_eq!(stale.pending_changes, None);

    // Nothing is forgotten before the user can see what stays behind.
    state.update(settings::Message::AskForget, &session);
    assert!(!state.stale_server().expect("stale server").confirming);
    state.update(
        settings::Message::PendingCounted("another-storage".to_string(), Ok(9)),
        &session,
    );
    assert_eq!(
        state.stale_server().expect("stale server").pending_changes,
        None
    );
    state.update(
        settings::Message::PendingCounted(STORAGE.to_string(), Ok(2)),
        &session,
    );
    assert_eq!(
        state.stale_server().expect("stale server").pending_changes,
        Some(2)
    );
    assert!(matches!(
        state.update(settings::Message::ConfirmForget, &session),
        settings::Outcome::None
    ));

    state.update(settings::Message::AskForget, &session);
    assert!(state.stale_server().expect("stale server").confirming);
    state.update(settings::Message::CancelForget, &session);
    assert!(!state.stale_server().expect("stale server").confirming);
    state.update(settings::Message::AskForget, &session);
    assert!(matches!(
        state.update(settings::Message::ConfirmForget, &session),
        settings::Outcome::Task(_)
    ));

    let forgotten = state.update(
        settings::Message::Forgotten(Ok(Some("https://zann.example".to_string()))),
        &session,
    );
    let settings::Outcome::Reconnect { server_url } = forgotten else {
        panic!("a forgotten server is connected to again");
    };
    assert!(state.stale_server().is_none());
    let connect = connect::State::with_server_url(server_url.expect("pinned address"));
    assert_eq!(connect.stage(), &connect::Stage::Server);
    assert_eq!(connect.server_url(), "https://zann.example");
}

#[test]
fn a_successful_sync_clears_the_changed_identity_and_other_failures_stay_plain() {
    let (dir, session) = vault_with_items();
    let mut state = settings_for(&dir);
    state.update(
        settings::Message::Synced(
            "remote-storage".to_string(),
            Err(local::SyncFailure::IdentityChanged),
        ),
        &session,
    );
    state.update(
        settings::Message::Synced("remote-storage".to_string(), Ok(())),
        &session,
    );
    assert!(state.stale_server().is_none());

    state.update(
        settings::Message::Synced(
            "remote-storage".to_string(),
            Err(local::SyncFailure::Other("offline".to_string())),
        ),
        &session,
    );
    assert!(state.stale_server().is_none());
    assert_eq!(state.error(), Some("offline"));

    // A failed count never leaves the account without a way to retry.
    state.update(
        settings::Message::Synced(
            "remote-storage".to_string(),
            Err(local::SyncFailure::IdentityChanged),
        ),
        &session,
    );
    state.update(
        settings::Message::PendingCounted(
            "remote-storage".to_string(),
            Err("database busy".to_string()),
        ),
        &session,
    );
    assert!(state.stale_server().is_none());
    assert_eq!(state.error(), Some("database busy"));
}

#[test]
fn a_scheduled_sync_refused_for_a_changed_identity_leads_to_the_settings_recovery() {
    use std::time::Instant;

    let (dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    const STORAGE: &str = "remote-storage";
    let now = Instant::now();
    session.auto_sync().unlocked(now, false);
    let mut vault = vault::State::new(page, None);

    // Nothing to review before a refusal.
    assert!(matches!(
        vault.update(vault::Message::ReviewStaleServer, &session),
        vault::Outcome::None
    ));

    let ticket = session.auto_sync().take_due(now).expect("due on unlock");
    vault.update(
        vault::Message::AutoSynced {
            ticket,
            storage_id: STORAGE.to_string(),
            list_generation: 0,
            result: Err(local::SyncFailure::IdentityChanged),
        },
        &session,
    );
    let vault::Outcome::StaleServer(storage_id, failure) =
        vault.update(vault::Message::ReviewStaleServer, &session)
    else {
        panic!("the refusal leads to the recovery");
    };
    assert_eq!(storage_id, STORAGE);
    assert_eq!(failure, local::SyncFailure::IdentityChanged);

    // Settings takes it as the refusal its own sync would have met.
    let mut state = settings_for(&dir);
    assert!(matches!(
        state.update(
            settings::Message::Synced(storage_id, Err(failure)),
            &session
        ),
        settings::Outcome::Task(_)
    ));
    assert_eq!(
        state.stale_server().expect("stale server").storage_id,
        STORAGE
    );

    // A plain failure or a sync that goes through withdraws the offer.
    for result in [
        Err(local::SyncFailure::Other("offline".to_string())),
        Ok(None),
    ] {
        let ticket = session.auto_sync().take_now().expect("idle schedule");
        vault.update(
            vault::Message::AutoSynced {
                ticket,
                storage_id: STORAGE.to_string(),
                list_generation: 0,
                result,
            },
            &session,
        );
        assert!(matches!(
            vault.update(vault::Message::ReviewStaleServer, &session),
            vault::Outcome::None
        ));
    }
}

#[test]
fn the_sync_indicator_shows_the_most_urgent_state_and_acts_on_it() {
    use std::time::Instant;
    use zann_client::app::local::{StorageLink, StorageSyncState};
    use zann_ui_core::SyncIndicator;

    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let now = Instant::now();
    session.auto_sync().unlocked(now, true);
    let mut vault = vault::State::new(page, None);
    assert!(
        vault.sync_indicator_state().is_none(),
        "nothing shows before the state is read"
    );

    let state = |link, pending_changes| StorageSyncState {
        link,
        server_url: Some("https://zann.example.test".to_string()),
        pending_changes,
        last_synced_at: Some("2026-11-13T07:15:34+00:00".to_string()),
    };
    vault.update(
        vault::Message::SyncStateLoaded(Ok(state(StorageLink::Connected, 3))),
        &session,
    );
    assert!(matches!(
        vault.sync_indicator_state(),
        Some(SyncIndicator::Pending {
            pending_changes: 3,
            ..
        })
    ));
    assert!(vault.sync_indicator().is_some());

    // Pressing it syncs now, and the indicator shows the sync running.
    assert!(matches!(
        vault.update(vault::Message::SyncIndicatorPressed, &session),
        vault::Outcome::Task(_)
    ));
    assert!(matches!(
        vault.sync_indicator_state(),
        Some(SyncIndicator::Syncing { .. })
    ));

    // A storage whose connection is gone leads to connecting it again.
    vault.update(
        vault::Message::SyncStateLoaded(Ok(state(StorageLink::Disconnected, 3))),
        &session,
    );
    let vault::Outcome::StaleServer(_, failure) =
        vault.update(vault::Message::SyncIndicatorPressed, &session)
    else {
        panic!("the indicator leads to the reconnect");
    };
    assert_eq!(
        failure,
        local::SyncFailure::Disconnected {
            server_url: Some("https://zann.example.test".to_string()),
            pending_changes: 3,
        }
    );
}

#[test]
fn the_sync_error_on_screen_can_be_copied() {
    use std::time::Instant;

    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    let now = Instant::now();
    session.auto_sync().unlocked(now, false);
    let mut vault = vault::State::new(page, None);
    assert!(matches!(
        vault.update(vault::Message::CopyError, &session),
        vault::Outcome::None
    ));

    let ticket = session.auto_sync().take_due(now).expect("due on unlock");
    vault.update(
        vault::Message::AutoSynced {
            ticket,
            storage_id: "remote-storage".to_string(),
            list_generation: 0,
            result: Err(local::SyncFailure::Other("sync db_error".to_string())),
        },
        &session,
    );
    let vault::Outcome::Copy { value, .. } = vault.update(vault::Message::CopyError, &session)
    else {
        panic!("the error goes to the clipboard");
    };
    assert!(value.contains("sync db_error"));
}

#[test]
fn a_storage_without_its_connection_leads_to_connecting_its_server_again() {
    use std::time::Instant;

    let (dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).unwrap();
    const STORAGE: &str = "remote-storage";
    let gone = local::SyncFailure::Disconnected {
        server_url: Some("https://zann.example.test".to_string()),
        pending_changes: 399,
    };
    assert!(
        gone.to_string().contains("399"),
        "the banner counts what waits"
    );

    let now = Instant::now();
    session.auto_sync().unlocked(now, false);
    let mut vault = vault::State::new(page, None);
    let ticket = session.auto_sync().take_due(now).expect("due on unlock");
    vault.update(
        vault::Message::AutoSynced {
            ticket,
            storage_id: STORAGE.to_string(),
            list_generation: 0,
            result: Err(gone.clone()),
        },
        &session,
    );
    let vault::Outcome::StaleServer(storage_id, failure) =
        vault.update(vault::Message::ReviewStaleServer, &session)
    else {
        panic!("the scheduled sync's refusal is not silent");
    };
    assert_eq!(failure, gone);

    let mut state = settings_for(&dir);
    // Nothing to reconnect before a refusal.
    assert!(matches!(
        state.update(settings::Message::Reconnect, &session),
        settings::Outcome::None
    ));
    state.update(
        settings::Message::Synced(storage_id, Err(failure)),
        &session,
    );
    assert_eq!(
        state.disconnected(),
        Some(&settings::Disconnected {
            storage_id: STORAGE.to_string(),
            server_url: Some("https://zann.example.test".to_string()),
            pending_changes: 399,
        })
    );
    assert_eq!(state.error(), None, "the account row carries the reason");
    assert!(state.stale_server().is_none(), "nothing to forget");

    let settings::Outcome::Reconnect { server_url } =
        state.update(settings::Message::Reconnect, &session)
    else {
        panic!("the row leads to connecting again");
    };
    assert_eq!(server_url.as_deref(), Some("https://zann.example.test"));
    assert!(state.disconnected().is_none());

    // A later sync of that storage replaces the row's state.
    state.update(
        settings::Message::Synced(STORAGE.to_string(), Err(gone)),
        &session,
    );
    state.update(
        settings::Message::Synced(STORAGE.to_string(), Ok(())),
        &session,
    );
    assert!(state.disconnected().is_none());
}

#[test]
fn backend_classifies_the_identity_change_and_forgets_idempotently() {
    let (_dir, session) = vault_with_items();
    let facade = session.facade();

    assert_eq!(
        local::SyncFailure::from(zann_client::app::local::LocalError::Sync {
            kind: "server_identity_changed".to_string(),
            message: "refused".to_string(),
        }),
        local::SyncFailure::IdentityChanged
    );
    assert!(matches!(
        local::sync(&facade, None),
        Err(local::SyncFailure::Other(_))
    ));

    let storage = local::current_storage_id(&facade).expect("selected storage");
    // A disconnected cache reports why pending changes cannot be sent.
    assert!(matches!(
        local::sync_and_reload(&facade, storage.clone(), None),
        Err(local::SyncFailure::Disconnected { .. })
    ));
    assert_eq!(
        local::pending_change_count(&facade, storage.clone()).expect("count"),
        2
    );
    assert_eq!(
        local::forget_server(&facade, storage).expect("no server to forget"),
        None
    );
}
