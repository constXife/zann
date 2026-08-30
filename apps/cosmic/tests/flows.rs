//! The screens are plain state machines, so the flows can be driven without a
//! compositor. Anything that needs a real server (probing, logging in) stops at
//! the message boundary: the response is fed in as a message.

use zann_cosmic::backend::local;
use zann_cosmic::backend::remote::{LoginOutcome, Method, Remote, ServerProbe};
use zann_cosmic::screens::detail::Detail;
use zann_cosmic::screens::{connect, master, vault};
use zann_cosmic::session::Session;
use zann_ffi::{ItemSummary, ItemUpdate, VaultSummaryFfi};
use zann_ui_core::ItemCounts;

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
    local::initialize_master_password(&facade, "demo-password".to_string()).expect("initialize");
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
fn reload_keeps_the_explicit_database_instead_of_reresolving_the_environment() {
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
        let (mut session, _) = Session::open_at(explicit_path.clone())?;
        local::initialize_master_password(&session.facade(), "explicit-password".to_string())?;
        session.reload()?;
        let status = session
            .facade()
            .app_status()
            .map_err(|err| err.to_string())?;
        if !status.initialized {
            return Err("reload opened a different database".to_string());
        }
        Ok::<(), String>(())
    })();

    result.expect("reload explicit session");
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
fn vault_context_exposes_the_active_personal_vault() {
    let (_dir, session) = vault_with_items();
    let facade = session.facade();
    let context = local::vault_context(&facade).expect("vault context");

    assert_eq!(context.vaults.len(), 1);
    assert_eq!(context.vaults[0].kind, "personal");
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
    local::initialize_master_password(&facade, "demo-password".to_string()).expect("initialize");
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
    let params = Detail::parse(zann_ffi::ItemDetail {
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
        master::Message::Opened(Ok((page, Some("offline".to_string())))),
        &session,
    );
    match opened {
        master::Outcome::Opened { page, sync_error } => {
            assert_eq!(page.total, 2);
            assert_eq!(sync_error.as_deref(), Some("offline"));
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
fn vault_selector_only_reserves_sidebar_space_for_multiple_vaults() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None, None).expect("items");
    let mut state = vault::State::new(page, None);
    assert!(state.vault_selector().is_none());

    state.update(
        vault::Message::VaultsLoaded(Ok(local::VaultContext {
            current_vault_id: Some("personal".to_string()),
            vaults: vec![
                VaultSummaryFfi {
                    id: "personal".to_string(),
                    name: "Personal".to_string(),
                    kind: "personal".to_string(),
                    is_default: false,
                    item_count: 399,
                },
                VaultSummaryFfi {
                    id: "shared".to_string(),
                    name: "infra".to_string(),
                    kind: "shared".to_string(),
                    is_default: false,
                    item_count: 15,
                },
            ],
        })),
        &session,
    );

    assert!(state.vault_selector().is_some());
}

#[test]
fn the_splitter_stays_between_the_tauri_panel_limits() {
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

    // Overshoot clamps at Tauri's list maximum without banking the excess.
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
fn connect_walks_the_stages_a_server_dictates() {
    let mut state = connect::State::default();
    assert_eq!(state.stage(), &connect::Stage::Server);

    // One method: skip the picker.
    state.update(connect::Message::Probed(Ok(ServerProbe {
        methods: vec![Method::Password],
        register: true,
        server_name: Some("Zann Mock".to_string()),
        fingerprint_changed: None,
    })));
    assert_eq!(state.stage(), &connect::Stage::Password);

    // Two methods: ask.
    let mut state = connect::State::default();
    state.update(connect::Message::Probed(Ok(ServerProbe {
        methods: vec![Method::Password, Method::Oidc],
        register: false,
        server_name: None,
        fingerprint_changed: None,
    })));
    assert_eq!(state.stage(), &connect::Stage::Method);

    // A changed server key never logs in on its own.
    state.update(connect::Message::Outcome(Ok(
        LoginOutcome::FingerprintChanged {
            login_id: "login".to_string(),
            old: "sha256:old".to_string(),
            new: "sha256:new".to_string(),
        },
    )));
    assert_eq!(
        state.stage(),
        &connect::Stage::Fingerprint {
            old: "sha256:old".to_string(),
            new: "sha256:new".to_string(),
        }
    );

    let outcome = state.update(connect::Message::Outcome(Ok(LoginOutcome::Success {
        storage_id: "storage".to_string(),
        has_personal_keys: false,
    })));
    assert!(matches!(
        outcome,
        connect::Outcome::Connected { storage_id, has_personal_keys }
            if storage_id == "storage" && !has_personal_keys
    ));
}

#[test]
fn cancelling_connect_returns_to_the_shell() {
    let mut state = connect::State::default();
    assert!(matches!(
        state.update(connect::Message::Cancel),
        connect::Outcome::Cancelled
    ));
}
