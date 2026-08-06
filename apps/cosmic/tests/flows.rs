//! The screens are plain state machines, so the flows can be driven without a
//! compositor. Anything that needs a real server (probing, logging in) stops at
//! the message boundary: the response is fed in as a message.

use zann_cosmic::backend::local;
use zann_cosmic::backend::remote::{LoginOutcome, Method, ServerProbe};
use zann_cosmic::screens::detail::{self, Detail};
use zann_cosmic::screens::{connect, master, vault};
use zann_cosmic::session::Session;
use zann_ffi::ItemUpdate;

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
    let db_url = format!("sqlite://{}", dir.path().join("local.sqlite").display());
    let (session, status) = Session::open_at(db_url).expect("open");
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
fn detail_masks_secrets_and_reads_totp() {
    let (_dir, session) = vault_with_items();
    let facade = session.facade();
    let page = local::items(&facade, None).expect("items");
    let login = page
        .items
        .iter()
        .find(|item| item.type_id == "login")
        .expect("login in the page");

    let detail = Detail::parse(local::item_get(&facade, login.id.clone()).expect("item_get"))
        .expect("parse");

    let password = detail
        .fields
        .iter()
        .find(|field| field.key == "password")
        .expect("password field");
    assert!(password.masked, "a password field is masked by default");

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
    let page = local::items(&session.facade(), None).expect("items");
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
    let page = local::items(&session.facade(), None).expect("items");
    let mut state = vault::State::new(page, None);

    assert_eq!(state.visible().len(), 2);

    state.update(vault::Message::QueryInput("mail".to_string()), &session);
    let visible = state.visible();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].title, "mail");

    state.update(vault::Message::ClearQuery, &session);
    assert_eq!(state.visible().len(), 2);

    // The clipboard belongs to the shell, so the detail's copy travels up.
    let outcome = state.update(
        vault::Message::Detail(zann_cosmic::screens::detail::Message::Copy("s3cret".into())),
        &session,
    );
    assert!(matches!(outcome, vault::Outcome::Copy(value) if value == "s3cret"));
}

#[test]
fn the_splitter_stays_between_the_two_minimums() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None).expect("items");
    let mut state = vault::State::new(page, None);
    state.set_content_width(1200.0);
    assert_eq!(state.list_width(), 400.0);

    // Pressing on its own moves nothing: the first move is what fixes the
    // origin the rest of the drag is measured from.
    state.update(vault::Message::ResizeStart, &session);
    state.update(vault::Message::ResizeMove(700.0), &session);
    assert_eq!(state.list_width(), 400.0);
    state.update(vault::Message::ResizeMove(800.0), &session);
    assert_eq!(state.list_width(), 500.0);

    // Dragging past the maximum stops there instead of banking the overshoot,
    // so coming back moves the splitter on the first pixel.
    state.update(vault::Message::ResizeMove(1400.0), &session);
    assert_eq!(state.list_width(), 560.0);
    state.update(vault::Message::ResizeMove(760.0), &session);
    assert_eq!(state.list_width(), 460.0);

    // A window with no room for both minimums squeezes the detail, not the
    // list — and the width the user asked for survives to be restored.
    state.set_content_width(800.0);
    assert_eq!(state.list_width(), 320.0);
    state.set_content_width(1200.0);
    assert_eq!(state.list_width(), 460.0);

    // Releasing stops the tracking, so a stray pointer no longer resizes.
    state.update(vault::Message::ResizeEnd, &session);
    state.update(vault::Message::ResizeMove(200.0), &session);
    assert_eq!(state.list_width(), 460.0);
}

#[test]
fn a_revealed_field_hides_itself_once_the_setting_says_to() {
    let (_dir, session) = vault_with_items();
    let facade = session.facade();
    let page = local::items(&facade, None).expect("items");
    let login = page
        .items
        .iter()
        .find(|item| item.type_id == "login")
        .expect("login in the page");
    let detail = Detail::parse(local::item_get(&facade, login.id.clone()).expect("item_get"))
        .expect("parse");
    let password = detail
        .fields
        .iter()
        .position(|field| field.key == "password")
        .expect("password field");

    let mut state = vault::State::new(page, None);
    state.update(vault::Message::Loaded(Ok(detail)), &session);

    // Off by default, so revealing schedules nothing to take it away.
    let outcome = state.update(
        vault::Message::Detail(detail::Message::ToggleReveal(password)),
        &session,
    );
    assert!(matches!(outcome, vault::Outcome::None));
    assert!(state.detail().expect("detail").fields[password].revealed);

    state.set_reveal_seconds(20);
    let outcome = state.update(
        vault::Message::Detail(detail::Message::ToggleReveal(password)),
        &session,
    );
    assert!(
        matches!(outcome, vault::Outcome::None),
        "hiding again waits for nothing"
    );

    let outcome = state.update(
        vault::Message::Detail(detail::Message::ToggleReveal(password)),
        &session,
    );
    assert!(
        matches!(outcome, vault::Outcome::Task(_)),
        "revealing starts the clock"
    );

    // A stale timer belongs to an earlier reveal and leaves this one alone.
    // Only the third toggle started a clock, so that clock is the first one.
    state.update(vault::Message::HideRevealed(0), &session);
    assert!(state.detail().expect("detail").fields[password].revealed);

    state.update(vault::Message::HideRevealed(1), &session);
    assert!(!state.detail().expect("detail").fields[password].revealed);
}

#[test]
fn a_folder_narrows_the_list_and_the_place_is_reported() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None).expect("items");
    let mut state = vault::State::new(page, None);

    // The fixture has `work/aws` and `personal/mail`.
    assert_eq!(state.visible().len(), 2);

    let outcome = state.update(
        vault::Message::SelectFolder(Some("work".to_string())),
        &session,
    );
    assert!(matches!(
        outcome,
        vault::Outcome::Moved(zann_cosmic::settings::Place::Folder(Some(ref path))) if path == "work"
    ));
    let visible = state.visible();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].path, "work/aws");

    // A folder and the search compose, they do not replace each other.
    state.update(vault::Message::QueryInput("mail".to_string()), &session);
    assert!(state.visible().is_empty(), "mail does not live under work");

    state.update(vault::Message::ClearQuery, &session);
    state.update(vault::Message::SelectFolder(None), &session);
    assert_eq!(state.visible().len(), 2);
}

#[test]
fn the_last_place_comes_back_with_its_folder_unfolded() {
    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None).expect("items");
    let mut state = vault::State::new(page, None);

    state.set_content_width(1200.0);
    state.restore(520.0, None, Some("work"));
    assert_eq!(state.list_width(), 520.0);

    let visible = state.visible();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].path, "work/aws");

    // A path with no folder behind it any more must not hide the whole list.
    state.restore(520.0, None, None);
    assert_eq!(state.visible().len(), 2);
}

#[test]
fn a_bulk_copy_names_the_secrets_without_spelling_them_out() {
    let (_dir, session) = vault_with_items();
    let facade = session.facade();
    let page = local::items(&facade, None).expect("items");
    let login = page
        .items
        .iter()
        .find(|item| item.type_id == "login")
        .expect("login in the page");
    let detail = Detail::parse(local::item_get(&facade, login.id.clone()).expect("item_get"))
        .expect("parse");

    let (env, held_back) = detail.as_env();
    assert_eq!(held_back, 2, "the password and the one-time code");
    assert!(env.contains("username=demo@example.com"));
    assert!(env.contains("password=<protected>"));
    assert!(!env.contains("hunter2"), "a secret must not leave this way");

    let (json, held_back) = detail.as_json();
    assert_eq!(held_back, 2);
    assert!(!json.contains("hunter2"));

    // Raw is the payload as stored, secrets and all — it is the one copy that
    // says so on the button.
    assert!(detail.payload_json.contains("hunter2"));

    // The one a reader most likely came for is the first masked field.
    assert_eq!(detail.primary_secret(), Some("hunter2"));
}

#[test]
fn the_palette_offers_commands_then_items() {
    use zann_cosmic::screens::palette;

    let (_dir, session) = vault_with_items();
    let page = local::items(&session.facade(), None).expect("items");
    let vault = vault::State::new(page, None);
    let candidates = vault.candidates();
    let mut state = palette::State::new();

    // Nothing selected, so the two commands that need an item are held back.
    let rows = state.rows(&candidates, false);
    assert_eq!(
        rows.iter()
            .filter(|row| matches!(row, palette::Row::Command(_)))
            .count(),
        2
    );
    assert_eq!(
        rows.iter()
            .filter(|row| matches!(row, palette::Row::Item(_)))
            .count(),
        2
    );

    // A query narrows both halves at once.
    state.update(palette::Message::QueryInput("mail".to_string()), &rows);
    let rows = state.rows(&candidates, true);
    assert_eq!(rows.len(), 1, "only the item named mail");
    assert!(matches!(rows[0], palette::Row::Item(_)));

    // Enter runs whatever the highlight is on, and the highlight went back to
    // the top when the query changed.
    assert!(matches!(
        state.update(palette::Message::Submit, &rows),
        palette::Outcome::Run(palette::Row::Item(_))
    ));

    // Moving past the end wraps rather than falling off it.
    let rows = state.rows(&candidates, true);
    state.update(palette::Message::Move(-1), &rows);
    assert!(matches!(
        state.update(palette::Message::Submit, &rows),
        palette::Outcome::Run(_)
    ));
}

/// The catalogue is looked up by string, so nothing stops a typo reaching the
/// screen as its own key. This is the check the compiler cannot do: every key
/// the sources ask for has to exist.
#[test]
fn every_key_the_app_asks_for_is_in_the_catalogue() {
    let catalogue = zann_ui_core::i18n::Catalogue::new("en");
    let mut missing = Vec::new();

    for entry in walk_sources("src") {
        let source = std::fs::read_to_string(&entry).expect("read a source file");
        for key in literal_keys(&source) {
            // `fields.<name>` is built from the item's own field names, which
            // are data and are meant to fall through to a spelled-out label.
            if !key.starts_with("fields.") && !catalogue.has(&key) {
                missing.push(format!("{}: {key}", entry.display()));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "keys with no catalogue entry: {missing:#?}"
    );
}

/// Every `"a.b"`-shaped string literal in a source file. Dotted lowercase with
/// no spaces is what a catalogue key looks like — and, as it turns out, what a
/// filename looks like too, so those are named and skipped.
fn literal_keys(source: &str) -> Vec<String> {
    const FILE_SUFFIXES: &[&str] = &[".json", ".sqlite", ".rs", ".toml", ".png", ".desktop"];

    let mut keys = Vec::new();
    for piece in source.split('"').skip(1).step_by(2) {
        if FILE_SUFFIXES.iter().any(|suffix| piece.ends_with(suffix)) {
            continue;
        }
        let looks_like_a_key = piece.contains('.')
            && !piece.contains(' ')
            && !piece.contains('/')
            && !piece.contains('{')
            && piece
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
            && piece.split('.').all(|part| {
                part.chars().next().is_some_and(char::is_lowercase) && !part.is_empty()
            })
            && piece.split('.').count() >= 2;
        if looks_like_a_key {
            keys.push(piece.to_string());
        }
    }
    keys
}

fn walk_sources(root: &str) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk_sources(&path.to_string_lossy()));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found
}

#[test]
fn settings_round_trip_through_a_file() {
    let mut settings = zann_cosmic::settings::Settings::default();
    assert_eq!(settings.auto_lock_minutes, 10);
    assert!(settings.close_to_tray);

    settings.set(zann_cosmic::settings::Change::AutoLockMinutes(30));
    settings.set(zann_cosmic::settings::Change::CloseToTray(false));

    let text = serde_json::to_string(&settings).expect("serialize");
    let back: zann_cosmic::settings::Settings = serde_json::from_str(&text).expect("deserialize");
    assert_eq!(back, settings);

    // A file written by an older build is missing fields, not broken.
    let partial: zann_cosmic::settings::Settings =
        serde_json::from_str(r#"{"auto_lock_minutes": 5}"#).expect("partial");
    assert_eq!(partial.auto_lock_minutes, 5);
    assert_eq!(
        partial.clipboard_clear_seconds,
        zann_cosmic::settings::Settings::default().clipboard_clear_seconds
    );
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
    })));
    assert_eq!(state.stage(), &connect::Stage::Password);

    // Two methods: ask.
    let mut state = connect::State::default();
    state.update(connect::Message::Probed(Ok(ServerProbe {
        methods: vec![Method::Password, Method::Oidc],
        register: false,
        server_name: None,
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
