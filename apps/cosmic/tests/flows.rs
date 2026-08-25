//! The screens are plain state machines, so the flows can be driven without a
//! compositor. Anything that needs a real server (probing, logging in) stops at
//! the message boundary: the response is fed in as a message.

use zann_cosmic::backend::local;
use zann_cosmic::backend::remote::{LoginOutcome, Method, Remote, ServerProbe};
use zann_cosmic::screens::detail::Detail;
use zann_cosmic::screens::{connect, master, vault};
use zann_cosmic::session::Session;
use zann_ffi::ItemUpdate;

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

    // The clipboard belongs to the shell, so the drawer's copy travels up.
    let outcome = state.update(
        vault::Message::Detail(zann_cosmic::screens::detail::Message::Copy("s3cret".into())),
        &session,
    );
    assert!(matches!(outcome, vault::Outcome::Copy(value) if value == "s3cret"));

    assert!(matches!(
        state.update(vault::Message::Lock, &session),
        vault::Outcome::Locked
    ));
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
