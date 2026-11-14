mod support;
use zann_ffi::{BrowserErrorKindFfi, CoreError};

#[test]
fn storage_open_is_independent_and_native_host_activation_is_explicit_and_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let core = support::open(&root.join("local.sqlite"));
    assert!(matches!(
        core.browser_pairings(),
        Err(CoreError::Browser {
            kind: BrowserErrorKindFfi::NotRunning,
            ..
        })
    ));
    core.start_browser_service().unwrap();
    core.start_browser_service().unwrap();
    let settings = core.browser_pairings().unwrap();
    assert!(settings.paired.is_empty());
    assert!(settings.active_code_id.is_none());
    let code = core.browser_begin_pairing().unwrap();
    assert_eq!(code.value.len(), 6);
    assert_eq!(code.expires_in_seconds, 120);
    assert_eq!(
        core.browser_pairings().unwrap().active_code_id.as_deref(),
        Some(code.id.as_str())
    );
    assert!(root.join("ipc/browser.sock").exists());
}

#[test]
fn long_root_still_opens_storage_and_hosting_reports_a_typed_path_limit() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir
        .path()
        .canonicalize()
        .unwrap()
        .join("long-client-root-".repeat(10));
    let core = support::open(&root.join("local.sqlite"));
    assert!(core.app_status().is_ok());
    assert!(matches!(
        core.start_browser_service(),
        Err(CoreError::Browser {
            kind: BrowserErrorKindFfi::PathTooLong,
            ..
        })
    ));
    assert!(core.app_status().is_ok());
    assert!(!root.join("ipc").exists());
}
