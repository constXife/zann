mod support;

use zann_ffi::{CoreError, SessionErrorKindFfi, SessionOperationFfi};

#[test]
fn remote_session_projects_typed_session_errors() {
    let root = tempfile::tempdir().expect("tempdir");
    let core = support::open(&root.path().join("local.sqlite"));
    let session = core.remote_session().expect("remote session");

    let closed_port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port();
    assert!(matches!(
        session.prepare_connection(
            format!("http://127.0.0.1:{closed_port}"),
            "Remote".into(),
            "default".into(),
        ),
        Err(CoreError::Session {
            kind: SessionErrorKindFfi::TransportUnavailable,
            ..
        })
    ));

    let operation = SessionOperationFfi::new(60_000).expect("operation");
    assert!(matches!(
        session.logout(None, operation),
        Err(CoreError::Session {
            kind: SessionErrorKindFfi::Configuration,
            ..
        })
    ));
}
