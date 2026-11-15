use super::*;
use crate::session::{SessionError, SessionErrorKind, SessionOperationId};

#[tokio::test]
async fn provider_exchange_sends_the_exact_native_redirect_and_verifier_once() {
    use mockito::Matcher;
    let mut server = mockito::Server::new_async().await;
    let request = server
        .mock("POST", "/token")
        .match_header("authorization", Matcher::Missing)
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded("code".into(), "one-time-code".into()),
            Matcher::UrlEncoded(
                "redirect_uri".into(),
                "com.example.zann:/oidc/callback".into(),
            ),
            Matcher::UrlEncoded("code_verifier".into(), "private-verifier".into()),
            Matcher::UrlEncoded("grant_type".into(), "authorization_code".into()),
        ]))
        .expect(1)
        .with_status(200)
        .with_body(r#"{"access_token":"fake-access","id_token":"fake-id"}"#)
        .create_async()
        .await;
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let token = exchange_authorization_code(
        &http,
        &format!("{}/token", server.url()),
        "client",
        "one-time-code",
        "com.example.zann:/oidc/callback",
        "private-verifier",
    )
    .await
    .unwrap();
    assert!(token.id_token.as_deref() == Some("fake-id"));
    request.assert_async().await;
}

#[tokio::test]
async fn cancelled_provider_exchange_is_never_dispatched_or_retried() {
    let mut server = mockito::Server::new_async().await;
    let request = server.mock("POST", "/token").expect(0).create_async().await;
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let (operation, cancel) =
        SessionOperation::new(std::time::Instant::now() + Duration::from_secs(2));
    cancel.cancel();
    let endpoint = format!("{}/token", server.url());
    let work = exchange_authorization_code(
        &http,
        &endpoint,
        "client",
        "code",
        "com.example.zann:/oidc/callback",
        "verifier",
    );
    assert_eq!(
        within_operation(&operation, work)
            .await
            .err()
            .unwrap()
            .kind(),
        OidcBrowserErrorKind::Cancelled
    );
    request.assert_async().await;
}

#[test]
fn a_flow_failure_preserves_its_cause_but_redacts_default_diagnostics() {
    let cause = std::io::Error::other("private-sentinel");
    let error = OidcBrowserError::caused_by(OidcBrowserErrorKind::Transport, cause);
    assert!(std::error::Error::source(&error).is_some());
    assert!(!format!("{error:?}: {error}").contains("private-sentinel"));
}

#[test]
fn session_failure_keeps_its_cause() {
    let cause = SessionError::for_app(SessionOperationId::new(), SessionErrorKind::Protocol);
    let rendered = cause.to_string();
    let error = OidcBrowserError::session(cause);

    assert_eq!(error.kind(), OidcBrowserErrorKind::Session);
    assert_eq!(
        error.to_string(),
        format!("OIDC session failed: {rendered}")
    );
    let source = std::error::Error::source(&error).expect("session cause");
    assert_eq!(source.to_string(), rendered);
    let session = error.into_session_error().expect("session error");
    assert_eq!(session.kind(), SessionErrorKind::Protocol);
}

#[test]
fn flow_failure_is_not_a_session_error() {
    let error = OidcBrowserError::new(OidcBrowserErrorKind::Transport);
    assert!(std::error::Error::source(&error).is_none());
    let error = error.into_session_error().expect_err("flow error");
    assert_eq!(error.kind(), OidcBrowserErrorKind::Transport);
}

#[test]
fn provider_urls_require_tls_except_loopback() {
    assert!(validate_sensitive_url("https://id.example.test/authorize").is_ok());
    assert!(validate_sensitive_url("http://127.0.0.1:8080/authorize").is_ok());
    assert!(validate_sensitive_url("http://id.example.test/authorize").is_err());
    assert!(validate_sensitive_url("https://user@id.example.test/authorize").is_err());
}
