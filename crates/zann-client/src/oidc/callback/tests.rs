use super::*;

fn application() -> CallbackTransport {
    CallbackTransport::new(OidcCallback::Application {
        redirect_uri: "com.example.zann:/oidc/callback".to_owned(),
    })
    .unwrap()
}

#[test]
fn application_redirect_is_explicit_and_never_opens_a_listener() {
    let callback = application();
    assert!(callback.listener.is_none());
    for uri in [
        "https://example.test/callback",
        "com.example.zann://host/callback",
        "com.example.zann:/",
        "com.example.zann:/callback?state=x",
        "com.example.zann:/callback#fragment",
    ] {
        assert!(application_redirect(uri).is_err(), "{uri}");
    }
}

#[test]
fn state_is_checked_before_provider_error_or_code_is_admitted() {
    for query in ["state=foreign&code=x", "state=foreign&error=denied"] {
        let callback = application()
            .application_callback(format!("com.example.zann:/oidc/callback?{query}"))
            .unwrap();
        assert_eq!(
            callback.authorization_code("current").err().unwrap().kind(),
            OidcBrowserErrorKind::Protocol
        );
    }
    let callback = application()
        .application_callback("com.example.zann:/oidc/callback?state=current&error=denied".into())
        .unwrap();
    assert_eq!(
        callback.authorization_code("current").err().unwrap().kind(),
        OidcBrowserErrorKind::AuthorizationRejected
    );
}

#[test]
fn callback_requires_exact_destination_and_unambiguous_fields() {
    let callback = application();
    let valid = callback
        .application_callback("com.example.zann:/oidc/callback?state=s&code=secret".into())
        .unwrap();
    assert_eq!(valid.code.as_ref().unwrap().as_str(), "secret");
    assert_eq!(valid.state.as_str(), "s");
    assert!(!valid.rejected);
    for uri in [
        "com.other.zann:/oidc/callback?state=s&code=x",
        "com.example.zann:/other?state=s&code=x",
        "com.example.zann:/oidc/callback?state=s&code=x&code=y",
        "com.example.zann:/oidc/callback?state=s&state=t&code=x",
        "com.example.zann:/oidc/callback?state=s&code=x&error=denied",
        "com.example.zann:/oidc/callback?code=x",
        "com.example.zann:/oidc/callback?state=s&code=x#fragment",
    ] {
        assert!(callback.application_callback(uri.into()).is_err());
    }
    let rejected = callback
        .application_callback("com.example.zann:/oidc/callback?state=s&error=denied".into())
        .unwrap();
    assert!(rejected.rejected);
    assert_eq!(rejected.state.as_str(), "s");
    assert!(callback
        .application_callback("x".repeat(MAX_CALLBACK_BYTES + 1))
        .is_err());
}

#[tokio::test]
async fn system_callback_cannot_silently_wait_on_loopback() {
    let (operation, _) = SessionOperation::new(std::time::Instant::now() + Duration::from_secs(2));
    assert_eq!(
        application()
            .receive(&operation, "state")
            .await
            .err()
            .unwrap()
            .kind(),
        OidcBrowserErrorKind::Configuration
    );
}

#[tokio::test]
async fn cancellation_and_deadline_stop_pending_provider_io() {
    let (operation, cancel) =
        SessionOperation::new(std::time::Instant::now() + Duration::from_secs(2));
    cancel.cancel();
    let error = within_operation::<()>(&operation, std::future::pending())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), OidcBrowserErrorKind::Cancelled);
    let (operation, _) = SessionOperation::new(std::time::Instant::now());
    let error = within_operation::<()>(&operation, std::future::pending())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), OidcBrowserErrorKind::DeadlineExceeded);
}

#[tokio::test]
async fn loopback_ignores_foreign_state_before_accepting_the_current_one() {
    let transport = CallbackTransport::new(OidcCallback::Loopback).unwrap();
    let uri = transport.uri.to_string();
    let (operation, _) = SessionOperation::new(std::time::Instant::now() + Duration::from_secs(3));
    let send = tokio::spawn(async move {
        let http = reqwest::Client::new();
        assert_eq!(
            http.get(format!("{uri}?state=foreign&error=denied"))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
        assert_eq!(
            http.get(format!("{uri}?state=current&code=code"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    });
    let callback = transport.receive(&operation, "current").await.unwrap();
    send.await.unwrap();
    assert_eq!(callback.state.as_str(), "current");
}
