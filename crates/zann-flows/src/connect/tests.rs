use super::*;

fn probe(
    flow: &mut Connect,
    methods: Vec<AuthMethod>,
    registration_available: bool,
) -> Vec<Effect> {
    let effects = flow.dispatch(Action::Probe {
        url: " example.com/ ".into(),
    });
    let id = effects
        .iter()
        .find_map(|effect| effect.operation().map(|(id, _)| id))
        .expect("probe");
    flow.complete(
        id,
        Completion::Probed(Ok(Probe::Ready(ServerInfo {
            methods,
            registration_available,
            server_name: Some("Example".into()),
        }))),
    )
}
fn operation(effects: &[Effect]) -> OperationId {
    effects
        .iter()
        .find_map(|effect| effect.operation().map(|(id, _)| id))
        .expect("work effect")
}
fn password() -> Action {
    Action::SubmitPassword {
        email: " person@example.test ".into(),
        password: "private-password".into(),
        full_name: Some(" Example User ".into()),
    }
}

#[test]
fn discovery_filters_noninteractive_methods_and_owns_registration() {
    let mut flow = Connect::new(1);
    probe(
        &mut flow,
        vec![
            AuthMethod::ServiceAccount,
            AuthMethod::Password,
            AuthMethod::Password,
        ],
        true,
    );
    assert_eq!(flow.snapshot().methods, vec![AuthMethod::Password]);
    assert_eq!(flow.snapshot().stage, Stage::Password { register: false });
    flow.dispatch(Action::SetRegistering { register: true });
    let effects = flow.dispatch(password());
    assert!(
        matches!(&effects[0], Effect::Password { email, password, full_name: Some(name), register: true, .. }
        if email == "person@example.test" && password == "private-password" && name == "Example User")
    );
    assert!(flow.dispatch(password()).is_empty());
    assert!(flow
        .dispatch(Action::SetRegistering { register: false })
        .is_empty());
}

#[test]
fn unavailable_registration_and_methods_are_never_admitted() {
    let mut flow = Connect::new(1);
    probe(&mut flow, vec![AuthMethod::Password], false);
    flow.dispatch(Action::SetRegistering { register: true });
    assert_eq!(flow.snapshot().stage, Stage::Password { register: false });
    assert!(flow.dispatch(Action::StartOidc).is_empty());
    let mut flow = Connect::new(2);
    probe(&mut flow, vec![AuthMethod::ServiceAccount], false);
    assert_eq!(flow.snapshot().stage, Stage::Server);
    assert!(flow.snapshot().error.is_some());
}

#[test]
fn back_cancels_one_operation_and_late_completions_cannot_replace_a_retry() {
    let mut flow = Connect::new(1);
    probe(
        &mut flow,
        vec![AuthMethod::Password, AuthMethod::Oidc],
        false,
    );
    flow.dispatch(Action::ChoosePassword);
    let old = operation(&flow.dispatch(password()));
    assert!(
        matches!(flow.dispatch(Action::Back).as_slice(), [Effect::Cancel { id }] if *id == old)
    );
    assert_eq!(flow.snapshot().stage, Stage::Methods);
    flow.dispatch(Action::ChoosePassword);
    let current = operation(&flow.dispatch(password()));
    assert_ne!(old, current);
    assert!(flow
        .complete(
            old,
            Completion::Password(Ok(Connected {
                storage_id: "old".into(),
                has_personal_keys: false
            }))
        )
        .is_empty());
    assert!(flow.snapshot().busy);
    assert!(flow.accepts(current, Step::Password));
    let effects = flow.complete(
        current,
        Completion::Password(Ok(Connected {
            storage_id: "current".into(),
            has_personal_keys: true,
        })),
    );
    assert!(
        matches!(effects.last(), Some(Effect::Connected(Connected { storage_id, has_personal_keys: true })) if storage_id == "current")
    );
    assert!(flow.dispatch(Action::Back).is_empty());
}

#[test]
fn cancel_and_reopen_reject_success_failure_and_queued_work() {
    let mut old = Connect::new(1);
    let id = operation(&old.dispatch(Action::Probe {
        url: "example.com".into(),
    }));
    old.dispatch(Action::Cancel);
    let mut reopened = Connect::new(2);
    let current = operation(&reopened.dispatch(Action::Probe {
        url: "new.example".into(),
    }));
    for completion in [
        Completion::Probed(Err(Failure::Message("old failure".into()))),
        Completion::Probed(Ok(Probe::Ready(ServerInfo {
            methods: vec![AuthMethod::Oidc],
            registration_available: false,
            server_name: None,
        }))),
        Completion::Password(Ok(Connected {
            storage_id: "old".into(),
            has_personal_keys: false,
        })),
        Completion::OidcStarted(Ok("https://old.example/authorize".into())),
    ] {
        assert!(old.complete(id, completion.clone()).is_empty());
        assert!(reopened.complete(id, completion).is_empty());
    }
    assert!(old.dispatch(Action::StartOidc).is_empty());
    assert!(reopened.accepts(current, Step::Probe));
}

#[test]
fn trust_is_explicit_and_a_stale_confirmation_cannot_advance_a_new_probe() {
    let mut flow = Connect::new(1);
    let id = operation(&flow.dispatch(Action::Probe {
        url: "example.com".into(),
    }));
    assert!(flow
        .complete(
            id,
            Completion::Probed(Ok(Probe::FingerprintChanged {
                old: "old".into(),
                new: "new".into()
            }))
        )
        .is_empty());
    assert!(flow.dispatch(password()).is_empty());
    assert!(flow.dispatch(Action::StartOidc).is_empty());
    let trust = operation(&flow.dispatch(Action::TrustFingerprint));
    flow.dispatch(Action::Back);
    let next = operation(&flow.dispatch(Action::Probe {
        url: "new.example".into(),
    }));
    assert!(flow
        .complete(
            trust,
            Completion::Trusted(Ok(ServerInfo {
                methods: vec![AuthMethod::Password],
                registration_available: false,
                server_name: None
            }))
        )
        .is_empty());
    assert!(flow.accepts(next, Step::Probe));
}

#[test]
fn oidc_has_one_cancellable_operation_and_rejects_duplicate_start_results() {
    let mut flow = Connect::new(1);
    let id = operation(&probe(&mut flow, vec![AuthMethod::Oidc], false));
    assert!(flow.dispatch(Action::StartOidc).is_empty());
    let effects = flow.complete(
        id,
        Completion::OidcStarted(Ok("https://issuer.example/authorize".into())),
    );
    assert!(
        matches!(effects.as_slice(), [Effect::OpenBrowser { id: open, .. }, Effect::FinishOidc { id: finish }] if *open == id && *finish == id)
    );
    assert!(flow.accepts(id, Step::OidcFinish));
    assert!(flow
        .complete(
            id,
            Completion::OidcStarted(Err(Failure::Message("duplicate".into())))
        )
        .is_empty());
    assert!(matches!(
        flow.dispatch(Action::ReopenBrowser).as_slice(),
        [Effect::OpenBrowser { .. }]
    ));
    assert!(matches!(
        flow.dispatch(Action::CopyBrowserUrl).as_slice(),
        [Effect::CopyBrowserUrl { .. }]
    ));
    flow.dispatch(Action::Back);
    assert!(flow.dispatch(Action::ReopenBrowser).is_empty());
    assert!(flow
        .complete(
            id,
            Completion::OidcFinished(Ok(Connected {
                storage_id: "old".into(),
                has_personal_keys: false
            }))
        )
        .is_empty());
}

#[test]
fn cancelled_and_failed_operations_can_be_retried_without_browser_state() {
    let mut flow = Connect::new(1);
    let id = operation(&probe(&mut flow, vec![AuthMethod::Oidc], false));
    flow.complete(
        id,
        Completion::OidcStarted(Ok("https://issuer.example/authorize".into())),
    );
    flow.complete(id, Completion::OidcFinished(Err(Failure::Cancelled)));
    assert_eq!(flow.snapshot().stage, Stage::Methods);
    assert!(!flow.snapshot().busy);
    assert!(flow.snapshot().error.is_none());
    let retry = operation(&flow.dispatch(Action::StartOidc));
    assert_ne!(id, retry);
}

#[test]
fn inputs_effects_and_browser_stages_redact_debug() {
    let mut flow = Connect::new(1);
    probe(&mut flow, vec![AuthMethod::Password], false);
    let effects = flow.dispatch(password());
    assert!(!format!("{:?}", password()).contains("private-password"));
    assert!(!format!("{effects:?}").contains("private-password"));
    assert!(!format!(
        "{:?}",
        Stage::Browser {
            url: "private-authorization-url".into()
        }
    )
    .contains("private-authorization-url"));
}

#[test]
fn failed_trust_returns_to_discovery_instead_of_reusing_a_consumed_challenge() {
    let mut flow = Connect::new(1);
    let id = operation(&flow.dispatch(Action::Probe {
        url: "example.test".into(),
    }));
    flow.complete(
        id,
        Completion::Probed(Ok(Probe::FingerprintChanged {
            old: "old".into(),
            new: "new".into(),
        })),
    );
    let id = operation(&flow.dispatch(Action::TrustFingerprint));
    let effects = flow.complete(
        id,
        Completion::Trusted(Err(Failure::Message("concurrent trust change".into()))),
    );
    assert_eq!(flow.snapshot().stage, Stage::Server);
    assert_eq!(
        flow.snapshot().error.as_deref(),
        Some("concurrent trust change")
    );
    assert!(matches!(
        effects.as_slice(),
        [Effect::Cancel { .. }, Effect::ResetConnection]
    ));
    assert!(flow.dispatch(Action::TrustFingerprint).is_empty());
    assert!(!flow
        .dispatch(Action::Probe {
            url: "example.test".into()
        })
        .is_empty());
}
