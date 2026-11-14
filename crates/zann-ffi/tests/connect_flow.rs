use zann_ffi::*;

fn probe(flow: &ConnectFlowFfi) -> ConnectOperationFfi {
    let effects = flow.dispatch(ConnectActionFfi::Probe {
        url: " https://example.test/ ".into(),
    });
    match &effects[1] {
        ConnectEffectFfi::Probe {
            id,
            url,
            connection_name,
            profile_name,
        } => {
            assert_eq!(url, "https://example.test/");
            assert_eq!(connection_name, zann_flows::connect::CONNECTION_NAME);
            assert_eq!(profile_name, zann_flows::connect::PROFILE_NAME);
            *id
        }
        _ => panic!("probe effect"),
    }
}
fn info(methods: Vec<AuthMethodFfi>, registration_available: bool) -> ConnectServerFfi {
    ConnectServerFfi {
        methods,
        registration_available,
        server_name: Some("Server".into()),
    }
}

#[test]
fn trust_registration_and_success_cross_the_same_typed_boundary() {
    let flow = ConnectFlowFfi::new();
    let id = probe(&flow);
    let wrong_step = flow.complete(ConnectCompletionFfi::Trusted {
        id,
        info: info(vec![AuthMethodFfi::Password], false),
    });
    assert!(wrong_step.is_empty());
    assert!(flow.accepts(id, ConnectStepFfi::Probe));
    flow.complete(ConnectCompletionFfi::Probed {
        id,
        probe: ConnectProbeFfi::FingerprintChanged {
            old: "old".into(),
            new: "new".into(),
        },
    });
    assert_eq!(
        flow.snapshot().stage,
        ConnectStageFfi::Fingerprint {
            old: "old".into(),
            new: "new".into()
        }
    );
    let effects = flow.dispatch(ConnectActionFfi::TrustFingerprint);
    let ConnectEffectFfi::TrustFingerprint { id } = effects[0] else {
        panic!("trust effect")
    };
    flow.complete(ConnectCompletionFfi::Trusted {
        id,
        info: info(
            vec![AuthMethodFfi::ServiceAccount, AuthMethodFfi::Password],
            true,
        ),
    });
    assert_eq!(
        flow.snapshot().stage,
        ConnectStageFfi::Password { register: false }
    );
    assert_eq!(flow.snapshot().methods, vec![AuthMethodFfi::Password]);
    flow.dispatch(ConnectActionFfi::SetRegistering { register: true });
    let effects = flow.dispatch(ConnectActionFfi::SubmitPassword {
        email: " person@example.test ".into(),
        password: "secret-ffi-sentinel".into(),
        full_name: Some(" Name ".into()),
    });
    let id = match &effects[0] {
        ConnectEffectFfi::Password {
            id,
            email,
            password,
            full_name,
            register,
            timeout_ms,
        } => {
            assert_eq!(email, "person@example.test");
            assert_eq!(password, "secret-ffi-sentinel");
            assert_eq!(full_name.as_deref(), Some("Name"));
            assert!(*register);
            assert_eq!(*timeout_ms, zann_flows::connect::LOGIN_TIMEOUT_MS);
            *id
        }
        _ => panic!("password effect"),
    };
    assert!(!format!("{effects:?}").contains("secret-ffi-sentinel"));
    let effects = flow.complete(ConnectCompletionFfi::Password {
        id,
        storage_id: "storage".into(),
        has_personal_keys: true,
    });
    assert!(
        matches!(effects.last(), Some(ConnectEffectFfi::Connected { storage_id, has_personal_keys: true }) if storage_id == "storage")
    );
    assert_eq!(flow.snapshot().stage, ConnectStageFfi::Complete);
    assert!(flow
        .complete(ConnectCompletionFfi::Password {
            id,
            storage_id: "duplicate".into(),
            has_personal_keys: false
        })
        .is_empty());
}

#[test]
fn oidc_phase_back_and_stale_results_have_native_reducer_semantics() {
    let flow = ConnectFlowFfi::new();
    let id = probe(&flow);
    let effects = flow.complete(ConnectCompletionFfi::Probed {
        id,
        probe: ConnectProbeFfi::Ready {
            info: info(vec![AuthMethodFfi::Oidc], false),
        },
    });
    let ConnectEffectFfi::BeginOidc { id, timeout_ms } = effects[0] else {
        panic!("begin OIDC")
    };
    assert_eq!(timeout_ms, zann_flows::connect::LOGIN_TIMEOUT_MS);
    let effects = flow.complete(ConnectCompletionFfi::OidcStarted {
        id,
        url: "https://issuer.test/?state=private-sentinel".into(),
    });
    assert!(matches!(
        effects.as_slice(),
        [
            ConnectEffectFfi::OpenBrowser { .. },
            ConnectEffectFfi::FinishOidc { .. }
        ]
    ));
    assert!(!format!("{:?}", flow.snapshot()).contains("private-sentinel"));
    assert!(flow.accepts(id, ConnectStepFfi::OidcFinish));
    assert!(flow
        .complete(ConnectCompletionFfi::Failed {
            id,
            step: ConnectStepFfi::OidcStart,
            message: Some("old start".into())
        })
        .is_empty());
    let effects = flow.dispatch(ConnectActionFfi::Back);
    assert!(
        matches!(effects.first(), Some(ConnectEffectFfi::Cancel { id: cancelled }) if *cancelled == id)
    );
    assert_eq!(flow.snapshot().stage, ConnectStageFfi::Server);
    let current = probe(&flow);
    flow.complete(ConnectCompletionFfi::OidcFinished {
        id,
        storage_id: "old".into(),
        has_personal_keys: false,
    });
    assert!(flow.accepts(current, ConnectStepFfi::Probe));
    assert!(flow.snapshot().busy);
    assert!(flow.snapshot().error.is_none());
}

#[test]
fn cancelled_and_reopened_ffi_flows_reject_old_capability_results() {
    let old = ConnectFlowFfi::new();
    let id = probe(&old);
    old.dispatch(ConnectActionFfi::Cancel);
    let reopened = ConnectFlowFfi::new();
    let next = probe(&reopened);
    for flow in [&old, &reopened] {
        assert!(!flow.accepts(id, ConnectStepFfi::Probe));
        assert!(flow
            .complete(ConnectCompletionFfi::Probed {
                id,
                probe: ConnectProbeFfi::Ready {
                    info: info(vec![AuthMethodFfi::Password], false)
                }
            })
            .is_empty());
        assert!(flow
            .complete(ConnectCompletionFfi::Failed {
                id,
                step: ConnectStepFfi::Probe,
                message: Some("old failure".into())
            })
            .is_empty());
    }
    assert_ne!(id.instance, next.instance);
    assert!(reopened.accepts(next, ConnectStepFfi::Probe));
}
