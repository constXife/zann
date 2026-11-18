use super::*;

struct Plan(&'static str);
impl Preparation for Plan {
    fn successor_code(&self) -> &str {
        self.0
    }
}
type Flow = AccountRecovery<Plan, u32>;
const CODE: &str = "successor-code";

fn work(effects: &[Effect<Plan, u32>]) -> OperationId {
    effects
        .iter()
        .find_map(Effect::operation)
        .expect("work effect")
}
fn prepared(pending: Vec<u32>) -> Flow {
    let mut flow = Flow::new(7);
    flow.dispatch(Action::SetLocator(" person@example.test ".into()));
    let effects = flow.dispatch(Action::Prepare);
    assert!(
        matches!(&effects[..], [Effect::Prepare { locator, .. }] if locator == "person@example.test")
    );
    flow.complete(
        work(&effects),
        Ok(Reply::Prepared {
            preparation: Plan(CODE),
            pending,
        }),
    );
    flow
}
fn consumed(handle: u32, progress: Result<Progress, Failure>) -> Result<Reply<Plan, u32>, Failure> {
    Ok(Reply::Consumed(Consumed { handle, progress }))
}
fn progress(state: RecoveryState, candidate: Option<Candidate>) -> Result<Progress, Failure> {
    Ok(Progress { state, candidate })
}
fn armed() -> Flow {
    let mut flow = prepared(vec![]);
    let effects = flow.dispatch(Action::Consume { confirmation: CODE });
    flow.complete(
        work(&effects),
        consumed(1, progress(RecoveryState::Consumed, None)),
    );
    flow
}

#[test]
fn successor_confirmation_mismatch_never_spends_the_old_code() {
    let mut flow = prepared(vec![]);
    assert!(matches!(
        flow.snapshot().phase,
        Phase::Confirm {
            successor_code: CODE,
            ..
        }
    ));
    assert!(!flow.can_consume("successor-cod"));
    assert!(flow
        .dispatch(Action::Consume {
            confirmation: "successor-cod"
        })
        .is_empty());
    assert!(matches!(flow.snapshot().phase, Phase::Confirm { .. }));
    assert!(flow.can_consume(CODE));
    let effects = flow.dispatch(Action::Consume { confirmation: CODE });
    assert!(matches!(
        &effects[..],
        [Effect::Consume {
            preparation: Plan(CODE),
            ..
        }]
    ));
    assert!(flow.snapshot().busy);
}

#[test]
fn happy_path_enrolls_and_completes() {
    let mut flow = armed();
    assert!(matches!(
        flow.snapshot().phase,
        Phase::Recover {
            consumed: true,
            candidate: false,
            editable: true,
            password_required: true,
            ..
        }
    ));
    flow.dispatch(Action::SetName(" Laptop ".into()));
    flow.dispatch(Action::SetMode(PasskeyMode::AuthOnly));
    assert!(matches!(
        flow.snapshot().phase,
        Phase::Recover {
            password_required: false,
            ..
        }
    ));
    let effects = flow.dispatch(Action::Enroll {
        pairing: "browser".into(),
    });
    assert!(matches!(&effects[..], [Effect::Enroll {
        handle: 1, restart: false, name, mode: PasskeyMode::AuthOnly, pairing, ..
    }] if name == "Laptop" && pairing == "browser"));
    assert!(flow.dispatch(Action::ResumeCurrent).is_empty());
    flow.complete(work(&effects), Ok(Reply::Enrolled));
    assert!(matches!(flow.snapshot().phase, Phase::Completed));
    assert!(flow.dispatch(Action::ResumeCurrent).is_empty());
}

#[test]
fn lost_consume_response_keeps_the_handle_for_retry_and_resume() {
    let mut flow = prepared(vec![]);
    let effects = flow.dispatch(Action::Consume { confirmation: CODE });
    flow.complete(
        work(&effects),
        consumed(9, Err(Failure::Message("connection reset".into()))),
    );
    let snapshot = flow.snapshot();
    assert!(matches!(
        snapshot.phase,
        Phase::Recover {
            consumed: false,
            ..
        }
    ));
    assert_eq!(snapshot.error, Some("connection reset"));
    assert!(flow
        .dispatch(Action::Enroll {
            pairing: "browser".into()
        })
        .is_empty());
    let retry = flow.dispatch(Action::RetryConsume);
    assert!(matches!(
        &retry[..],
        [Effect::RetryConsume { handle: 9, .. }]
    ));
    assert!(flow.snapshot().error.is_none());
    flow.complete(work(&retry), Err(Failure::Message("timeout".into())));
    let resume = flow.dispatch(Action::ResumeCurrent);
    assert!(matches!(&resume[..], [Effect::Resume { handle: 9, .. }]));
    flow.complete(
        work(&resume),
        consumed(9, progress(RecoveryState::CredentialReady, None)),
    );
    assert!(matches!(
        flow.snapshot().phase,
        Phase::Recover { consumed: true, .. }
    ));
    assert!(flow.dispatch(Action::RetryConsume).is_empty());
}

#[test]
fn failed_arm_returns_to_locate_and_pending_recoveries_resume() {
    let mut flow = prepared(vec![]);
    let effects = flow.dispatch(Action::Consume { confirmation: CODE });
    flow.complete(work(&effects), Err(Failure::Message("offline".into())));
    assert!(matches!(
        flow.snapshot().phase,
        Phase::Locate {
            locator: " person@example.test "
        }
    ));
    let mut flow = prepared(vec![4, 5]);
    assert!(flow.dispatch(Action::ResumePending(2)).is_empty());
    let effects = flow.dispatch(Action::ResumePending(1));
    assert!(matches!(&effects[..], [Effect::Resume { handle: 5, .. }]));
    flow.complete(
        work(&effects),
        consumed(5, progress(RecoveryState::Consumed, None)),
    );
    assert!(matches!(
        flow.snapshot().phase,
        Phase::Recover { consumed: true, .. }
    ));
    assert!(!flow.can_consume(CODE));
}

#[test]
fn candidate_fixes_enrollment_unless_restarting() {
    let mut flow = prepared(vec![]);
    let effects = flow.dispatch(Action::Consume { confirmation: CODE });
    let candidate = Candidate {
        name: "Phone".into(),
        mode: PasskeyMode::AuthOnly,
    };
    flow.complete(
        work(&effects),
        consumed(3, progress(RecoveryState::CredentialReady, Some(candidate))),
    );
    flow.dispatch(Action::SetName("Other".into()));
    flow.dispatch(Action::SetMode(PasskeyMode::VaultUnlock));
    assert!(matches!(
        flow.snapshot().phase,
        Phase::Recover {
            candidate: true,
            editable: false,
            name: "Phone",
            mode: PasskeyMode::AuthOnly,
            ..
        }
    ));
    flow.dispatch(Action::SetRestart(true));
    flow.dispatch(Action::SetName("Other".into()));
    flow.dispatch(Action::SetMode(PasskeyMode::VaultUnlock));
    flow.dispatch(Action::SetRestart(false));
    let effects = flow.dispatch(Action::Enroll {
        pairing: "browser".into(),
    });
    assert!(matches!(&effects[..], [Effect::Enroll {
        restart: false, name, mode: PasskeyMode::AuthOnly, ..
    }] if name == "Phone"));
}

#[test]
fn terminal_server_states_stop_or_complete_the_wizard() {
    for (state, completed) in [
        (RecoveryState::Completed, true),
        (RecoveryState::Expired, false),
        (RecoveryState::Abandoned, false),
        (RecoveryState::Superseded, false),
    ] {
        let mut flow = prepared(vec![]);
        let effects = flow.dispatch(Action::Consume { confirmation: CODE });
        flow.complete(work(&effects), consumed(1, progress(state, None)));
        let phase = flow.snapshot().phase;
        assert_eq!(matches!(phase, Phase::Completed), completed);
        assert_eq!(matches!(phase, Phase::Stopped), !completed);
        assert!(flow.dispatch(Action::ResumeCurrent).is_empty());
    }
}

#[test]
fn busy_back_cancels_and_stale_or_misrouted_replies_are_ignored() {
    let mut flow = armed();
    let first = flow.dispatch(Action::ResumeCurrent);
    let first_id = work(&first);
    assert!(flow.dispatch(Action::RetryConsume).is_empty());
    assert!(flow.dispatch(Action::SetName("ignored".into())).is_empty());
    flow.complete(first_id, Ok(Reply::Enrolled));
    assert!(flow.snapshot().busy);
    flow.complete(
        OperationId {
            instance: 8,
            sequence: first_id.sequence,
        },
        consumed(1, progress(RecoveryState::Completed, None)),
    );
    assert!(flow.snapshot().busy);
    flow.complete(first_id, Err(Failure::Cancelled));
    assert!(!flow.snapshot().busy);
    assert!(flow.snapshot().error.is_none());
    flow.complete(
        first_id,
        consumed(1, progress(RecoveryState::Completed, None)),
    );
    assert!(matches!(flow.snapshot().phase, Phase::Recover { .. }));

    let second = flow.dispatch(Action::ResumeCurrent);
    let second_id = work(&second);
    assert_ne!(second_id, first_id);
    let effects = flow.dispatch(Action::Back);
    assert!(matches!(&effects[..], [Effect::Cancel { id }, Effect::Closed] if *id == second_id));
    assert!(flow.closed());
    flow.complete(
        second_id,
        consumed(1, progress(RecoveryState::Completed, None)),
    );
    assert!(matches!(flow.snapshot().phase, Phase::Recover { .. }));
    assert!(flow.dispatch(Action::Back).is_empty());
    assert!(flow.dispatch(Action::ResumeCurrent).is_empty());
}

#[test]
fn opening_requires_an_idle_method_choice() {
    let mut connect = crate::connect::Connect::new(1);
    assert!(!can_open(connect.snapshot()));
    let effects = connect.dispatch(crate::connect::Action::Probe {
        url: "example.test".into(),
    });
    let (id, _) = effects
        .iter()
        .find_map(crate::connect::Effect::operation)
        .expect("probe");
    assert!(!can_open(connect.snapshot()));
    connect.complete(
        id,
        crate::connect::Completion::Probed(Ok(crate::connect::Probe::Ready(
            crate::connect::ServerInfo {
                methods: vec![
                    zann_core::AuthMethod::Password,
                    zann_core::AuthMethod::Passkey,
                ],
                registration_available: false,
                server_name: None,
            },
        ))),
    );
    assert!(can_open(connect.snapshot()));
    connect.dispatch(crate::connect::Action::ChoosePassword);
    assert!(can_open(connect.snapshot()));
}

#[test]
fn locate_requires_a_locator() {
    let mut flow = Flow::new(1);
    flow.dispatch(Action::SetLocator("   ".into()));
    assert!(flow.dispatch(Action::Prepare).is_empty());
    assert!(!flow.can_consume(""));
}
