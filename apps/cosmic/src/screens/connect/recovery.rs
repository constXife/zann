//! Recovery form adapter: secret drafts and effect execution only. Wizard
//! policy lives in `zann_flows::recovery`; the client owns custody and replay.
use super::*;
use crate::backend::remote::recovery::{Request, ResultValue};
mod view;
use zann_client::app::{AccountRecoveryHandle, AccountRecoveryPreparation, LoginPassword};
use zann_core::api::account_access::{PasskeyMode, RecoveryView};
use zann_flows::recovery::{
    AccountRecovery, Action, Candidate, Consumed, Effect, Failure, Progress, Reply,
};
use zeroize::{Zeroize, Zeroizing};

pub(super) struct Preparation(AccountRecoveryPreparation);
impl zann_flows::recovery::Preparation for Preparation {
    fn successor_code(&self) -> &str {
        self.0.successor_code()
    }
}
type Flow = AccountRecovery<Preparation, AccountRecoveryHandle>;

pub(super) struct Recovery {
    flow: Flow,
    old_code: String,
    confirmation: String,
    password: String,
}
#[derive(Clone)]
pub enum Message {
    Open,
    Back,
    Locator(String),
    OldCode(String),
    Confirmation(String),
    Password(String),
    Name(String),
    AuthOnly(bool),
    Restart(bool),
    Prepare,
    Consume,
    RetryConsume,
    ResumeCurrent,
    ResumePending(usize),
    Continue(String),
    Finished(
        zann_flows::OperationId,
        Arc<std::sync::Mutex<Option<Result<ResultValue, String>>>>,
    ),
}
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountRecoveryMessage(<redacted>)")
    }
}
impl State {
    pub(super) fn update_recovery(&mut self, message: Message) -> Vec<Outcome> {
        if matches!(message, Message::Open) {
            if zann_flows::recovery::can_open(self.flow.snapshot()) {
                self.recovery = Some(Recovery {
                    flow: Flow::new(next_view_request()),
                    old_code: String::new(),
                    confirmation: String::new(),
                    password: String::new(),
                });
            }
            return vec![];
        }
        let Some(recovery) = &mut self.recovery else {
            return vec![];
        };
        let busy = recovery.flow.snapshot().busy;
        let action = match message {
            Message::Open => return vec![],
            Message::Finished(id, result) => {
                let Some(result) = result.lock().expect("recovery reply lock poisoned").take()
                else {
                    return vec![];
                };
                recovery.flow.complete(id, reply(result));
                return vec![];
            }
            Message::OldCode(value) | Message::Confirmation(value) | Message::Password(value)
                if busy =>
            {
                drop(Zeroizing::new(value));
                return vec![];
            }
            Message::OldCode(value) => {
                replace_secret(&mut recovery.old_code, value);
                return vec![];
            }
            Message::Confirmation(value) => {
                replace_secret(&mut recovery.confirmation, value);
                return vec![];
            }
            Message::Password(value) => {
                replace_secret(&mut recovery.password, value);
                return vec![];
            }
            Message::Consume => {
                let effects = recovery.flow.dispatch(Action::Consume {
                    confirmation: &recovery.confirmation,
                });
                return self.execute_recovery(effects);
            }
            Message::Continue(pairing) => {
                if self.control.is_none() || !self.pairings.iter().any(|p| p.public_key == pairing)
                {
                    return vec![];
                }
                Action::Enroll { pairing }
            }
            Message::Back => Action::Back,
            Message::Locator(value) => Action::SetLocator(value),
            Message::Name(value) => Action::SetName(value),
            Message::AuthOnly(auth_only) => Action::SetMode(if auth_only {
                PasskeyMode::AuthOnly
            } else {
                PasskeyMode::VaultUnlock
            }),
            Message::Restart(value) => Action::SetRestart(value),
            Message::Prepare => Action::Prepare,
            Message::RetryConsume => Action::RetryConsume,
            Message::ResumeCurrent => Action::ResumeCurrent,
            Message::ResumePending(index) => Action::ResumePending(index),
        };
        let effects = recovery.flow.dispatch(action);
        self.execute_recovery(effects)
    }

    fn execute_recovery(
        &mut self,
        effects: Vec<Effect<Preparation, AccountRecoveryHandle>>,
    ) -> Vec<Outcome> {
        let mut outcomes = Vec::new();
        for effect in effects {
            let Some(recovery) = &mut self.recovery else {
                break;
            };
            let (id, request) = match effect {
                Effect::Cancel { id } => {
                    if let Some(remote) = &self.remote {
                        remote.cancel(id);
                    }
                    continue;
                }
                Effect::Closed => {
                    self.recovery = None;
                    continue;
                }
                Effect::Prepare { id, locator } => (id, Ok(Request::Prepare { locator })),
                Effect::Consume { id, preparation } => (
                    id,
                    Ok(Request::Consume {
                        preparation: preparation.0,
                        confirmation: take_secret(&mut recovery.confirmation),
                        old_code: take_secret(&mut recovery.old_code),
                    }),
                ),
                Effect::RetryConsume { id, handle } => (
                    id,
                    Ok(Request::RetryConsume {
                        handle,
                        old_code: take_secret(&mut recovery.old_code),
                    }),
                ),
                Effect::Resume { id, handle } => (id, Ok(Request::Resume(handle))),
                Effect::Enroll {
                    id,
                    handle,
                    restart,
                    name,
                    mode,
                    pairing,
                } => {
                    let password = match mode {
                        PasskeyMode::AuthOnly => Ok(None),
                        PasskeyMode::VaultUnlock => {
                            LoginPassword::new(std::mem::take(&mut recovery.password))
                                .map(Some)
                                .map_err(|error| error.to_string())
                        }
                    };
                    let request = match (password, &self.control) {
                        (Ok(password), Some(control)) => Ok(Request::Enroll {
                            restart,
                            handle,
                            name,
                            mode,
                            password,
                            provider: control.account_ceremony_provider(pairing),
                        }),
                        (Err(error), _) => Err(error),
                        (Ok(_), None) => Err("browser control is unavailable".to_owned()),
                    };
                    (id, request)
                }
            };
            let plan = request.and_then(|request| {
                self.remote()
                    .and_then(|remote| remote.recovery_plan(id, request))
            });
            match plan {
                Ok(plan) => {
                    let generation = self.generation;
                    outcomes.push(Outcome::Task(Task::future(async move {
                        let result = off_thread(move || plan.run()).await;
                        Event {
                            generation,
                            message: super::Message::Recovery(Message::Finished(
                                id,
                                Arc::new(std::sync::Mutex::new(Some(result))),
                            )),
                        }
                    })));
                }
                Err(error) => {
                    if let Some(recovery) = &mut self.recovery {
                        recovery.flow.complete(id, Err(Failure::Message(error)));
                    }
                }
            }
        }
        outcomes
    }
}

fn reply(
    result: Result<ResultValue, String>,
) -> Result<Reply<Preparation, AccountRecoveryHandle>, Failure> {
    Ok(match result.map_err(Failure::Message)? {
        ResultValue::Prepared {
            preparation,
            pending,
        } => Reply::Prepared {
            preparation: Preparation(preparation),
            pending,
        },
        ResultValue::Consumed { handle, result } => Reply::Consumed(Consumed {
            handle,
            progress: result.map(progress).map_err(Failure::Message),
        }),
        ResultValue::Completed => Reply::Enrolled,
    })
}

fn progress(view: Box<RecoveryView>) -> Progress {
    let view = *view;
    Progress {
        state: view.status.state,
        candidate: view.candidate.map(|candidate| Candidate {
            name: candidate.name,
            mode: candidate.mode,
        }),
    }
}

fn replace_secret(draft: &mut String, value: String) {
    draft.zeroize();
    *draft = value;
}

fn take_secret(draft: &mut String) -> Zeroizing<String> {
    Zeroizing::new(std::mem::take(draft))
}

impl Drop for Recovery {
    fn drop(&mut self) {
        self.old_code.zeroize();
        self.confirmation.zeroize();
        self.password.zeroize();
    }
}
