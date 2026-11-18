//! Blocking native executor over the canonical restricted account-access flow.
use super::*;
use super::{AccountRecoveryHandle, AccountRecoveryPreparation};
use zann_core::api::account_access::{PasskeyMode, RecoveryView};
use zeroize::Zeroizing;
pub enum Request {
    Prepare {
        locator: String,
    },
    Consume {
        preparation: AccountRecoveryPreparation,
        confirmation: Zeroizing<String>,
        old_code: Zeroizing<String>,
    },
    Resume(AccountRecoveryHandle),
    RetryConsume {
        handle: AccountRecoveryHandle,
        old_code: Zeroizing<String>,
    },
    Enroll {
        restart: bool,
        handle: AccountRecoveryHandle,
        name: String,
        mode: PasskeyMode,
        password: Option<LoginPassword>,
        provider: Arc<dyn super::AccountCeremonyProvider>,
    },
}
pub enum ResultValue {
    Prepared {
        preparation: AccountRecoveryPreparation,
        pending: Vec<AccountRecoveryHandle>,
    },
    Consumed {
        handle: AccountRecoveryHandle,
        result: Result<Box<RecoveryView>, String>,
    },
    Completed,
}
pub struct RecoveryPlan {
    remote: Arc<Remote>,
    target: super::SessionTarget,
    operation: SessionOperation,
    request: Request,
}
impl Remote {
    pub fn recovery_plan(
        self: &Arc<Self>,
        id: OperationId,
        request: Request,
    ) -> Result<RecoveryPlan, String> {
        let mut state = self.state.lock().expect("Connect executor lock poisoned");
        if state.closed {
            return Err("connection flow was cancelled".into());
        }
        let target = state
            .prepared
            .as_ref()
            .ok_or("server connection has not been prepared")?
            .target()
            .clone();
        if let Some((_, cancel)) = state.active.take() {
            cancel.cancel();
        }
        let (operation, cancel) = SessionOperation::new(Instant::now() + Duration::from_secs(600));
        state.active = Some((id, cancel));
        Ok(RecoveryPlan {
            remote: self.clone(),
            target,
            operation,
            request,
        })
    }
}
impl RecoveryPlan {
    pub fn run(self) -> Result<ResultValue, String> {
        self.remote.runtime.block_on(async {
            let client = &self.remote.client;
            match self.request {
                Request::Prepare { locator } => {
                    let pending = client
                        .pending_account_recoveries(&self.target, &self.operation)
                        .await
                        .map_err(|e| e.to_string())?;
                    let preparation = client
                        .prepare_account_recovery(self.target, locator, self.operation)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(ResultValue::Prepared {
                        preparation,
                        pending,
                    })
                }
                Request::Consume {
                    preparation,
                    confirmation,
                    old_code,
                } => {
                    let (handle, result) = client
                        .arm_and_consume_account_recovery(
                            preparation,
                            confirmation,
                            old_code,
                            self.operation,
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    let result = result.map(Box::new).map_err(|e| e.to_string());
                    Ok(ResultValue::Consumed { handle, result })
                }
                Request::RetryConsume { handle, old_code } => {
                    let result = client
                        .consume_account_recovery(&handle, old_code, self.operation)
                        .await
                        .map(Box::new)
                        .map_err(|e| e.to_string());
                    Ok(ResultValue::Consumed { handle, result })
                }
                Request::Resume(handle) => {
                    let result = client
                        .resume_account_recovery(&handle, self.operation)
                        .await
                        .map(Box::new)
                        .map_err(|e| e.to_string());
                    Ok(ResultValue::Consumed { handle, result })
                }
                Request::Enroll {
                    restart,
                    handle,
                    name,
                    mode,
                    password,
                    provider,
                } => {
                    if restart {
                        client
                            .restart_recovery_passkey(
                                &handle,
                                name,
                                mode,
                                password,
                                provider,
                                self.operation,
                            )
                            .await
                    } else {
                        client
                            .enroll_recovery_passkey(
                                &handle,
                                name,
                                mode,
                                password,
                                provider,
                                self.operation,
                            )
                            .await
                    }
                    .map_err(|e| e.to_string())?;
                    Ok(ResultValue::Completed)
                }
            }
        })
    }
}
