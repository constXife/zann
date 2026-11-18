//! Restricted recovery authority never enters the ordinary session/token owner.
use super::*;
use crate::config::{
    v2::recovery::{RecoveryIntentPhase, RecoveryPreparation},
    VerifiedEndpointBinding,
};
use zeroize::Zeroizing;

pub struct AccountRecoveryPreparation {
    preparation: RecoveryPreparation,
    target: SessionTarget,
}
impl AccountRecoveryPreparation {
    pub fn successor_code(&self) -> &str {
        self.preparation.next_recovery_key()
    }
}
impl std::fmt::Debug for AccountRecoveryPreparation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountRecoveryPreparation(<redacted>)")
    }
}
#[derive(Clone, Debug)]
pub struct AccountRecoveryHandle {
    pub operation_id: Uuid,
    pub(super) target: SessionTarget,
    locator: String,
}
impl AppClient {
    pub(super) async fn recovery_endpoint(
        &self,
        target: &SessionTarget,
        operation: &SessionOperation,
    ) -> Result<VerifiedEndpointBinding, SessionError> {
        ensure_account_operation(operation)?;
        let failure =
            || SessionError::for_app(operation.operation_id(), SessionErrorKind::TrustInvalid);
        let snapshot = self
            .repository
            .snapshot()
            .map_err(|e| failure().with_source(e))?;
        let connection = snapshot
            .config()
            .connections
            .get(target.connection_id())
            .ok_or_else(failure)?;
        let metadata = connection.metadata().clone();
        let transport =
            AuthHttpTransport::new(&metadata.address).map_err(|e| failure().with_source(e))?;
        let info = transport
            .system_info()
            .await
            .map_err(|e| recovery_http_error(operation, e))?;
        let verified = crate::remote::trust::verify_and_bind_system_info(&metadata.address, info)
            .map_err(|e| failure().with_source(std::io::Error::other(e)))?;
        let binding = verified.binding();
        if metadata.server_id.as_deref() != Some(binding.server_id())
            || metadata.server_fingerprint.as_deref() != Some(binding.server_fingerprint())
        {
            return Err(failure());
        }
        let current = self
            .repository
            .snapshot()
            .map_err(|e| failure().with_source(e))?;
        if current
            .config()
            .connections
            .get(target.connection_id())
            .map(|c| c.metadata())
            != Some(&metadata)
        {
            return Err(failure());
        }
        ensure_account_operation(operation)?;
        Ok(binding.clone())
    }
    pub async fn prepare_account_recovery(
        &self,
        target: SessionTarget,
        locator: String,
        operation: SessionOperation,
    ) -> Result<AccountRecoveryPreparation, SessionError> {
        let endpoint = self.recovery_endpoint(&target, &operation).await?;
        let preparation = RecoveryPreparation::new(&endpoint, locator).map_err(|e| {
            SessionError::for_app(operation.operation_id(), SessionErrorKind::Configuration)
                .with_source(e)
        })?;
        Ok(AccountRecoveryPreparation {
            preparation,
            target,
        })
    }
    pub async fn arm_account_recovery(
        &self,
        mut plan: AccountRecoveryPreparation,
        confirmation: Zeroizing<String>,
        operation: SessionOperation,
    ) -> Result<AccountRecoveryHandle, SessionError> {
        let failure =
            || SessionError::for_app(operation.operation_id(), SessionErrorKind::Configuration);
        plan.preparation
            .confirm_saved(&confirmation)
            .map_err(|e| failure().with_source(e))?;
        let observed = self.recovery_endpoint(&plan.target, &operation).await?;
        if !plan.preparation.matches(&observed) {
            return Err(failure());
        }
        let intent = self
            .repository
            .prepare_recovery(&plan.preparation, self.credential_store.as_ref())
            .map_err(|e| failure().with_source(e))?;
        Ok(AccountRecoveryHandle {
            operation_id: intent.operation_id,
            target: plan.target,
            locator: intent.locator().into(),
        })
    }
    pub async fn arm_and_consume_account_recovery(
        &self,
        plan: AccountRecoveryPreparation,
        confirmation: Zeroizing<String>,
        old_code: Zeroizing<String>,
        operation: SessionOperation,
    ) -> Result<(AccountRecoveryHandle, Result<RecoveryView, SessionError>), SessionError> {
        let handle = self
            .arm_account_recovery(plan, confirmation, operation.detached_copy())
            .await?;
        let result = self
            .consume_account_recovery(&handle, old_code, operation)
            .await;
        Ok((handle, result))
    }
    pub async fn consume_account_recovery(
        &self,
        handle: &AccountRecoveryHandle,
        old_code: Zeroizing<String>,
        operation: SessionOperation,
    ) -> Result<RecoveryView, SessionError> {
        let failure =
            || SessionError::for_app(operation.operation_id(), SessionErrorKind::Protocol);
        let observed = self.recovery_endpoint(&handle.target, &operation).await?;
        let secrets = self
            .repository
            .recovery_secrets(
                handle.operation_id,
                &observed,
                self.credential_store.as_ref(),
            )
            .map_err(|e| failure().with_source(e))?;
        let device = match self
            .repository
            .recovery_dispatch_device(handle.operation_id, &observed)
            .map_err(|e| failure().with_source(e))?
        {
            Some(device) => device,
            None => self.session.recovery_device()?,
        };
        let input = RecoveryConsume {
            operation_id: handle.operation_id,
            locator: handle.locator.clone(),
            recovery_key: old_code.to_string(),
            next_recovery_key: secrets.next_recovery_key().into(),
            device: device.clone(),
        };
        let digest = input
            .digest(observed.server_id())
            .map_err(|e| failure().with_source(e))?;
        self.repository
            .mark_recovery_dispatched(handle.operation_id, &observed, digest, device)
            .map_err(|e| failure().with_source(e))?;
        let transport =
            AuthHttpTransport::new(observed.address()).map_err(|e| failure().with_source(e))?;
        ensure_account_operation(&operation)?;
        let receipt: RecoveryConsumeReceipt = transport
            .recovery_post(
                "v1/auth/recover",
                handle.operation_id,
                secrets.resume_token(),
                &input,
            )
            .await
            .map_err(|e| recovery_http_error(&operation, e))?;
        if receipt.operation_id != handle.operation_id {
            return Err(failure());
        }
        let view = self
            .resume_account_recovery(handle, operation.detached_copy())
            .await?;
        if RecoveryConsumeReceipt::from(&view.status).user_id != receipt.user_id
            || view.status.auth_epoch != receipt.auth_epoch
            || view.status.successor_code_version != receipt.successor_code_version
        {
            return Err(failure());
        }
        Ok(view)
    }
    pub async fn resume_account_recovery(
        &self,
        handle: &AccountRecoveryHandle,
        operation: SessionOperation,
    ) -> Result<RecoveryView, SessionError> {
        let failure =
            || SessionError::for_app(operation.operation_id(), SessionErrorKind::Protocol);
        let observed = self.recovery_endpoint(&handle.target, &operation).await?;
        let secrets = self
            .repository
            .recovery_secrets(
                handle.operation_id,
                &observed,
                self.credential_store.as_ref(),
            )
            .map_err(|e| failure().with_source(e))?;
        let transport =
            AuthHttpTransport::new(observed.address()).map_err(|e| failure().with_source(e))?;
        // Resolve each durable public request with the exact mutation ID/body
        // before reading newer status. The saved code is injected only in memory.
        for pending in self
            .repository
            .pending_account_requests(handle.operation_id, &observed)
            .map_err(|e| failure().with_source(e))?
        {
            let prefix = format!("v1/auth/recover/{}/", handle.operation_id);
            let suffix = pending.path.strip_prefix(&prefix).ok_or_else(failure)?;
            if !matches!(
                suffix,
                "credential/options" | "credential/finish" | "complete" | "abandon"
            ) {
                return Err(failure());
            }
            use crate::account_access::intents::PublicRequest;
            ensure_account_operation(&operation)?;
            let reply: RecoveryStepReply = match &pending.public_body {
                PublicRequest::RecoveryComplete {
                    mutation_id,
                    expected_revision,
                    successor_code_version,
                } if suffix == "complete" => {
                    transport
                        .recovery_post(
                            &pending.path,
                            handle.operation_id,
                            secrets.resume_token(),
                            &RecoveryComplete {
                                mutation_id: *mutation_id,
                                expected_revision: *expected_revision,
                                successor_code_version: *successor_code_version,
                                next_recovery_key: secrets.next_recovery_key().into(),
                            },
                        )
                        .await
                }
                PublicRequest::RecoveryOptions(input) if suffix == "credential/options" => {
                    transport
                        .recovery_post(
                            &pending.path,
                            handle.operation_id,
                            secrets.resume_token(),
                            input,
                        )
                        .await
                }
                PublicRequest::RecoveryFinish(input) if suffix == "credential/finish" => {
                    transport
                        .recovery_post(
                            &pending.path,
                            handle.operation_id,
                            secrets.resume_token(),
                            input,
                        )
                        .await
                }
                PublicRequest::RecoveryAbandon(input) if suffix == "abandon" => {
                    transport
                        .recovery_post(
                            &pending.path,
                            handle.operation_id,
                            secrets.resume_token(),
                            input,
                        )
                        .await
                }
                _ => return Err(failure()),
            }
            .map_err(|e| self.account_request_error(pending.id, &operation, e))?;
            self.repository
                .finish_account_request(pending.id, reply.public_receipt())
                .map_err(|e| failure().with_source(e))?;
        }
        ensure_account_operation(&operation)?;
        let view: RecoveryView = transport
            .recovery_get(
                &format!("v1/auth/recover/{}", handle.operation_id),
                handle.operation_id,
                secrets.resume_token(),
            )
            .await
            .map_err(|e| recovery_http_error(&operation, e))?;
        self.repository
            .observe_recovery(handle.operation_id, &observed, view.status.clone())
            .map_err(|e| failure().with_source(e))?;
        Ok(view)
    }
    pub async fn pending_account_recoveries(
        &self,
        target: &SessionTarget,
        operation: &SessionOperation,
    ) -> Result<Vec<AccountRecoveryHandle>, SessionError> {
        let op = SessionOperationId::new();
        let failure = || SessionError::for_app(op, SessionErrorKind::Configuration);
        let endpoint = self.recovery_endpoint(target, operation).await?;
        Ok(self
            .repository
            .pending_recoveries()
            .map_err(|e| failure().with_source(e))?
            .into_iter()
            .filter(|i| i.matches(&endpoint) && i.phase != RecoveryIntentPhase::Stopped)
            .map(|i| AccountRecoveryHandle {
                operation_id: i.operation_id,
                target: target.clone(),
                locator: i.locator().into(),
            })
            .collect())
    }
}

pub(super) fn recovery_http_error(
    operation: &SessionOperation,
    error: crate::remote::auth::AuthHttpError,
) -> SessionError {
    SessionError::from_http_for_app(operation.operation_id(), &error).with_source(error)
}
