//! Journaled restricted HTTP and browser dispatch.
use super::*;
pub(super) struct RecoveryApi<'a> {
    pub(super) client: &'a AppClient,
    pub(super) handle: &'a AccountRecoveryHandle,
    pub(super) operation: &'a SessionOperation,
    pub(super) endpoint: VerifiedEndpointBinding,
    pub(super) secrets: zann_crypto::recovery::RecoverySecrets,
}
impl RecoveryApi<'_> {
    fn failure(&self) -> SessionError {
        SessionError::for_app(self.operation.operation_id(), SessionErrorKind::Protocol)
    }
    pub(super) async fn post<T: SecurityRequest>(
        &self,
        suffix: &str,
        input: &T,
    ) -> Result<RecoveryStepReply, SessionError> {
        let current = self
            .client
            .recovery_endpoint(&self.handle.target, self.operation)
            .await?;
        if current != self.endpoint {
            return Err(self.failure());
        }
        let transport =
            AuthHttpTransport::new(current.address()).map_err(|e| self.failure().with_source(e))?;
        let intent = self
            .client
            .repository
            .stage_account_request(
                current.clone(),
                Some(self.handle.operation_id),
                &format!("v1/auth/recover/{}/{suffix}", self.handle.operation_id),
                input.public_request(),
            )
            .map_err(|e| self.failure().with_source(e))?;
        ensure_account_operation(self.operation)?;
        let reply: RecoveryStepReply = transport
            .recovery_post(
                &format!("v1/auth/recover/{}/{suffix}", self.handle.operation_id),
                self.handle.operation_id,
                self.secrets.resume_token(),
                input,
            )
            .await
            .map_err(|e| {
                self.client
                    .account_request_error(intent.id, self.operation, e)
            })?;
        self.client
            .repository
            .finish_account_request(intent.id, reply.public_receipt())
            .map_err(|e| self.failure().with_source(e))?;
        self.client
            .repository
            .observe_recovery(self.handle.operation_id, &current, reply.status.clone())
            .map_err(|e| self.failure().with_source(e))?;
        Ok(reply)
    }
    pub(super) async fn ceremony(
        &self,
        provider: &dyn AccountCeremonyProvider,
        options: CeremonyOptions,
        require_prf: bool,
    ) -> Result<AccountCeremonyResult, SessionError> {
        crate::session::perform_account_ceremony(
            provider,
            (&self.endpoint).into(),
            options,
            require_prf,
            self.operation,
        )
        .await
    }
}
