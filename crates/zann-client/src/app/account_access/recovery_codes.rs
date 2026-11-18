//! Staged server recovery code: durable OS custody precedes explicit activation.
use super::*;
use crate::config::v2::RecoveryCodeCandidate;
use zeroize::Zeroizing;
pub struct AccountRecoveryCode {
    candidate: RecoveryCodeCandidate,
    target: SessionTarget,
    code: Zeroizing<String>,
}
impl AccountRecoveryCode {
    pub fn code(&self) -> &str {
        &self.code
    }
}
impl std::fmt::Debug for AccountRecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountRecoveryCode(<redacted>)")
    }
}
impl AppClient {
    pub async fn prepare_server_recovery_code(
        &self,
        target: &SessionTarget,
        operation: SessionOperation,
    ) -> Result<AccountRecoveryCode, SessionError> {
        let api = AccountApi::new(self, target, &operation)?;
        api.access().await?;
        let failure =
            || SessionError::for_app(operation.operation_id(), SessionErrorKind::Configuration);
        let security = self
            .account_security(target, operation.detached_copy())
            .await?;
        if security.credentials.is_empty() {
            return Err(failure());
        }
        let endpoint = self.recovery_endpoint(target, &operation).await?;
        let (candidate, code) = self
            .repository
            .prepare_recovery_code(
                endpoint,
                api.storage,
                api.subject,
                security.security_revision,
                security.recovery_candidate_id,
                self.credential_store.as_ref(),
            )
            .map_err(|e| failure().with_source(e))?;
        Ok(AccountRecoveryCode {
            candidate,
            target: target.clone(),
            code,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn activate_server_recovery_code(
        &self,
        candidate: &AccountRecoveryCode,
        confirmation: Zeroizing<String>,
        disable_password: bool,
        root: &SecretKey,
        keyring: &unlock::DeviceUnlock,
        provider: Arc<dyn AccountCeremonyProvider>,
        operation: SessionOperation,
    ) -> Result<SecurityReceipt, SessionError> {
        let api = AccountApi::new(self, &candidate.target, &operation)?;
        api.access().await?;
        let failure =
            || SessionError::for_app(operation.operation_id(), SessionErrorKind::Configuration);
        let endpoint = self
            .recovery_endpoint(&candidate.target, &operation)
            .await?;
        let code = self
            .repository
            .confirmed_recovery_code(
                &candidate.candidate,
                &endpoint,
                &api.storage,
                &api.subject,
                &confirmation,
                self.credential_store.as_ref(),
            )
            .map_err(|e| failure().with_source(e))?;
        let security = self
            .account_security(&candidate.target, operation.detached_copy())
            .await?;
        let digest = ActivateRecoveryCode::body_digest(
            candidate.candidate.id,
            code.expose_secret(),
            disable_password,
        )
        .map_err(|e| failure().with_source(e))?;
        let proof = if let Some(saved) = self
            .repository
            .recovery_code_request(
                candidate.candidate.id,
                &endpoint,
                security.recovery_candidate_id == Some(candidate.candidate.id),
            )
            .map_err(|e| failure().with_source(e))?
        {
            let crate::account_access::intents::PublicRequest::Code {
                candidate_id,
                expected_revision,
                disable_password: saved_disable,
                body_digest,
                proof,
            } = saved
            else {
                return Err(failure());
            };
            if candidate_id != candidate.candidate.id
                || expected_revision != candidate.candidate.revision
                || saved_disable != disable_password
                || body_digest != encode(&digest)
            {
                return Err(failure());
            }
            proof.replay().ok_or_else(failure)?
        } else {
            if security.security_revision != candidate.candidate.revision {
                return Err(failure());
            }
            api.management_proof(
                root,
                keyring,
                &security,
                provider.as_ref(),
                MutationPurpose::CodeRotate,
                digest,
            )
            .await?
        };
        let receipt: SecurityReceipt = api
            .post(
                "v1/users/me/security/recovery-code/activate",
                &ActivateRecoveryCode {
                    candidate_id: candidate.candidate.id,
                    expected_revision: candidate.candidate.revision,
                    recovery_key: code.expose_secret().into(),
                    disable_password,
                    proof,
                },
            )
            .await?;
        if receipt.mutation_id != candidate.candidate.id
            || receipt.recovery_candidate_id != Some(candidate.candidate.id)
            || receipt.recovery_key_version.is_none()
        {
            return Err(failure());
        }
        self.repository
            .forget_activated_recovery_code(candidate.candidate.id, self.credential_store.as_ref())
            .map_err(|e| failure().with_source(e))?;
        Ok(receipt)
    }
}
