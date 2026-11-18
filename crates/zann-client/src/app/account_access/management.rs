use super::*;
impl AppClient {
    pub async fn revoke_account_passkey(
        &self,
        target: &SessionTarget,
        root: &SecretKey,
        keyring: &unlock::DeviceUnlock,
        credential_id: String,
        provider: Arc<dyn AccountCeremonyProvider>,
        operation: SessionOperation,
    ) -> Result<SecurityReceipt, SessionError> {
        let api = AccountApi::new(self, target, &operation)?;
        let security = self
            .account_security(target, operation.detached_copy())
            .await?;
        let digest = RevokeCredential::body_digest(&credential_id, true).map_err(|e| {
            SessionError::for_app(operation.operation_id(), SessionErrorKind::Protocol)
                .with_source(e)
        })?;
        let proof = api
            .management_proof(
                root,
                keyring,
                &security,
                provider.as_ref(),
                MutationPurpose::CredentialRevoke,
                digest,
            )
            .await?;
        let input = RevokeCredential {
            mutation_id: Uuid::new_v4(),
            expected_revision: security.security_revision,
            credential_id,
            revoke_sessions: true,
            proof,
        };
        api.post("v1/users/me/passkeys/revoke", &input).await
    }
}
impl AccountApi<'_> {
    pub(super) async fn management_proof(
        &self,
        root: &SecretKey,
        keyring: &unlock::DeviceUnlock,
        security: &AccountSecurity,
        provider: &dyn AccountCeremonyProvider,
        purpose: MutationPurpose,
        digest: [u8; 32],
    ) -> Result<ManagementProof, SessionError> {
        let failure =
            || SessionError::for_app(self.operation.operation_id(), SessionErrorKind::Protocol);
        if self.access().await?.personal_vaults_enabled() {
            let descriptor = security.descriptor.as_ref().ok_or_else(failure)?;
            let entry = keyring.accounts.get(&self.storage).ok_or_else(failure)?;
            if entry.server_id != self.server || entry.account_subject != self.subject {
                return Err(failure());
            }
            let (key, origin) = keyring
                .account_key(root, &self.storage)
                .map_err(|e| failure().with_source(e))?;
            if origin != AccountKeyOrigin::AccountPassword
                || self
                    .client
                    .verify_account_key(self.target, &key, self.operation.detached_copy())
                    .await
                    .map_err(|e| failure().with_source(e))?
                    != AccountKeyCheck::Matches
            {
                return Err(failure());
            }
            Ok(ManagementProof::Custody {
                proof: self
                    .custody(
                        &key,
                        descriptor,
                        security.security_revision,
                        purpose,
                        digest,
                    )
                    .await?,
            })
        } else {
            self.uv(
                provider,
                security.security_revision,
                UvAuthorizationIntent::Mutation {
                    purpose,
                    body_digest: encode(&digest),
                },
            )
            .await
        }
    }
}
