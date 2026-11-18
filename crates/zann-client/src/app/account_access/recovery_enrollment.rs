//! Replacement credential enrollment under the restricted recovery authority.
use super::recovery::AccountRecoveryHandle;
use super::*;
use crate::config::VerifiedEndpointBinding;

mod api;
use api::RecoveryApi;
impl AppClient {
    /// Continues the registered replacement candidate using a fresh test/PRF.
    /// A new registration is performed only when no credential was registered.
    #[allow(clippy::too_many_arguments)]
    pub async fn enroll_recovery_passkey(
        &self,
        handle: &AccountRecoveryHandle,
        name: String,
        mode: PasskeyMode,
        encryption_password: Option<LoginPassword>,
        provider: Arc<dyn AccountCeremonyProvider>,
        operation: SessionOperation,
    ) -> Result<RecoveryStepReply, SessionError> {
        self.recovery_passkey(
            handle,
            name,
            mode,
            encryption_password,
            provider,
            operation,
            false,
        )
        .await
    }
    /// Explicitly supersedes the staged candidate, requiring a new registration.
    #[allow(clippy::too_many_arguments)]
    pub async fn restart_recovery_passkey(
        &self,
        handle: &AccountRecoveryHandle,
        name: String,
        mode: PasskeyMode,
        encryption_password: Option<LoginPassword>,
        provider: Arc<dyn AccountCeremonyProvider>,
        operation: SessionOperation,
    ) -> Result<RecoveryStepReply, SessionError> {
        self.recovery_passkey(
            handle,
            name,
            mode,
            encryption_password,
            provider,
            operation,
            true,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn recovery_passkey(
        &self,
        handle: &AccountRecoveryHandle,
        name: String,
        mode: PasskeyMode,
        encryption_password: Option<LoginPassword>,
        provider: Arc<dyn AccountCeremonyProvider>,
        operation: SessionOperation,
        restart: bool,
    ) -> Result<RecoveryStepReply, SessionError> {
        let endpoint = self.recovery_endpoint(&handle.target, &operation).await?;
        let failure =
            || SessionError::for_app(operation.operation_id(), SessionErrorKind::Protocol);
        let secrets = self
            .repository
            .recovery_secrets(
                handle.operation_id,
                &endpoint,
                self.credential_store.as_ref(),
            )
            .map_err(|e| failure().with_source(e))?;
        let api = RecoveryApi {
            client: self,
            handle,
            operation: &operation,
            endpoint,
            secrets,
        };
        let view = self
            .resume_account_recovery(handle, operation.detached_copy())
            .await?;
        if view.status.state.is_terminal() {
            return Err(failure());
        }
        let key = if mode == PasskeyMode::VaultUnlock {
            let password = encryption_password.ok_or_else(failure)?;
            let descriptor = view.descriptor.as_ref().ok_or_else(failure)?;
            if descriptor.server_id != api.endpoint.server_id()
                || descriptor.user_id != view.status.user_id
                || Some(descriptor.key_epoch as i64) != view.status.account_key_epoch
            {
                return Err(failure());
            }
            view.kdf
                .kdf_params
                .validate_policy()
                .map_err(|e| failure().with_source(std::io::Error::other(e)))?;
            if zann_crypto::passwords::kdf_fingerprint(
                &view.kdf.kdf_salt,
                &view.kdf.kdf_params.to_crypto_params(),
            )
            .map_err(|e| failure().with_source(std::io::Error::other(e)))?
                != view.kdf.salt_fingerprint
            {
                return Err(failure());
            }
            let bytes = zann_crypto::passwords::derive_auth_hash(
                password.expose(),
                &view.kdf.kdf_salt,
                &view.kdf.kdf_params.to_crypto_params(),
            )
            .map_err(|e| failure().with_source(std::io::Error::other(e)))?;
            drop(password);
            let key = SecretKey::from_bytes(bytes);
            let transport = AuthHttpTransport::new(api.endpoint.address())
                .map_err(|e| failure().with_source(e))?;
            let material: RecoveryKeyMaterial = transport
                .recovery_get(
                    &format!("v1/auth/recover/{}/data", handle.operation_id),
                    handle.operation_id,
                    api.secrets.resume_token(),
                )
                .await
                .map_err(|e| super::recovery::recovery_http_error(&operation, e))?;
            let envelope = material.personal.ok_or_else(failure)?;
            // Verify both existing personal ciphertext and immutable custody
            // identity before signing or producing any replacement envelope.
            let encrypted = zann_crypto::account_access::decode(&envelope.vault_key_enc, 65536)
                .map_err(|e| failure().with_source(e))?;
            zann_crypto::vault_crypto::decrypt_vault_key(&key, envelope.vault_id, &encrypted)
                .map_err(|e| failure().with_source(e))?;
            AccountCustody::derive(
                &key,
                api.endpoint.server_id(),
                descriptor.user_id,
                descriptor.key_epoch,
            )
            .and_then(|c| c.proves(descriptor))
            .map_err(|e| failure().with_source(e))?;
            Some(key)
        } else {
            drop(encryption_password);
            None
        };
        let (tested_options, credential) = if let Some(candidate) = view
            .candidate
            .as_ref()
            .filter(|_| !restart)
            .filter(|c| c.registered_credential_id.is_some())
        {
            if candidate.name != name || candidate.mode != mode {
                return Err(failure());
            }
            let options = api
                .post(
                    "credential/options",
                    &RecoveryCredentialOptions {
                        mutation_id: Uuid::new_v4(),
                        expected_revision: view.status.revision,
                        action: RecoveryOptionsPhase::Test,
                    },
                )
                .await?;
            (
                options,
                candidate
                    .registered_credential_id
                    .clone()
                    .ok_or_else(failure)?,
            )
        } else {
            let registered_options = api
                .post(
                    "credential/options",
                    &RecoveryCredentialOptions {
                        mutation_id: Uuid::new_v4(),
                        expected_revision: view.status.revision,
                        action: RecoveryOptionsPhase::Register { name, mode },
                    },
                )
                .await?;
            let RecoveryStepResult::Ceremony { options } = registered_options.result else {
                return Err(failure());
            };
            if options.phase != CeremonyPhase::Register
                || options.user_id != Some(view.status.user_id)
            {
                return Err(failure());
            }
            let response = api
                .ceremony(provider.as_ref(), options, mode == PasskeyMode::VaultUnlock)
                .await?;
            let credential = response.response.credential_id().to_owned();
            drop(response.prf);
            let tested_options = api
                .post(
                    "credential/finish",
                    &RecoveryCredentialFinish {
                        mutation_id: Uuid::new_v4(),
                        expected_revision: registered_options.status.revision,
                        action: RecoveryFinishPhase::Register {
                            response: response.response,
                        },
                    },
                )
                .await?;
            (tested_options, credential)
        };
        let RecoveryStepResult::Ceremony { options } = tested_options.result else {
            return Err(failure());
        };
        if options.phase != CeremonyPhase::Test || !options.credential_ids.is_empty() {
            return Err(failure());
        }
        let rp = options.rp_id.clone();
        let tested = api
            .ceremony(provider.as_ref(), options, mode == PasskeyMode::VaultUnlock)
            .await?;
        if tested.response.credential_id() != credential {
            return Err(failure());
        }
        let receipt = api
            .post(
                "credential/finish",
                &RecoveryCredentialFinish {
                    mutation_id: Uuid::new_v4(),
                    expected_revision: tested_options.status.revision,
                    action: RecoveryFinishPhase::Test {
                        response: tested.response,
                    },
                },
            )
            .await?;
        let RecoveryStepResult::Tested { receipt: bound } = &receipt.result else {
            return Err(failure());
        };
        if !bound.tested || bound.credential_id != credential || bound.mode != mode {
            return Err(failure());
        }
        let mut revision = receipt.status.revision;
        if let Some(key) = key {
            let descriptor = view.descriptor.as_ref().ok_or_else(failure)?;
            let prf = tested.prf.ok_or_else(failure)?.into_account_prf();
            let grant = if let Some(grant) = view.grant.as_ref().filter(|_| !restart) {
                if grant.rp_id != rp || grant.credential_id != credential {
                    return Err(failure());
                }
                let opened = grant
                    .open(descriptor, &prf)
                    .map_err(|e| failure().with_source(e))?;
                if !zann_crypto::tokens::constant_time_equal(opened.as_bytes(), key.as_bytes()) {
                    return Err(failure());
                }
                None
            } else {
                Some(
                    AccountGrant::create(descriptor, rp, credential, Uuid::new_v4(), &key, &prf)
                        .map_err(|e| failure().with_source(e))?,
                )
            };
            drop(prf);
            if let Some(grant) = grant {
                let digest = encode(&grant.body_digest().map_err(|e| failure().with_source(e))?);
                let nonce = api
                    .post(
                        "credential/options",
                        &RecoveryCredentialOptions {
                            mutation_id: Uuid::new_v4(),
                            expected_revision: revision,
                            action: RecoveryOptionsPhase::Grant {
                                body_digest: digest.clone(),
                            },
                        },
                    )
                    .await?;
                let RecoveryStepResult::Custody { context } = nonce.result else {
                    return Err(failure());
                };
                if context.server_id != api.endpoint.server_id()
                    || context.user_id != view.status.user_id
                    || context.authority != Authority::Recovery
                    || context.authority_id != handle.operation_id
                    || context.security_revision != view.security_revision as u64
                    || context.purpose != MutationPurpose::GrantAdd
                    || context.body_digest != digest
                {
                    return Err(failure());
                }
                let custody = AccountCustody::derive(
                    &key,
                    api.endpoint.server_id(),
                    descriptor.user_id,
                    descriptor.key_epoch,
                )
                .map_err(|e| failure().with_source(e))?;
                let signature = custody
                    .sign_mutation(descriptor, &context)
                    .map_err(|e| failure().with_source(e))?;
                let staged = api
                    .post(
                        "credential/finish",
                        &RecoveryCredentialFinish {
                            mutation_id: Uuid::new_v4(),
                            expected_revision: nonce.status.revision,
                            action: RecoveryFinishPhase::Grant {
                                grant: Box::new(grant),
                                proof: CustodyProof { context, signature },
                            },
                        },
                    )
                    .await?;
                if !matches!(staged.result, RecoveryStepResult::GrantReady { .. }) {
                    return Err(failure());
                }
                revision = staged.status.revision;
            }
        } else {
            drop(tested.prf);
        }
        let completed = api
            .post(
                "complete",
                &RecoveryComplete {
                    mutation_id: Uuid::new_v4(),
                    expected_revision: revision,
                    successor_code_version: view.status.successor_code_version,
                    next_recovery_key: api.secrets.next_recovery_key().into(),
                },
            )
            .await?;
        if !matches!(completed.result, RecoveryStepResult::Completed) {
            return Err(failure());
        }
        // The caller must perform a fresh ordinary discoverable login. A recovery
        // receipt never produces bearer tokens or unlocks a local root.
        Ok(completed)
    }
}
