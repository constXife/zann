use super::*;
/// Fresh authorization for binding the first custody descriptor. A bearer alone
/// cannot select one. Later enrollment uses the established local custody key.
pub enum PasskeyEnrollmentAuthorization {
    ServerPassword(LoginPassword),
    ExistingPasskey,
    EstablishedCustody,
}
impl AppClient {
    #[allow(clippy::too_many_arguments)]
    pub async fn enroll_account_passkey(
        &self,
        target: &SessionTarget,
        root: &SecretKey,
        keyring: &unlock::DeviceUnlock,
        name: String,
        mode: PasskeyMode,
        authorization: PasskeyEnrollmentAuthorization,
        provider: Arc<dyn AccountCeremonyProvider>,
        operation: SessionOperation,
    ) -> Result<SecurityReceipt, SessionError> {
        let api = AccountApi::new(self, target, &operation)?;
        let failure =
            || SessionError::for_app(operation.operation_id(), SessionErrorKind::Protocol);
        let envelope = keyring.accounts.get(&api.storage).ok_or_else(failure)?;
        if envelope.server_id != api.server || envelope.account_subject != api.subject {
            return Err(failure());
        }
        let (key, origin) = keyring
            .account_key(root, &api.storage)
            .map_err(|e| failure().with_source(e))?;
        let mut security = self
            .account_security(target, operation.detached_copy())
            .await?;
        if security.user_id.to_string() != api.subject {
            return Err(failure());
        }
        let personal = api.access().await?.personal_vaults_enabled();
        let descriptor = if personal {
            if origin != AccountKeyOrigin::AccountPassword
                || self
                    .verify_account_key(target, &key, operation.detached_copy())
                    .await
                    .map_err(|e| failure().with_source(e))?
                    != AccountKeyCheck::Matches
            {
                return Err(failure());
            }
            let custody = AccountCustody::derive(&key, &api.server, security.user_id, 1)
                .map_err(|e| failure().with_source(e))?;
            let proposed = custody.descriptor(&api.server, security.user_id, 1);
            if let Some(existing) = &security.descriptor {
                custody
                    .proves(existing)
                    .map_err(|e| failure().with_source(e))?;
                if existing != &proposed {
                    return Err(failure());
                }
            } else {
                let proof = match &authorization {
                    PasskeyEnrollmentAuthorization::ServerPassword(password) => {
                        ManagementProof::InitialPassword {
                            server_password: password.expose().to_owned(),
                        }
                    }
                    PasskeyEnrollmentAuthorization::ExistingPasskey => {
                        api.uv(
                            provider.as_ref(),
                            security.security_revision,
                            UvAuthorizationIntent::Descriptor {
                                descriptor: proposed.clone(),
                            },
                        )
                        .await?
                    }
                    PasskeyEnrollmentAuthorization::EstablishedCustody => return Err(failure()),
                };
                security = api
                    .post(
                        "v1/users/me/security/descriptor",
                        &DescriptorBootstrap {
                            operation_id: Uuid::new_v4(),
                            expected_revision: security.security_revision,
                            descriptor: proposed.clone(),
                            proof,
                        },
                    )
                    .await?;
                if security.descriptor.as_ref() != Some(&proposed) {
                    return Err(failure());
                }
            }
            Some(proposed)
        } else {
            if mode == PasskeyMode::VaultUnlock || origin != AccountKeyOrigin::LocalCacheKey {
                return Err(failure());
            }
            None
        };
        let request = EnrollmentRequest {
            operation_id: Uuid::new_v4(),
            expected_revision: security.security_revision,
            name,
            mode,
        };
        let options: CeremonyOptions = api.post("v1/users/me/passkeys/options", &request).await?;
        if options.operation_id != request.operation_id
            || options.phase != CeremonyPhase::Register
            || options.user_id != Some(security.user_id)
        {
            return Err(failure());
        }
        let registered = api
            .ceremony(provider.as_ref(), options, mode == PasskeyMode::VaultUnlock)
            .await?;
        let credential_id = registered.response.credential_id().to_owned();
        // Registration PRF is not needed; only the independently tested assertion
        // establishes that the newly created resident credential can unlock.
        drop(registered.prf);
        let options: CeremonyOptions = api
            .post(
                "v1/users/me/passkeys/register",
                &CeremonyFinish {
                    operation_id: request.operation_id,
                    response: registered.response,
                },
            )
            .await?;
        if options.phase != CeremonyPhase::Test
            || options.operation_id != request.operation_id
            || !options.credential_ids.is_empty()
        {
            return Err(failure());
        }
        let rp_id = options.rp_id.clone();
        let tested = api
            .ceremony(provider.as_ref(), options, mode == PasskeyMode::VaultUnlock)
            .await?;
        if tested.response.credential_id() != credential_id {
            return Err(failure());
        }
        let receipt: CandidateReceipt = api
            .post(
                "v1/users/me/passkeys/test",
                &CeremonyFinish {
                    operation_id: request.operation_id,
                    response: tested.response,
                },
            )
            .await?;
        if receipt.operation_id != request.operation_id
            || receipt.credential_id != credential_id
            || receipt.mode != mode
            || !receipt.tested
        {
            return Err(failure());
        }
        if mode == PasskeyMode::VaultUnlock {
            let descriptor = descriptor.as_ref().ok_or_else(failure)?;
            let prf = tested.prf.ok_or_else(failure)?.into_account_prf();
            let grant =
                AccountGrant::create(descriptor, rp_id, credential_id, Uuid::new_v4(), &key, &prf)
                    .map_err(|e| failure().with_source(e))?;
            drop(prf);
            let proof = api
                .custody(
                    &key,
                    descriptor,
                    security.security_revision,
                    MutationPurpose::GrantAdd,
                    grant.body_digest().map_err(|e| failure().with_source(e))?,
                )
                .await?;
            let staged: CandidateReceipt = api
                .post(
                    "v1/users/me/passkeys/grant",
                    &StageGrant {
                        operation_id: request.operation_id,
                        grant,
                        proof,
                    },
                )
                .await?;
            if staged.receipt_id != receipt.receipt_id {
                return Err(failure());
            }
        }
        let digest = receipt
            .activation_digest()
            .map_err(|e| failure().with_source(e))?;
        let proof = if let Some(descriptor) = &descriptor {
            ManagementProof::Custody {
                proof: api
                    .custody(
                        &key,
                        descriptor,
                        security.security_revision,
                        MutationPurpose::CredentialAdd,
                        digest,
                    )
                    .await?,
            }
        } else {
            // Shared-only bootstrap is explicitly authorized with a fresh server
            // password; subsequent credentials require an already enrolled UV key.
            match &authorization {
                PasskeyEnrollmentAuthorization::ServerPassword(password) => {
                    ManagementProof::InitialPassword {
                        server_password: password.expose().into(),
                    }
                }
                PasskeyEnrollmentAuthorization::ExistingPasskey => {
                    api.uv(
                        provider.as_ref(),
                        security.security_revision,
                        UvAuthorizationIntent::Mutation {
                            purpose: MutationPurpose::CredentialAdd,
                            body_digest: encode(&digest),
                        },
                    )
                    .await?
                }
                PasskeyEnrollmentAuthorization::EstablishedCustody => return Err(failure()),
            }
        };
        api.post(
            "v1/users/me/passkeys/activate",
            &ActivateCredential {
                operation_id: request.operation_id,
                expected_revision: security.security_revision,
                proof,
            },
        )
        .await
    }
}
impl AccountApi<'_> {
    pub(super) async fn uv(
        &self,
        provider: &dyn AccountCeremonyProvider,
        revision: i64,
        intent: UvAuthorizationIntent,
    ) -> Result<ManagementProof, SessionError> {
        let id = Uuid::new_v4();
        let options: CeremonyOptions = self
            .post(
                &format!("v1/users/me/security/uv/{id}/options"),
                &UvAuthorizationRequest {
                    expected_revision: revision,
                    intent,
                },
            )
            .await?;
        let result = self.ceremony(provider, options, false).await?;
        drop(result.prf);
        Ok(ManagementProof::ExistingPasskey {
            operation_id: id,
            response: result.response,
        })
    }
}
