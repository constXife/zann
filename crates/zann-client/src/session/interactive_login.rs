//! One token-publication path for password and discoverable passkey login.
use super::*;
impl TokenManager {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn complete_interactive_login(
        &self,
        locks: HeldSessionLocks,
        permit: InteractiveLoginIntentPermit,
        prelogin_identity: Option<ConfigIdentity>,
        target: SessionTarget,
        port: Arc<dyn AuthPort>,
        verified: EndpointIdentity,
        storage_id: Option<String>,
        operation: SessionOperation,
        cleanup_deferred: bool,
        auth_method: AuthMethod,
        response: LoginResponse,
    ) -> Result<SessionAccess, SessionError> {
        let LoginResponse {
            access_token,
            refresh_token,
            expires_in,
        } = response;
        let access = CredentialSecret::new(access_token);
        let refresh = CredentialSecret::new(refresh_token);
        let expires_at = checked_expiry(self.inner.clock.now(), expires_in);
        let (access, refresh, expires_at) = match (access, refresh, expires_at) {
            (Ok(access), Ok(refresh), Some(expires_at)) => (access, refresh, expires_at),
            (_, refresh, _) => {
                let refresh = refresh.ok();
                let remote_outcome_unknown = refresh.is_none();
                return self
                    .finish_failed_password_login(
                        locks,
                        refresh.as_ref(),
                        &port,
                        &operation,
                        if remote_outcome_unknown {
                            SessionErrorKind::SessionLostRemoteUnknown
                        } else {
                            SessionErrorKind::Protocol
                        },
                        None,
                        None,
                        cleanup_deferred || remote_outcome_unknown,
                    )
                    .await;
            }
        };
        if let Some(kind) = operation.pre_dispatch_error() {
            return self
                .finish_failed_password_login(
                    locks,
                    Some(&refresh),
                    &port,
                    &operation,
                    kind,
                    None,
                    None,
                    cleanup_deferred,
                )
                .await;
        }
        enum MeResult {
            Completed(Box<Result<Identity, AuthFailure>>),
            Cancelled,
            Deadline,
        }
        let deadline = tokio::time::Instant::from_std(operation.deadline);
        let me = tokio::select! {
            biased;
            _ = operation.cancelled() => MeResult::Cancelled,
            _ = tokio::time::sleep_until(deadline) => MeResult::Deadline,
            result = port.me(access.expose_secret()) => MeResult::Completed(Box::new(result)),
        };
        let identity = match me {
            MeResult::Completed(result) => match *result {
                Ok(identity) => identity,
                Err(failure) => {
                    return self
                        .finish_failed_password_login(
                            locks,
                            Some(&refresh),
                            &port,
                            &operation,
                            failure.kind.session_error_kind(),
                            failure.status,
                            failure.server_code,
                            cleanup_deferred,
                        )
                        .await;
                }
            },
            MeResult::Cancelled => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::Cancelled,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
            MeResult::Deadline => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::DeadlineExceeded,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        if !matches!(
            (auth_method, &identity.source),
            (AuthMethod::Password, AuthSource::Internal)
                | (AuthMethod::Passkey, AuthSource::Passkey)
        ) {
            return self
                .finish_failed_password_login(
                    locks,
                    Some(&refresh),
                    &port,
                    &operation,
                    SessionErrorKind::TransportRejected,
                    None,
                    None,
                    cleanup_deferred,
                )
                .await;
        }
        let canonical_email = identity.email.clone();
        if canonical_email.is_empty()
            || canonical_email.trim() != canonical_email
            || canonical_email.len() > LOGIN_EMAIL_MAX_BYTES
        {
            return self
                .finish_failed_password_login(
                    locks,
                    Some(&refresh),
                    &port,
                    &operation,
                    SessionErrorKind::Protocol,
                    None,
                    None,
                    cleanup_deferred,
                )
                .await;
        }
        enum ConfirmedPreloginResult {
            Completed(Result<PreloginResponse, AuthFailure>),
            Cancelled,
            Deadline,
        }
        let deadline = tokio::time::Instant::from_std(operation.deadline);
        let confirmed_prelogin = tokio::select! {
            biased;
            _ = operation.cancelled() => ConfirmedPreloginResult::Cancelled,
            _ = tokio::time::sleep_until(deadline) => ConfirmedPreloginResult::Deadline,
            result = port.prelogin(&canonical_email) => ConfirmedPreloginResult::Completed(result),
        };
        let confirmed_prelogin = match confirmed_prelogin {
            ConfirmedPreloginResult::Completed(Ok(prelogin)) => prelogin,
            ConfirmedPreloginResult::Completed(Err(failure)) => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        failure.kind.session_error_kind(),
                        failure.status,
                        failure.server_code,
                        cleanup_deferred,
                    )
                    .await;
            }
            ConfirmedPreloginResult::Cancelled => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::Cancelled,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
            ConfirmedPreloginResult::Deadline => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::DeadlineExceeded,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        let authenticated_identity = match password_login_identity_from_prelogin(
            confirmed_prelogin,
            Some(canonical_email),
        ) {
            Ok(identity) => identity,
            Err(kind) => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        kind,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        if prelogin_identity.as_ref().is_some_and(|preflight| {
            !password_login_kdf_is_coherent(preflight, &authenticated_identity)
        }) {
            return self
                .finish_failed_password_login(
                    locks,
                    Some(&refresh),
                    &port,
                    &operation,
                    SessionErrorKind::Protocol,
                    None,
                    None,
                    cleanup_deferred,
                )
                .await;
        }
        if let Some(kind) = operation.pre_dispatch_error() {
            return self
                .finish_failed_password_login(
                    locks,
                    Some(&refresh),
                    &port,
                    &operation,
                    kind,
                    None,
                    None,
                    cleanup_deferred,
                )
                .await;
        }
        let account_subject = identity.user_id.to_string();
        let access_copy = match copy_secret(&access) {
            Ok(secret) => secret,
            Err(_) => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::Internal,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        let refresh_copy = match copy_secret(&refresh) {
            Ok(secret) => secret,
            Err(_) => {
                return self
                    .finish_failed_password_login(
                        locks,
                        Some(&refresh),
                        &port,
                        &operation,
                        SessionErrorKind::Internal,
                        None,
                        None,
                        cleanup_deferred,
                    )
                    .await;
            }
        };
        let expires_at_wire = expires_at.to_rfc3339_opts(SecondsFormat::Secs, true);
        let repository = self.inner.repository.clone();
        let store = self.inner.credential_store.clone();
        let subject_for_commit = account_subject.clone();
        let operation_for_commit = operation.detached_copy();
        let (locks, (committed, permit)) = run_with_locks(locks, move || {
            let mut permit = permit;
            let committed = repository.commit_login_after_auth_intent_with_operation_locks(
                &mut permit,
                &subject_for_commit,
                authenticated_identity,
                access_copy,
                refresh_copy,
                expires_at_wire,
                store.as_ref(),
                || operation_for_commit.pre_dispatch_error().is_some(),
            );
            (committed, permit)
        })
        .await
        .map_err(|_| SessionError::new(&operation, SessionErrorKind::RecoveryRequired))?;
        match committed {
            Ok(outcome) => {
                let cleanup_deferred = cleanup_deferred || outcome_has_warnings(&outcome);
                let (locks, authorized_target_generation) = self
                    .generation_from_snapshot(
                        locks,
                        outcome.snapshot().clone(),
                        &target,
                        &operation,
                    )
                    .await?;
                drop(locks);
                Ok(password_login_access(
                    &target,
                    &verified,
                    &operation,
                    PasswordLoginAccess {
                        auth_method,
                        storage_id: storage_id.clone(),
                        account_subject,
                        expires_at,
                        access_secret: access,
                        cleanup_deferred,
                        authorized_target_generation,
                    },
                ))
            }
            Err(commit_error) => {
                self.finish_password_login_commit_failure(
                    locks,
                    permit,
                    &target,
                    &verified,
                    storage_id,
                    account_subject,
                    expires_at,
                    access,
                    refresh,
                    port,
                    &operation,
                    cleanup_deferred,
                    commit_error,
                    auth_method,
                )
                .await
            }
        }
    }
}
