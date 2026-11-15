//! Explicit account preparation over one endpoint trust owner.
use super::*;
use crate::config::v2::ReplicaReservation;

impl AppClient {
    /// Add an account, or reconnect this exact replica. Empty provisioning slots
    /// are reused; cancelled probes cannot consume the configured-account budget.
    pub async fn prepare_account_connection(
        &self,
        endpoint: &str,
        name: &str,
        reconnect_storage: Option<&str>,
    ) -> Result<PrepareConnectionOutcome, SessionError> {
        let operation = SessionOperationId::new();
        let failure = || SessionError::for_app(operation, SessionErrorKind::Configuration);
        let snapshot = self
            .repository
            .snapshot()
            .map_err(|e| failure().with_source(e))?;
        let owner = snapshot
            .config()
            .connection_for_address(endpoint)
            .map_err(|e| failure().with_source(e))?;
        if let Some(storage) = reconnect_storage {
            if let Some((id, profile)) = snapshot
                .config()
                .replica_profile(storage)
                .map_err(|e| failure().with_source(e))?
            {
                if owner != Some(id.clone()) {
                    return Err(failure());
                }
                return self
                    .prepare_connection(
                        endpoint,
                        &snapshot.config().connections[&id].metadata().name,
                        &profile,
                    )
                    .await;
            }
            let storage = Uuid::parse_str(storage).map_err(|e| failure().with_source(e))?;
            let replica = self
                .sync_store_factory
                .clone()
                .replica_at(self.paths.clone(), storage)
                .await
                .map_err(|e| failure().with_source(e))?
                .ok_or_else(failure)?;
            if crate::config::ConfigV2::canonical_address(endpoint)
                .map_err(|e| failure().with_source(e))?
                != replica.address
            {
                return Err(failure());
            }
            return self
                .prepare_replica_connection(
                    endpoint,
                    name,
                    &format!("account-{storage}"),
                    Some(replica),
                    false,
                )
                .await;
        }
        self.prepare_replica_connection(
            endpoint,
            name,
            &format!("account-{}", Uuid::now_v7()),
            None,
            true,
        )
        .await
    }

    pub async fn prepare_connection(
        &self,
        endpoint: &str,
        connection_name: &str,
        profile_name: &str,
    ) -> Result<PrepareConnectionOutcome, SessionError> {
        self.prepare_replica_connection(endpoint, connection_name, profile_name, None, false)
            .await
    }

    async fn prepare_replica_connection(
        &self,
        endpoint: &str,
        name: &str,
        profile: &str,
        replica: Option<ReplicaAccount>,
        reuse_pending: bool,
    ) -> Result<PrepareConnectionOutcome, SessionError> {
        let operation = SessionOperationId::new();
        let configuration = || SessionError::for_app(operation, SessionErrorKind::Configuration);
        let transport = AuthHttpTransport::new(endpoint).map_err(|e| {
            SessionError::for_app(operation, SessionErrorKind::Protocol).with_source(e)
        })?;
        let info = transport
            .system_info()
            .await
            .map_err(|e| SessionError::from_http_for_app(operation, &e).with_source(e))?;
        let verified =
            crate::remote::trust::verify_and_bind_system_info(endpoint, info).map_err(|e| {
                SessionError::for_app(operation, SessionErrorKind::TrustInvalid)
                    .with_source(std::io::Error::other(e))
            })?;
        let snapshot = self
            .repository
            .snapshot()
            .map_err(|e| configuration().with_source(e))?;
        let connection_id = snapshot
            .config()
            .connection_for_address(verified.binding().address())
            .map_err(|e| configuration().with_source(e))?
            .unwrap_or_else(|| ConnectionId::deterministic(name, verified.binding().address()));
        let existing = snapshot.config().connections.get(&connection_id);
        let storage = replica
            .as_ref()
            .map(|replica| replica.storage_id.to_string())
            .or_else(|| {
                existing
                    .and_then(|connection| connection.profile_storage_id(profile))
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| Uuid::now_v7().to_string());
        let mut prepared = PreparedConnection {
            target: SessionTarget::new(connection_id.clone(), profile)
                .map_err(|e| configuration().with_source(e))?,
            auth_methods: verified
                .info()
                .auth_methods
                .iter()
                .filter_map(|value| AuthMethod::try_from(*value).ok())
                .collect(),
            registration_available: verified.info().internal_users_present == Some(false),
            server_name: verified.info().server_name.clone(),
            storage_id: storage,
        };
        if let Some(connection) = existing {
            match connection.metadata().server_id.as_deref() {
                Some(pinned) if pinned == verified.binding().server_id() => {}
                Some(_) => {
                    return Err(SessionError::for_app(
                        operation,
                        SessionErrorKind::ServerIdentityChanged,
                    ))
                }
                None => {
                    return Err(SessionError::for_app(
                        operation,
                        SessionErrorKind::TrustInvalid,
                    ))
                }
            }
        }
        let expected_connection_pin =
            existing.and_then(|connection| connection.metadata().server_fingerprint.clone());
        let old = expected_connection_pin
            .as_deref()
            .filter(|old| *old != verified.binding().server_fingerprint())
            .or_else(|| {
                replica
                    .as_ref()
                    .map(|replica| replica.server_fingerprint.as_str())
                    .filter(|old| *old != verified.binding().server_fingerprint())
            })
            .map(str::to_owned);
        let expected_subject = replica.map(|replica| replica.account_subject);
        if let Some(old) = old {
            return Ok(PrepareConnectionOutcome::FingerprintChanged(Box::new(
                ConnectionTrustChallenge {
                    expected_revision: snapshot.revision(),
                    connection_id,
                    expected_old_fingerprint: old,
                    verified,
                    prepared,
                    expected_subject,
                    expected_connection_pin,
                    connection_name: name.into(),
                    reuse_pending,
                },
            )));
        }
        let (snapshot, selected) = self
            .repository
            .pin_verified_connection(
                snapshot.revision(),
                connection_id,
                name.into(),
                verified.binding(),
                Some(ReplicaReservation {
                    profile: profile.into(),
                    storage: prepared.storage_id.clone(),
                    expected_subject,
                    reuse_pending,
                }),
                None,
            )
            .map_err(|e| configuration().with_source(e))?;
        if let Some(selected) = selected {
            prepared.target =
                SessionTarget::new(prepared.target.connection_id().clone(), &selected)
                    .map_err(|e| configuration().with_source(e))?;
            prepared.storage_id = snapshot.config().connections[prepared.target.connection_id()]
                .profile_storage_id(&selected)
                .expect("reserved storage")
                .into();
        }
        Ok(PrepareConnectionOutcome::Ready(prepared))
    }

    pub fn trust_connection(
        &self,
        challenge: ConnectionTrustChallenge,
    ) -> Result<PreparedConnection, SessionError> {
        let operation = SessionOperationId::new();
        let (snapshot, selected) = self
            .repository
            .pin_verified_connection(
                challenge.expected_revision,
                challenge.connection_id,
                challenge.connection_name,
                challenge.verified.binding(),
                Some(ReplicaReservation {
                    profile: challenge.prepared.target.profile_name().into(),
                    storage: challenge.prepared.storage_id.clone(),
                    expected_subject: challenge.expected_subject,
                    reuse_pending: challenge.reuse_pending,
                }),
                Some(challenge.expected_connection_pin),
            )
            .map_err(|e| {
                SessionError::for_app(operation, SessionErrorKind::Configuration).with_source(e)
            })?;
        let mut prepared = challenge.prepared;
        if let Some(selected) = selected {
            prepared.target = SessionTarget::new(
                prepared.target.connection_id().clone(),
                &selected,
            )
            .map_err(|e| {
                SessionError::for_app(operation, SessionErrorKind::Configuration).with_source(e)
            })?;
            prepared.storage_id = snapshot.config().connections[prepared.target.connection_id()]
                .profile_storage_id(&selected)
                .expect("reserved storage")
                .into();
        }
        Ok(prepared)
    }
}
