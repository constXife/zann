//! Atomic endpoint trust and account provisioning reservation.
use super::super::*;

impl ConfigRepository {
    /// Pin endpoint trust and reserve an explicit account target in one Config commit.
    #[cfg(feature = "remote")]
    pub(crate) fn pin_verified_connection(
        &self,
        expected_revision: u64,
        connection_id: ConnectionId,
        name: String,
        endpoint: &VerifiedEndpointBinding,
        reservation: Option<ReplicaReservation>,
        confirmed_previous_pin: Option<Option<String>>,
    ) -> Result<(ConfigSnapshot, Option<String>), ConfigError> {
        let mut selected = None;
        let snapshot = self.mutate(Some(expected_revision), |config| {
            match config.connections.get_mut(&connection_id) {
                Some(connection) => {
                    let metadata = &mut connection.metadata;
                    let pin_matches = match &confirmed_previous_pin {
                        Some(expected) => metadata.server_fingerprint == *expected,
                        None => metadata
                            .server_fingerprint
                            .as_deref()
                            .is_none_or(|v| v == endpoint.server_fingerprint),
                    };
                    if normalize_address(&metadata.address, "$.connection.address")?
                        != endpoint.address
                        || metadata
                            .server_id
                            .as_deref()
                            .is_some_and(|v| v != endpoint.server_id)
                        || !pin_matches
                    {
                        return Err(ConfigError::BindingChangeRequiresRebind {
                            connection_id,
                            field: "verified_endpoint",
                        });
                    }
                    metadata.server_id = Some(endpoint.server_id.clone());
                    metadata.server_fingerprint = Some(endpoint.server_fingerprint.clone());
                }
                None => {
                    if confirmed_previous_pin.as_ref().is_some_and(Option::is_some) {
                        return Err(ConfigError::IdentityChanged);
                    }
                    let mut metadata = ConnectionMetadata::new(name, endpoint.address.clone());
                    metadata.server_id = Some(endpoint.server_id.clone());
                    metadata.server_fingerprint = Some(endpoint.server_fingerprint.clone());
                    config.connections.insert(
                        connection_id.clone(),
                        ConnectionConfig::from_metadata(metadata),
                    );
                }
            }
            if let Some(mut reservation) = reservation {
                if reservation.reuse_pending {
                    if reservation.expected_subject.is_some() {
                        return Err(ConfigError::IdentityChanged);
                    }
                    if let Some(name) = config.pending_account_profile(&connection_id) {
                        reservation.profile = name.into();
                        if let Some(storage) =
                            config.connections[&connection_id].profile_storage_id(name)
                        {
                            reservation.storage = storage.into();
                        }
                    }
                }
                selected = Some(reservation.profile.clone());
                let owner = config
                    .connections
                    .get_mut(&connection_id)
                    .expect("pinned connection");
                let profile = owner
                    .credential_profiles
                    .entry(reservation.profile.clone())
                    .or_default();
                if let Some(subject) = reservation.expected_subject {
                    if profile
                        .account_subject
                        .as_deref()
                        .is_some_and(|stored| stored != subject)
                        || profile
                            .expected_account_subject
                            .as_deref()
                            .is_some_and(|stored| stored != subject)
                    {
                        return Err(ConfigError::IdentityChanged);
                    }
                    if profile.account_subject.is_none() {
                        profile.expected_account_subject = Some(subject);
                    }
                }
                bind_profile_storage(
                    config,
                    &connection_id,
                    &reservation.profile,
                    Some(&reservation.storage),
                )?;
            }
            Ok(())
        })?;
        Ok((snapshot, selected))
    }
}
