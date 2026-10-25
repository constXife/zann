//! Remote-only server capabilities over Config v2 and the canonical transport.

use crate::config::{ConfigRepository, ConnectionId};
use crate::remote::auth::AuthHttpTransport;
use crate::remote::trust::{verify_and_bind_system_info, VerifiedSystemInfo};
use zann_core::api::system::SystemInfoResponse;

mod credentials;
mod error;
mod items;
pub use error::ServerError;
pub use items::*;

pub struct ServerProbe {
    transport: AuthHttpTransport,
    verified: VerifiedSystemInfo,
}

/// A remote client may only be constructed from a signed, explicitly trusted
/// server observation. No credentials are read while probing or binding.
pub struct ServerClient {
    transport: AuthHttpTransport,
    endpoint: String,
    fingerprint: String,
    server_id: String,
}

impl ServerProbe {
    pub async fn new(endpoint: &str) -> Result<Self, ServerError> {
        let transport = AuthHttpTransport::new(endpoint)?;
        let info = transport.system_info().await?;
        let verified =
            verify_and_bind_system_info(endpoint, info).map_err(ServerError::identity_proof)?;
        Ok(Self {
            transport,
            verified,
        })
    }
    pub fn info(&self) -> &SystemInfoResponse {
        self.verified.info()
    }
    /// Use an explicitly supplied token without creating a saved connection.
    pub fn confirm_ephemeral(
        self,
        confirmed_fingerprint: &str,
    ) -> Result<ServerClient, ServerError> {
        let binding = self.verified.binding();
        if confirmed_fingerprint != binding.server_fingerprint() {
            return Err(ServerError::trust());
        }
        Ok(ServerClient {
            endpoint: binding.address().to_string(),
            fingerprint: binding.server_fingerprint().to_string(),
            server_id: binding.server_id().to_string(),
            transport: self.transport,
        })
    }
    pub fn bind_confirmed(
        self,
        repository: &ConfigRepository,
        id: &ConnectionId,
        confirmed_fingerprint: &str,
    ) -> Result<ServerClient, ServerError> {
        let binding = self.verified.binding();
        if confirmed_fingerprint != binding.server_fingerprint() {
            return Err(ServerError::trust());
        }
        let snapshot = repository.snapshot()?;
        let metadata = snapshot
            .config()
            .connections
            .get(id)
            .ok_or_else(|| ServerError::input("connection not found"))?
            .metadata();
        if metadata
            .server_id
            .as_deref()
            .is_some_and(|old| old != binding.server_id())
        {
            return Err(ServerError::trust());
        }
        if metadata
            .server_fingerprint
            .as_deref()
            .is_some_and(|old| old != binding.server_fingerprint())
        {
            repository.replace_verified_fingerprint(
                snapshot.revision(),
                id,
                metadata.server_fingerprint.as_deref().expect("checked"),
                binding,
            )?;
        } else {
            repository.pin_verified_connection(
                snapshot.revision(),
                id.clone(),
                metadata.name.clone(),
                binding,
                None,
            )?;
        }
        Ok(ServerClient {
            endpoint: binding.address().to_string(),
            fingerprint: binding.server_fingerprint().to_string(),
            server_id: binding.server_id().to_string(),
            transport: self.transport,
        })
    }
}
impl ServerClient {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub async fn me(&self, bearer: &str) -> Result<zann_core::Identity, ServerError> {
        Ok(self.transport.me(bearer).await?)
    }
    pub(super) fn check_endpoint(&self, endpoint: &str) -> Result<(), ServerError> {
        if endpoint.trim_end_matches('/') != self.endpoint.trim_end_matches('/') {
            return Err(ServerError::input("endpoint changed"));
        }
        Ok(())
    }
    async fn reverify(&self) -> Result<(), ServerError> {
        let info = self.transport.system_info().await?;
        let verified = verify_and_bind_system_info(&self.endpoint, info)
            .map_err(ServerError::identity_proof)?;
        if verified.binding().server_id() != self.server_id
            || verified.binding().server_fingerprint() != self.fingerprint
        {
            return Err(ServerError::trust());
        }
        Ok(())
    }
}

mod pagination;
pub use credentials::token_bundle;
pub use pagination::*;
