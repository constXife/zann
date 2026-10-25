use super::*;
use crate::config::{CredentialBundle, CredentialKind, CredentialSecret, CredentialStore};
use zann_core::api::auth::ServiceAccountLoginRequest;

/// Classify an explicitly supplied token at the canonical credential owner.
pub fn token_bundle(secret: CredentialSecret) -> CredentialBundle {
    if secret.expose_secret().starts_with("zann_sa_") {
        CredentialBundle::new(None, None, Some(secret))
    } else {
        CredentialBundle::new(Some(secret), None, None)
    }
}
impl ServerClient {
    async fn authenticate_verified_token(
        &self,
        secret: &CredentialSecret,
    ) -> Result<CredentialSecret, ServerError> {
        self.transport.ensure_sensitive_endpoint()?;
        if secret.expose_secret().starts_with("zann_sa_") {
            let request = ServiceAccountLoginRequest {
                token: secret.expose_secret().to_string(),
            };
            // The request DTO is canonical; its lifetime never exceeds dispatch.
            let mut response = self.transport.service_account_login(&request).await?;
            CredentialSecret::new(response.take_access_token()).map_err(Into::into)
        } else {
            CredentialSecret::new(secret.expose_secret()).map_err(Into::into)
        }
    }
    pub async fn authenticate_token(
        &self,
        secret: &CredentialSecret,
    ) -> Result<CredentialSecret, ServerError> {
        self.reverify().await?;
        self.authenticate_verified_token(secret).await
    }
    pub async fn profile_access(
        &self,
        repository: &ConfigRepository,
        store: &dyn CredentialStore,
        id: &ConnectionId,
        profile_name: &str,
        force_service_exchange: bool,
    ) -> Result<Option<CredentialSecret>, ServerError> {
        self.transport.ensure_sensitive_endpoint()?;
        self.reverify().await?;
        let snapshot = repository.snapshot()?;
        let connection = snapshot
            .config()
            .connections
            .get(id)
            .ok_or_else(|| ServerError::input("connection not found"))?;
        if connection.metadata().address.trim_end_matches('/')
            != self.endpoint.trim_end_matches('/')
            || connection.metadata().server_fingerprint.as_deref() != Some(&self.fingerprint)
            || connection.metadata().server_id.as_deref() != Some(&self.server_id)
        {
            return Err(ServerError::trust());
        }
        let profile = connection
            .credential_profiles()
            .get(profile_name)
            .ok_or_else(|| ServerError::input("profile not found"))?;
        if let Some(credential_id) = profile.credentials().get(&CredentialKind::ServiceAccount) {
            let secret = store
                .get(credential_id)?
                .ok_or_else(|| ServerError::input("service token missing"))?;
            return self.authenticate_verified_token(&secret).await.map(Some);
        }
        if force_service_exchange {
            return Ok(None);
        }
        let credential_id = profile
            .credentials()
            .get(&CredentialKind::Access)
            .ok_or_else(|| ServerError::input("access token missing"))?;
        Ok(store.get(credential_id)?)
    }
}
