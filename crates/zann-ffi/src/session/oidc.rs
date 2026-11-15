//! Platform callback transport projection; auth policy remains in zann-client.
use super::*;
use zann_client::oidc::{OidcBrowserLogin, OidcCallback};

#[derive(uniffi::Enum)]
pub enum OidcCallbackFfi {
    Loopback,
    Application { redirect_uri: String },
}

impl From<OidcCallbackFfi> for OidcCallback {
    fn from(value: OidcCallbackFfi) -> Self {
        match value {
            OidcCallbackFfi::Loopback => Self::Loopback,
            OidcCallbackFfi::Application { redirect_uri } => Self::Application { redirect_uri },
        }
    }
}

/// One consumable login, bound to the client that prepared it. No provider
/// token, verifier or Zann bearer is exposed to the native adapter.
#[derive(uniffi::Object)]
pub struct OidcLoginFfi {
    authorization_url: String,
    callback_scheme: String,
    login: Mutex<Option<OidcBrowserLogin>>,
    bridge: Arc<Bridge>,
}

impl OidcLoginFfi {
    fn take(&self) -> CoreResult<OidcBrowserLogin> {
        self.login
            .lock()
            .expect("lock poisoned")
            .take()
            .ok_or_else(|| CoreError::InvalidArgument("OIDC login was already used".to_string()))
    }
}

#[uniffi::export]
impl OidcLoginFfi {
    pub fn authorization_url(&self) -> String {
        self.authorization_url.clone()
    }
    pub fn callback_scheme(&self) -> String {
        self.callback_scheme.clone()
    }

    pub fn remaining_timeout_ms(&self) -> CoreResult<u64> {
        self.login
            .lock()
            .expect("lock poisoned")
            .as_ref()
            .map(OidcBrowserLogin::remaining_timeout_ms)
            .ok_or_else(|| CoreError::InvalidArgument("OIDC login was already used".to_string()))
    }

    pub fn finish(&self) -> CoreResult<Arc<SessionAccessFfi>> {
        let login = self.take()?;
        let access = self
            .bridge
            .runtime
            .block_on(login.finish(&self.bridge.client))?;
        Ok(Arc::new(SessionAccessFfi(access)))
    }

    pub fn finish_with_callback(&self, callback_uri: String) -> CoreResult<Arc<SessionAccessFfi>> {
        let login = self.take()?;
        let access = self
            .bridge
            .runtime
            .block_on(login.finish_with_callback(&self.bridge.client, callback_uri))?;
        Ok(Arc::new(SessionAccessFfi(access)))
    }
}

#[uniffi::export]
impl RemoteSession {
    pub fn begin_oidc_login(
        &self,
        connection: Arc<PreparedConnectionFfi>,
        operation: Arc<SessionOperationFfi>,
        callback: OidcCallbackFfi,
    ) -> CoreResult<Arc<OidcLoginFfi>> {
        let login = self.0.runtime.block_on(self.0.client.begin_oidc_login(
            connection.0.target().clone(),
            operation.take()?,
            callback.into(),
        ))?;
        Ok(Arc::new(OidcLoginFfi {
            authorization_url: login.authorization_url().to_string(),
            callback_scheme: login.callback_scheme().to_string(),
            login: Mutex::new(Some(login)),
            bridge: Arc::clone(&self.0),
        }))
    }
}
