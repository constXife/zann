use super::*;
use zann_core::api::account_access::*;
impl AuthHttpTransport {
    pub(crate) async fn passkey_configuration(
        &self,
    ) -> Result<PasskeyConfiguration, AuthHttpError> {
        self.ensure_sensitive_transport(AuthOperation::ServerRead)?;
        let request = self
            .client
            .get(self.url_for(AuthOperation::ServerRead, "v1/auth/passkeys/config")?)
            .timeout(self.request_timeout);
        self.execute_json(AuthOperation::ServerRead, request).await
    }
    pub(crate) async fn passkey_options(
        &self,
        input: &PasskeyLoginOptions,
    ) -> Result<CeremonyOptions, AuthHttpError> {
        self.post_json(
            AuthOperation::ServerWrite,
            "v1/auth/passkeys/login/options",
            input,
        )
        .await
    }
    pub(crate) async fn passkey_finish(
        &self,
        input: &CeremonyFinish,
    ) -> Result<PasskeyLogin, AuthHttpError> {
        self.post_json(
            AuthOperation::ServerWrite,
            "v1/auth/passkeys/login/finish",
            input,
        )
        .await
    }
}
impl AuthHttpTransport {
    pub(crate) async fn account_get<R: DeserializeOwned>(
        &self,
        path: &str,
        token: &str,
    ) -> Result<R, AuthHttpError> {
        let operation = AuthOperation::ServerRead;
        self.ensure_sensitive_transport(operation)?;
        let request = self
            .client
            .get(self.url_for(operation, path)?)
            .header(AUTHORIZATION, bearer_authorization_header(token)?)
            .timeout(self.request_timeout);
        self.execute_json(operation, request).await
    }
    pub(crate) async fn account_post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        token: &str,
        input: &T,
    ) -> Result<R, AuthHttpError> {
        let operation = AuthOperation::ServerWrite;
        self.ensure_sensitive_transport(operation)?;
        let request = self
            .client
            .post(self.url_for(operation, path)?)
            .header(AUTHORIZATION, bearer_authorization_header(token)?)
            .json(input)
            .timeout(self.request_timeout);
        self.execute_json(operation, request).await
    }
}

impl AuthHttpTransport {
    pub(crate) async fn recovery_get<R: DeserializeOwned>(
        &self,
        path: &str,
        id: uuid::Uuid,
        token: &str,
    ) -> Result<R, AuthHttpError> {
        let operation = AuthOperation::ServerRead;
        self.ensure_sensitive_transport(operation)?;
        let request = self
            .client
            .get(self.url_for(operation, path)?)
            .header(AUTHORIZATION, recovery_header(id, token)?)
            .timeout(self.request_timeout);
        self.execute_json(operation, request).await
    }
    pub(crate) async fn recovery_post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        id: uuid::Uuid,
        token: &str,
        input: &T,
    ) -> Result<R, AuthHttpError> {
        let operation = AuthOperation::ServerWrite;
        self.ensure_sensitive_transport(operation)?;
        let request = self
            .client
            .post(self.url_for(operation, path)?)
            .header(AUTHORIZATION, recovery_header(id, token)?)
            .json(input)
            .timeout(self.request_timeout);
        self.execute_json(operation, request).await
    }
}
fn recovery_header(
    id: uuid::Uuid,
    token: &str,
) -> Result<reqwest::header::HeaderValue, AuthHttpError> {
    let text = zeroize::Zeroizing::new(format!("Recovery {id}.{token}"));
    let mut value = reqwest::header::HeaderValue::from_str(&text)
        .map_err(|_| AuthHttpError::new(AuthOperation::ServerWrite, AuthHttpErrorKind::Protocol))?;
    value.set_sensitive(true);
    Ok(value)
}
