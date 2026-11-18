use super::super::{AccessError, Result};
use crate::app::AppState;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, Method},
};
use zann_core::{Identity, Session};
pub(super) struct ManagementActor(pub Session);

#[async_trait]
impl FromRequestParts<AppState> for ManagementActor {
    type Rejection = AccessError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self> {
        let identity = parts
            .extensions
            .get::<Identity>()
            .ok_or(AccessError::Rejected)?;
        let action = if parts.method == Method::GET {
            "read"
        } else {
            "write"
        };
        if !identity.source.is_internal_interactive()
            || !state
                .policy_store
                .get()
                .is_allowed(identity, action, "users/me/security")
        {
            return Err(AccessError::Forbidden);
        }
        let session = super::session(state, &parts.headers).await?;
        if identity.user_id != session.user_id || identity.device_id != Some(session.device_id) {
            return Err(AccessError::Rejected);
        }
        Ok(Self(session))
    }
}
