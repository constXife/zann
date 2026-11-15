//! Authenticated policy chooses whether external enrollment needs account KDF material.
use super::*;
pub(super) async fn for_enrollment(
    port: &dyn AuthPort,
    email: &str,
    personal_vaults_enabled: bool,
    operation: &SessionOperation,
) -> Result<IdentityCommit, SessionError> {
    if !personal_vaults_enabled {
        return Ok(IdentityCommit::NotRequired {
            email: email.to_owned(),
        });
    }
    let prelogin = port
        .prelogin(email)
        .await
        .map_err(|failure| SessionError::from_auth(operation, &failure))?;
    let identity = password_login_identity_from_prelogin(prelogin, Some(email.to_owned()))
        .map_err(|kind| SessionError::new(operation, kind))?;
    Ok(IdentityCommit::InitializeOrMatch(identity))
}
