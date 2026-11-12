use super::*;

/// A fresh identity for a vault that is local-only from the start. A vault
/// that came from a server never gets one: its identity is the account's,
/// committed by the login.
pub(super) fn new_local_identity() -> ConfigIdentity {
    let salt = SecretKey::generate();
    ConfigIdentity {
        kdf_salt: base64::engine::general_purpose::STANDARD.encode(salt.as_bytes()),
        kdf_params: ConfigKdfParams {
            algorithm: "argon2id".to_string(),
            iterations: 3,
            memory_kb: 65536,
            parallelism: 4,
        },
        salt_fingerprint: None,
        first_seen_at: None,
        email: None,
    }
}

pub(super) fn derive_master_key(
    password: &str,
    identity: &ConfigIdentity,
) -> LocalResult<SecretKey> {
    let params =
        zann_core::api::auth::KdfParams::from(identity.kdf_params.clone()).to_crypto_params();
    let key = zann_core::passwords::derive_auth_hash(password, &identity.kdf_salt, &params)
        .map_err(|err| LocalError::InvalidArgument(err.to_string()))?;
    Ok(SecretKey::from_bytes(key))
}

/// Identities a login committed carry the account's salt fingerprint; a
/// local-only vault's never do.
fn is_account_identity(identity: &ConfigIdentity) -> bool {
    identity.salt_fingerprint.is_some() || identity.email.is_some()
}

impl LocalVault {
    /// A device that holds no vault yet has nothing local to check a key
    /// against, and its first sync binds the key to the server connection for
    /// good. So a device signed in to a server, or holding an account's
    /// identity, must first open the account's personal vault key there with
    /// it. Callers run this only where no vault exists, before storing any.
    pub(super) fn check_key_for_new_device(
        &self,
        master_key: &SecretKey,
        identity: Option<&ConfigIdentity>,
    ) -> LocalResult<()> {
        let client = self.app_client()?;
        let target = match client.configured_target(None) {
            Ok(target) => target,
            Err(_) if !identity.is_some_and(is_account_identity) => return Ok(()),
            Err(_) => return Err(sign_in_required()),
        };
        let operation =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(60)).0;
        match self
            .runtime
            .block_on(client.verify_account_key(&target, master_key, operation))
            .map_err(LocalError::from)?
        {
            AccountKeyCheck::Matches | AccountKeyCheck::Unpublished => Ok(()),
            AccountKeyCheck::Mismatch => {
                Err(LocalError::InvalidArgument("invalid password".to_string()))
            }
        }
    }

    /// A device signed in to a server without the account's identity would
    /// mint a salt the account can never match; it signs in again instead.
    pub(super) fn refuse_local_identity_on_server(&self) -> LocalResult<()> {
        match self.app_client()?.configured_target(None) {
            Ok(_) => Err(sign_in_required()),
            Err(_) => Ok(()),
        }
    }
}

fn sign_in_required() -> LocalError {
    LocalError::Sync {
        kind: "session_expired".to_string(),
        message: "sign in to the server again to confirm the master password".to_string(),
    }
}
