//! Platform ports a [`LocalVault`] is composed with, and the opener for a
//! native database path chosen by a shell.

use std::fs;
use std::path::{Component, Path};
use std::sync::Arc;

use zann_client::app::local::{LocalError, LocalResult};
use zann_client::config::{CredentialStore, LegacyCredentialSource};
use zann_client::credentials::{OsCredentialStore, OsLegacyCredentialSource};
use zann_db::SqliteFileLocation;
use zann_keystore::{default_authenticator, default_keystore, default_secret_store};
pub use zann_keystore::{
    HardwareAuthenticator, Keystore, KeystoreError, KeystoreStatus, KeystoreStatusReason,
    SecretStore, SecretValue,
};

use super::LocalVault;

/// Platform adapters behind one local vault. Choosing them is the composition
/// root's job; the vault never discovers an OS store on its own.
pub struct LocalVaultPorts {
    /// Holds the device wrapping key for remembered unlock.
    pub keystore: Arc<dyn Keystore>,
    pub authenticator: Arc<dyn HardwareAuthenticator>,
    /// Holds remote session tokens referenced by Config v2.
    pub credentials: Arc<dyn CredentialStore>,
    /// Read-only source of pre-Config-v2 CLI tokens, consulted only while a
    /// legacy config is being migrated.
    pub legacy_credentials: Arc<dyn LegacyCredentialSource>,
}

impl LocalVaultPorts {
    /// Desktop composition: the OS keyring for the device wrapping key and
    /// for credentials, raw-HID FIDO2 where the platform has it.
    #[must_use]
    pub fn system_default() -> Self {
        Self::with_platform_secrets(default_keystore().into(), Arc::from(default_secret_store()))
    }

    /// Composition for a shell that owns its OS secret storage (Keychain with
    /// an access-control policy, Android Keystore). The credential account
    /// naming stays in [`OsCredentialStore`]; hardware keys and legacy CLI
    /// entries keep the platform's own adapters.
    #[must_use]
    pub fn with_platform_secrets(
        keystore: Arc<dyn Keystore>,
        secret_store: Arc<dyn SecretStore>,
    ) -> Self {
        Self {
            keystore,
            authenticator: default_authenticator().into(),
            credentials: Arc::new(OsCredentialStore::new(secret_store)),
            legacy_credentials: Arc::new(OsLegacyCredentialSource::system_default()),
        }
    }
}

/// Opens the database at an absolute native path chosen by a shell, such as a
/// file inside an app container.
///
/// The parent directory is created if missing and canonicalized once here, so
/// platform symlinks above it (`/var` → `/private/var` on Apple systems) never
/// reach the symlink-free SQLite location checks. The file itself is not
/// resolved: a symlinked database is still rejected downstream.
pub fn open_vault_at_path(db_path: &Path, ports: LocalVaultPorts) -> LocalResult<Arc<LocalVault>> {
    LocalVault::open(native_file_location(db_path)?, ports)
}

fn native_file_location(db_path: &Path) -> LocalResult<SqliteFileLocation> {
    if !db_path.is_absolute() || db_path.components().any(|c| c == Component::ParentDir) {
        return Err(LocalError::InvalidArgument(
            "database path must be absolute and lexically normalized".to_string(),
        ));
    }
    let Some(Component::Normal(file_name)) = db_path.components().next_back() else {
        return Err(LocalError::InvalidArgument(
            "database path must name a file".to_string(),
        ));
    };
    let parent = db_path.parent().ok_or_else(|| {
        LocalError::InvalidArgument("database path must have a parent directory".to_string())
    })?;
    // Canonicalization needs the directory to exist; `LocalVault::open`
    // restricts it to the owner once the location is validated.
    fs::create_dir_all(parent).map_err(|err| LocalError::Service(err.to_string()))?;
    let parent = fs::canonicalize(parent).map_err(|err| LocalError::Service(err.to_string()))?;
    SqliteFileLocation::from_path(&parent.join(file_name))
        .map_err(|err| LocalError::InvalidArgument(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_location_rejects_relative_unnormalized_and_fileless_paths() {
        for path in [
            "relative/local.sqlite",
            "/",
            "/tmp/..",
            "/tmp/../local.sqlite",
        ] {
            assert!(
                matches!(
                    native_file_location(Path::new(path)),
                    Err(LocalError::InvalidArgument(_))
                ),
                "{path} must be rejected"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_location_canonicalizes_a_symlinked_parent() {
        let temp = crate::test_support::CanonicalTempDir::new("temporary container");
        let real = temp.path().join("real");
        fs::create_dir(&real).expect("real container");
        std::os::unix::fs::symlink(&real, temp.path().join("link")).expect("container symlink");

        let location = native_file_location(&temp.path().join("link/vault/local.sqlite"))
            .expect("native location");

        assert_eq!(location.path(), real.join("vault/local.sqlite"));
        assert_eq!(location.root(), real.join("vault"));
    }
}
