//! A shell-composed vault: every platform port is injected, and the database
//! path is the shell's own native path rather than a SQLite URI.

use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};

use crate::support::CanonicalTempDir;
use zann_client::config::{
    CredentialId, CredentialPortError, CredentialSecret, CredentialStore, LegacyCredentialLocator,
    LegacyCredentialSource,
};
use zann_client_sqlite::local_vault::{open_vault_at_path, LocalVaultPorts};
use zann_keystore::{UnsupportedAuthenticator, UnsupportedKeystore};

#[derive(Default)]
struct MemoryCredentials(Mutex<BTreeMap<String, String>>);

impl MemoryCredentials {
    fn secrets(&self) -> Vec<String> {
        let mut secrets: Vec<_> = self.0.lock().unwrap().values().cloned().collect();
        secrets.sort();
        secrets
    }
}

impl CredentialStore for MemoryCredentials {
    fn put(&self, id: &CredentialId, secret: &CredentialSecret) -> Result<(), CredentialPortError> {
        self.0
            .lock()
            .unwrap()
            .insert(id.as_str().to_owned(), secret.expose_secret().to_owned());
        Ok(())
    }

    fn get(&self, id: &CredentialId) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.0
            .lock()
            .unwrap()
            .get(id.as_str())
            .map(|secret| CredentialSecret::new(secret.clone()))
            .transpose()
            .map_err(|error| CredentialPortError::new(error.to_string()))
    }

    fn delete(&self, id: &CredentialId) -> Result<(), CredentialPortError> {
        self.0.lock().unwrap().remove(id.as_str());
        Ok(())
    }
}

/// The CLI keyring entry the `cli-keyring` config fixture refers to.
struct LegacyCliToken;

impl LegacyCredentialSource for LegacyCliToken {
    fn get(
        &self,
        locator: &LegacyCredentialLocator,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        Ok(
            (locator.cli_keyring_account().as_deref() == Some("access::cli::manual"))
                .then(|| CredentialSecret::new("test-legacy-access-token".to_owned()).unwrap()),
        )
    }
}

#[cfg(unix)]
#[test]
fn injected_credential_ports_migrate_a_legacy_token_under_a_symlinked_container() {
    let temp = CanonicalTempDir::new();
    let container = temp.join("container");
    fs::create_dir_all(container.join("vault")).expect("container");
    fs::write(
        container.join("vault/config.json"),
        include_bytes!("../../../../tests/fixtures/client-config/v1/cli-keyring.json"),
    )
    .expect("legacy config");
    std::os::unix::fs::symlink(&container, temp.join("container-link")).expect("symlink");
    let credentials = Arc::new(MemoryCredentials::default());
    let ports = LocalVaultPorts {
        keystore: Arc::new(UnsupportedKeystore),
        authenticator: Arc::new(UnsupportedAuthenticator),
        credentials: credentials.clone(),
        legacy_credentials: Arc::new(LegacyCliToken),
    };

    let core = open_vault_at_path(&temp.join("container-link/vault/local.sqlite"), ports)
        .expect("open through the symlinked container");
    // The fixture's server is unreachable, so the account cannot confirm the
    // master password and nothing is created; the legacy config is migrated
    // before that check.
    assert!(
        core.initialize_master_password("new device password".into())
            .expect("device password is independent of server auth")
            .unlocked
    );
    assert!(
        core.enroll_account_key("account encryption password".into())
            .is_err(),
        "account key enrollment still requires a live server proof"
    );
    assert!(core.app_status().expect("status").initialized);

    assert_eq!(credentials.secrets(), ["test-legacy-access-token"]);
    let config = fs::read_to_string(container.join("vault/client-config.json")).expect("config");
    assert!(
        !config.contains("test-legacy-access-token"),
        "the token belongs to the injected store, never the config"
    );
}
