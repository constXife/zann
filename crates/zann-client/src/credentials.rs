//! Adapters between typed client credentials and OS-managed secret storage.
//!
//! The account mapping lives here so shells never reconstruct keyring names.

use std::sync::Arc;

use zann_keystore::{
    default_legacy_secret_source, default_secret_store, LegacySecretSource as OsLegacySecretReader,
    SecretStore, SecretValue,
};

use crate::config::{
    CredentialId, CredentialPortError, CredentialPortErrorKind, CredentialSecret, CredentialStore,
    LegacyCredentialAccountSemantics, LegacyCredentialLocator, LegacyCredentialSource,
};

const CREDENTIAL_SERVICE: &str = "zann";
const CREDENTIAL_ACCOUNT_PREFIX: &str = "credential:v2:";
const LEGACY_CLI_SERVICE: &str = "zann-cli";

/// Typed credential storage backed by an injected OS secret store.
///
#[derive(Clone)]
pub struct OsCredentialStore {
    secret_store: Arc<dyn SecretStore>,
}

/// Read-only adapter for exact legacy CLI keyring entries used during the
/// one-way Config v2 migration.
///
/// Keeping this separate from [`OsCredentialStore`] makes it impossible for
/// the generic credential writer to select a legacy physical namespace.
#[derive(Clone)]
pub struct OsLegacyCredentialSource {
    legacy_source: Arc<dyn OsLegacySecretReader>,
}

impl OsLegacyCredentialSource {
    #[must_use]
    pub fn new(legacy_source: Arc<dyn OsLegacySecretReader>) -> Self {
        Self { legacy_source }
    }

    /// Select the platform's exact, read-only historical keyring adapter.
    #[must_use]
    pub fn system_default() -> Self {
        Self::new(Arc::from(default_legacy_secret_source()))
    }
}

impl OsCredentialStore {
    #[must_use]
    pub fn new(secret_store: Arc<dyn SecretStore>) -> Self {
        Self { secret_store }
    }

    /// Select the platform's default OS credential backend.
    #[must_use]
    pub fn system_default() -> Self {
        Self::new(Arc::from(default_secret_store()))
    }
}

impl CredentialStore for OsCredentialStore {
    fn validate(
        &self,
        credential_id: &CredentialId,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        self.secret_store
            .validate_namespace(CREDENTIAL_SERVICE, &credential_account(credential_id))
            .map_err(port_error)?;
        self.secret_store
            .validate(&SecretValue::new(secret.expose_secret()))
            .map_err(port_error)
    }

    fn put(
        &self,
        credential_id: &CredentialId,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialPortError> {
        self.secret_store
            .put(
                CREDENTIAL_SERVICE,
                &credential_account(credential_id),
                SecretValue::new(secret.expose_secret()),
            )
            .map_err(port_error)
    }

    fn get(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        self.secret_store
            .get(CREDENTIAL_SERVICE, &credential_account(credential_id))
            .map_err(port_error)?
            .map(|secret| CredentialSecret::new(secret.expose_secret().to_owned()))
            .transpose()
            .map_err(|error| CredentialPortError::new(error.to_string()))
    }

    fn delete(&self, credential_id: &CredentialId) -> Result<(), CredentialPortError> {
        self.secret_store
            .delete(CREDENTIAL_SERVICE, &credential_account(credential_id))
            .map_err(port_error)
    }
}

impl LegacyCredentialSource for OsLegacyCredentialSource {
    fn account_semantics(&self) -> LegacyCredentialAccountSemantics {
        if cfg!(target_os = "windows") {
            LegacyCredentialAccountSemantics::WindowsCaseInsensitive
        } else {
            LegacyCredentialAccountSemantics::Exact
        }
    }

    fn verifies_exact_account_identity(&self) -> bool {
        // The Windows reader checks the actual stored TargetName and username,
        // rather than trusting CredReadW's case-insensitive lookup alone.
        true
    }

    fn validate(&self, locator: &LegacyCredentialLocator) -> Result<(), CredentialPortError> {
        let Some(account) = locator.cli_keyring_account() else {
            return Ok(());
        };
        self.legacy_source
            .validate_legacy_namespace(LEGACY_CLI_SERVICE, &account)
            .map_err(port_error)
    }

    fn get(
        &self,
        locator: &LegacyCredentialLocator,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        let Some(account) = locator.cli_keyring_account() else {
            return Ok(None);
        };
        self.legacy_source
            .get_legacy(LEGACY_CLI_SERVICE, &account)
            .map_err(port_error)?
            .map(|secret| CredentialSecret::new(secret.expose_secret().to_owned()))
            .transpose()
            .map_err(|error| CredentialPortError::new(error.to_string()))
    }
}

fn credential_account(credential_id: &CredentialId) -> String {
    format!("{CREDENTIAL_ACCOUNT_PREFIX}{}", credential_id.as_str())
}

fn port_error(error: zann_keystore::KeystoreError) -> CredentialPortError {
    let kind = match &error {
        zann_keystore::KeystoreError::Cancelled => CredentialPortErrorKind::Cancelled,
        zann_keystore::KeystoreError::Unsupported => CredentialPortErrorKind::Unsupported,
        zann_keystore::KeystoreError::InvalidNamespace => CredentialPortErrorKind::InvalidNamespace,
        zann_keystore::KeystoreError::SecretTooLarge { maximum_bytes } => {
            CredentialPortErrorKind::SecretTooLarge {
                maximum_bytes: *maximum_bytes,
            }
        }
        zann_keystore::KeystoreError::Internal { .. } => CredentialPortErrorKind::Unavailable,
        zann_keystore::KeystoreError::NotFound => CredentialPortErrorKind::Other,
    };
    CredentialPortError::with_kind(kind, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use zann_keystore::KeystoreError;

    use super::*;
    use crate::config::CredentialKind;

    #[derive(Default)]
    struct MemorySecretStore {
        values: Mutex<BTreeMap<(String, String), String>>,
        reads: Mutex<Vec<(String, String)>>,
        maximum_secret_len: Option<usize>,
    }

    impl MemorySecretStore {
        fn seed(&self, service: &str, account: &str, secret: &str) {
            self.values.lock().expect("secret map lock").insert(
                (service.to_string(), account.to_string()),
                secret.to_string(),
            );
        }

        fn value(&self, service: &str, account: &str) -> Option<String> {
            self.values
                .lock()
                .expect("secret map lock")
                .get(&(service.to_string(), account.to_string()))
                .cloned()
        }
    }

    impl SecretStore for MemorySecretStore {
        fn validate(&self, secret: &SecretValue) -> Result<(), KeystoreError> {
            if self
                .maximum_secret_len
                .is_some_and(|maximum| secret.expose_secret().len() > maximum)
            {
                return Err(KeystoreError::SecretTooLarge {
                    maximum_bytes: self.maximum_secret_len.expect("configured limit"),
                });
            }
            Ok(())
        }

        fn put(
            &self,
            service: &str,
            account: &str,
            secret: SecretValue,
        ) -> Result<(), KeystoreError> {
            self.seed(service, account, secret.expose_secret());
            Ok(())
        }

        fn get(&self, service: &str, account: &str) -> Result<Option<SecretValue>, KeystoreError> {
            self.reads
                .lock()
                .expect("read log lock")
                .push((service.to_string(), account.to_string()));
            Ok(self.value(service, account).map(SecretValue::new))
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), KeystoreError> {
            self.values
                .lock()
                .expect("secret map lock")
                .remove(&(service.to_string(), account.to_string()));
            Ok(())
        }
    }

    impl OsLegacySecretReader for MemorySecretStore {
        fn get_legacy(
            &self,
            service: &str,
            account: &str,
        ) -> Result<Option<SecretValue>, KeystoreError> {
            self.reads
                .lock()
                .expect("read log lock")
                .push((service.to_string(), account.to_string()));
            Ok(self.value(service, account).map(SecretValue::new))
        }
    }

    fn credential_id() -> CredentialId {
        serde_json::from_str(&format!("\"cred_{}\"", "1".repeat(64))).expect("valid credential id")
    }

    fn locator(kind: CredentialKind) -> LegacyCredentialLocator {
        LegacyCredentialLocator {
            connection_name: "Prod.EXAMPLE/path-kept".to_string(),
            profile_name: "Session.Named".to_string(),
            kind,
        }
    }

    #[test]
    fn v2_credentials_use_one_canonical_service_and_account_mapping() {
        let backend = Arc::new(MemorySecretStore::default());
        let adapter = OsCredentialStore::new(backend.clone());
        let id = credential_id();
        let secret = CredentialSecret::new("access-secret").expect("bounded secret");

        CredentialStore::put(&adapter, &id, &secret).expect("put credential");
        let account = format!("credential:v2:{id}");
        assert_eq!(
            backend.value("zann", &account).as_deref(),
            Some("access-secret")
        );
        assert_eq!(
            CredentialStore::get(&adapter, &id)
                .expect("get credential")
                .expect("stored credential")
                .expose_secret(),
            "access-secret"
        );

        CredentialStore::delete(&adapter, &id).expect("delete credential");
        CredentialStore::delete(&adapter, &id).expect("idempotent delete");
        assert!(backend.value("zann", &account).is_none());
    }

    #[test]
    fn legacy_cli_accounts_are_read_exactly_and_never_normalized() {
        let backend = Arc::new(MemorySecretStore::default());
        let adapter = OsLegacyCredentialSource::new(backend.clone());
        let locator = locator(CredentialKind::Access);
        let exact_account = "access::Prod.EXAMPLE/path-kept::Session.Named";
        backend.seed("zann-cli", exact_account, "legacy-access");

        let secret = LegacyCredentialSource::get(&adapter, &locator)
            .expect("read legacy credential")
            .expect("legacy credential present");
        assert_eq!(secret.expose_secret(), "legacy-access");
        assert_eq!(
            backend.reads.lock().expect("read log lock").as_slice(),
            &[("zann-cli".to_string(), exact_account.to_string())]
        );
    }

    #[test]
    fn legacy_refresh_has_no_cli_keyring_account() {
        let backend = Arc::new(MemorySecretStore::default());
        let adapter = OsLegacyCredentialSource::new(backend.clone());

        assert!(
            LegacyCredentialSource::get(&adapter, &locator(CredentialKind::Refresh))
                .expect("refresh lookup")
                .is_none()
        );
        assert!(backend.reads.lock().expect("read log lock").is_empty());
    }

    #[test]
    fn ambiguous_legacy_components_never_reach_the_os_store() {
        let backend = Arc::new(MemorySecretStore::default());
        let adapter = OsLegacyCredentialSource::new(backend.clone());
        let locator = LegacyCredentialLocator {
            connection_name: "prod".to_string(),
            profile_name: "admin::token".to_string(),
            kind: CredentialKind::Access,
        };

        assert!(LegacyCredentialSource::get(&adapter, &locator)
            .expect("ambiguous lookup is skipped")
            .is_none());
        assert!(backend.reads.lock().expect("read log lock").is_empty());
    }

    #[test]
    fn legacy_service_account_uses_the_historical_service_prefix() {
        let backend = Arc::new(MemorySecretStore::default());
        let adapter = OsLegacyCredentialSource::new(backend.clone());
        let locator = locator(CredentialKind::ServiceAccount);
        let account = "service::Prod.EXAMPLE/path-kept::Session.Named";
        backend.seed("zann-cli", account, "legacy-service");

        assert_eq!(
            LegacyCredentialSource::get(&adapter, &locator)
                .expect("service lookup")
                .expect("service credential")
                .expose_secret(),
            "legacy-service"
        );
    }

    #[test]
    fn typed_preflight_delegates_to_the_platform_store() {
        let backend = Arc::new(MemorySecretStore {
            maximum_secret_len: Some(4),
            ..MemorySecretStore::default()
        });
        let adapter = OsCredentialStore::new(backend);
        let secret = CredentialSecret::new("too-long").expect("config-sized secret");

        let error = CredentialStore::validate(&adapter, &credential_id(), &secret)
            .expect_err("backend limit");
        assert_eq!(
            error.kind(),
            &CredentialPortErrorKind::SecretTooLarge { maximum_bytes: 4 }
        );
        assert!(error.to_string().contains("4 bytes"));
        assert!(!error.to_string().contains("too-long"));
    }
}
