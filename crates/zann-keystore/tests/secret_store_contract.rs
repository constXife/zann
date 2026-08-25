use std::collections::HashMap;
use std::sync::Mutex;

use zann_keystore::{KeystoreError, SecretStore, SecretValue};

#[derive(Default)]
struct InMemorySecretStore {
    values: Mutex<HashMap<(String, String), SecretValue>>,
}

impl SecretStore for InMemorySecretStore {
    fn put(&self, service: &str, account: &str, secret: SecretValue) -> Result<(), KeystoreError> {
        self.validate_namespace(service, account)?;
        self.values
            .lock()
            .expect("in-memory secret store lock")
            .insert((service.to_string(), account.to_string()), secret);
        Ok(())
    }

    fn get(&self, service: &str, account: &str) -> Result<Option<SecretValue>, KeystoreError> {
        self.validate_namespace(service, account)?;
        Ok(self
            .values
            .lock()
            .expect("in-memory secret store lock")
            .get(&(service.to_string(), account.to_string()))
            .map(|secret| SecretValue::new(secret.expose_secret())))
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeystoreError> {
        self.validate_namespace(service, account)?;
        self.values
            .lock()
            .expect("in-memory secret store lock")
            .remove(&(service.to_string(), account.to_string()));
        Ok(())
    }
}

fn assert_secret_store_contract(store: &dyn SecretStore) {
    let custom_store_value = SecretValue::new("x".repeat(70 * 1024));
    store.validate(&custom_store_value).unwrap();

    assert!(store.get("service", "account").unwrap().is_none());
    store.delete("service", "account").unwrap();

    store
        .put("service", "account", SecretValue::new("first"))
        .unwrap();
    assert_eq!(
        store
            .get("service", "account")
            .unwrap()
            .expect("stored secret")
            .expose_secret(),
        "first"
    );

    store
        .put("service", "account", SecretValue::new("replacement"))
        .unwrap();
    assert_eq!(
        store
            .get("service", "account")
            .unwrap()
            .expect("replacement secret")
            .expose_secret(),
        "replacement"
    );
    assert!(store.get("other", "account").unwrap().is_none());
    assert!(store.get("service", "other").unwrap().is_none());

    store.delete("service", "account").unwrap();
    store.delete("service", "account").unwrap();
    assert!(store.get("service", "account").unwrap().is_none());
}

#[test]
fn in_memory_implementation_satisfies_the_public_contract() {
    assert_secret_store_contract(&InMemorySecretStore::default());
}

#[test]
fn secret_value_debug_output_is_redacted() {
    let secret = "must-not-appear";
    let value = SecretValue::new(secret);
    let debug = format!("{value:?}");

    assert!(!debug.contains(secret));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn namespace_contract_rejects_invalid_service_grammar() {
    let store = InMemorySecretStore::default();

    assert!(matches!(
        store.validate_namespace("invalid.service", "account"),
        Err(KeystoreError::InvalidNamespace)
    ));
    store
        .validate_namespace("valid-service", "dotted.account")
        .unwrap();
}
