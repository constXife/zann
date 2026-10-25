#![allow(dead_code)]
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use zann_client::config::*;

pub const FINGERPRINT: &str = "sha256:test";
pub fn system_info(fingerprint: &str) -> serde_json::Value {
    let key = SigningKey::from_bytes(&[31; 32]);
    let public = key.verifying_key().to_bytes();
    let server_id = data_encoding::BASE32_NOPAD
        .encode(&Sha256::digest(public))
        .to_ascii_lowercase();
    let timestamp = chrono::Utc::now().timestamp();
    let signature = key.sign(format!("zann-id:v1:{server_id}:{timestamp}").as_bytes());
    serde_json::json!({"version":"1.0.0","build_commit":null,"server_id":server_id,
        "identity":{"public_key":STANDARD.encode(public),"timestamp":timestamp,"signature":STANDARD.encode(signature.to_bytes())},
        "server_name":"Test server","server_fingerprint":fingerprint,"auth_methods":[1,99],
        "personal_vaults_enabled":true,"internal_users_present":true})
}
pub fn mock_identity(server: &mut mockito::Server) -> mockito::Mock {
    server
        .mock("GET", "/v1/system/info")
        .with_status(200)
        .with_body(system_info(FINGERPRINT).to_string())
        .expect_at_least(0)
        .create()
}
#[derive(Default)]
pub struct MemoryStore(Mutex<BTreeMap<String, String>>);
impl CredentialStore for MemoryStore {
    fn put(&self, id: &CredentialId, secret: &CredentialSecret) -> Result<(), CredentialPortError> {
        self.0
            .lock()
            .expect("lock")
            .insert(id.as_str().into(), secret.expose_secret().into());
        Ok(())
    }
    fn get(&self, id: &CredentialId) -> Result<Option<CredentialSecret>, CredentialPortError> {
        Ok(self
            .0
            .lock()
            .expect("lock")
            .get(id.as_str())
            .map(|secret| CredentialSecret::new(secret.clone()).expect("secret")))
    }
    fn delete(&self, id: &CredentialId) -> Result<(), CredentialPortError> {
        self.0.lock().expect("lock").remove(id.as_str());
        Ok(())
    }
}
struct NoLegacy;
impl LegacyCredentialSource for NoLegacy {
    fn get(
        &self,
        _: &LegacyCredentialLocator,
    ) -> Result<Option<CredentialSecret>, CredentialPortError> {
        Ok(None)
    }
}
pub fn configuration(root: &std::path::Path) -> (ConfigRepository, Arc<MemoryStore>, ClientId) {
    let repository = ConfigRepository::new(ClientPaths::new(root));
    let store = Arc::new(MemoryStore::default());
    let client = ClientId::new("cli").expect("client ID");
    repository
        .initialize(&client, store.as_ref(), &NoLegacy)
        .expect("initialize");
    (repository, store, client)
}
