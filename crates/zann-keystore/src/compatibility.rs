//! Synthetic golden tripwires for persisted device-unlock material.
use crate::{Keystore, KeystoreError, KeystoreStatus, KeystoreStatusReason, RememberedUnlock};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    synthetic_only: bool,
    dwk_aad_utf8: String,
    dwk_base64: String,
    master_key_base64: String,
    wrapped_master_key_base64: String,
    #[cfg(all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos")))]
    hmac_output_base64: String,
    #[cfg(all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos")))]
    expected_dwk_base64: String,
}

fn fixture() -> Fixture {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../tests/fixtures/crypto/v1_device_unlock.json"
    ))
    .expect("synthetic fixture");
    assert!(fixture.synthetic_only);
    fixture
}

struct FixtureKeystore(Vec<u8>);
impl Keystore for FixtureKeystore {
    fn status(&self) -> KeystoreStatus {
        KeystoreStatus::unsupported(KeystoreStatusReason::Unavailable)
    }
    fn store_dwk(&self, _: &[u8]) -> Result<(), KeystoreError> {
        unreachable!("read-only fixture")
    }
    fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
        Ok(Some(self.0.clone()))
    }
    fn delete_dwk(&self) -> Result<(), KeystoreError> {
        unreachable!("read-only fixture")
    }
}

#[test]
fn remembered_v1_envelope_and_aad_remain_decryptable() {
    let fixture = fixture();
    assert_eq!(crate::remembered::DWK_AAD, fixture.dwk_aad_utf8.as_bytes());
    let store = FixtureKeystore(STANDARD.decode(fixture.dwk_base64).expect("fixture DWK"));
    let remembered = RememberedUnlock {
        wrapped_master_key: Some(fixture.wrapped_master_key_base64),
        ..Default::default()
    };
    assert_eq!(
        remembered
            .unlock_with_keystore(&store)
            .expect("golden unlock")
            .as_slice(),
        STANDARD
            .decode(fixture.master_key_base64)
            .expect("fixture master")
    );
    assert!(remembered
        .unlock_with_keystore(&FixtureKeystore(vec![0; 32]))
        .is_err());
}

#[cfg(all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos")))]
#[test]
fn fido_hmac_secret_domain_separation_matches_the_golden_key() {
    let fixture = fixture();
    let hmac: [u8; 32] = STANDARD
        .decode(fixture.hmac_output_base64)
        .expect("fixture HMAC output")
        .try_into()
        .expect("32 bytes");
    assert_eq!(
        STANDARD.encode(crate::fido::derive_key(&hmac)),
        fixture.expected_dwk_base64
    );
}
