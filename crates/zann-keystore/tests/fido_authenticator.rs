//! Round-trip against a real FIDO2 authenticator.
//!
//! Ignored by default: it needs a token that supports `hmac-secret` physically
//! connected, and it asks for three touches. It also leaves one non-discoverable
//! credential behind — those consume no storage on the authenticator, so there
//! is nothing to clean up. Run it manually with:
//!
//! ```text
//! cargo test -p zann-keystore --test fido_authenticator -- --ignored
//! ```

#![cfg(any(target_os = "linux", target_os = "macos"))]

use zann_keystore::fido;

#[test]
#[ignore = "requires a connected FIDO2 authenticator and three touches"]
fn enrols_derives_and_detects_the_authenticator() {
    fido::authenticator_status().expect("an authenticator must be connected");

    eprintln!("touch the key twice to enrol");
    let salt: [u8; 32] = rand::random();
    let (credential, enrolled_key) = fido::enroll(salt).expect("enrol");
    assert!(!credential.credential_id.is_empty());

    eprintln!("touch the key to derive");
    let first = fido::derive_dwk(&credential).expect("derive");
    assert_eq!(
        first, enrolled_key,
        "enrolment must hand back the same key a later unlock derives"
    );

    eprintln!("touch the key to derive again");
    let second = fido::derive_dwk(&credential).expect("derive again");
    assert_eq!(first, second, "the DWK must be reproducible");

    // No touch from here on.
    assert!(
        fido::is_present(&credential),
        "the enrolled authenticator is connected, so presence must be detected"
    );

    let stranger = fido::HardwareCredential {
        credential_id: vec![7u8; 64],
        salt,
    };
    assert!(
        !fido::is_present(&stranger),
        "a credential from some other authenticator must not count as present"
    );

    // A different salt is a different key: this is what lets two vaults share
    // one authenticator without sharing a wrapping key.
    eprintln!("touch the key once more to check salt separation");
    let other_salt = fido::HardwareCredential {
        credential_id: credential.credential_id.clone(),
        salt: rand::random(),
    };
    let derived = fido::derive_dwk(&other_salt).expect("derive with another salt");
    assert_ne!(first, derived);
}
