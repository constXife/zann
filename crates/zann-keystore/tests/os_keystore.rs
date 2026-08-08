//! Round-trip against the real OS credential store.
//!
//! Ignored by default: it needs a desktop session (Secret Service on Linux,
//! Keychain on macOS, Credential Manager on Windows) and writes a real entry.
//! Run it manually with:
//!
//! ```text
//! cargo test -p zann-keystore --test os_keystore -- --ignored
//! ```

#![cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]

use zann_keystore::{KeyringKeystore, Keystore};

#[test]
#[ignore = "requires a desktop session with an OS credential store"]
fn stores_and_reads_the_dwk_from_the_os_store() {
    let keystore = KeyringKeystore::new("zann-integration-test", "dwk");
    let status = keystore.status();
    assert!(
        status.supported,
        "no OS credential store available: {:?}",
        status.message
    );

    keystore.delete_dwk().expect("clean start");
    assert_eq!(keystore.load_dwk().expect("empty store"), None);

    let dwk = [42u8; 32];
    keystore.store_dwk(&dwk).expect("store");
    assert_eq!(keystore.load_dwk().expect("load"), Some(dwk.to_vec()));

    keystore.delete_dwk().expect("delete");
    assert_eq!(keystore.load_dwk().expect("load after delete"), None);
}
