//! Regression coverage for canonical client/FFI feature unification.

use std::path::PathBuf;

use zann_client::app::ClientId;
use zann_client::config::ClientPaths;

#[test]
fn canonical_app_client_and_ffi_can_coexist() {
    let paths = ClientPaths::new(PathBuf::from("/tmp/zann-coexistence-config"));
    assert!(paths.root().is_absolute());
    assert_eq!(
        ClientId::new("desktop").expect("client id").as_str(),
        "desktop"
    );
}
