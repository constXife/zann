//! Generates the Swift bindings for this crate's library.
//! See `apps/apple/ZannCoreKit/build-xcframework.sh`.

fn main() {
    uniffi::uniffi_bindgen_main()
}
