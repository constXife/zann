//! Generates the Swift bindings for this crate's cdylib.
//! See `scripts/generate-swift-bindings.sh`.

fn main() {
    uniffi::uniffi_bindgen_main()
}
