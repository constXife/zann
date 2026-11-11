# ZannCoreKit

Swift package that exposes the Rust core (`crates/zann-ffi`) to the Apple
shells. It wraps `ZannFFI.xcframework` (static `libzann_ffi.a` for macOS, iOS
and the iOS simulator, arm64 only) and the UniFFI-generated Swift bindings.
Both live in `Generated/` and are rebuilt, not committed.

```bash
apps/apple/ZannCoreKit/build-xcframework.sh debug
swift test --package-path apps/apple/ZannCoreKit
```

`Package.swift` `platforms` is the source of the macOS and iOS deployment
targets; the build script exports them to `cargo`. The `cc` crate does not
rebuild C objects when `IPHONEOS_DEPLOYMENT_TARGET` changes, so after building
`zann-ffi` for iOS without the script, run
`cargo clean -p blake3 --target aarch64-apple-ios` (and `-sim`) first.

No policy lives here: crypto, sync, URL normalization, field ordering and TOTP
stay in Rust (see `docs/architecture/capabilities.md`).
