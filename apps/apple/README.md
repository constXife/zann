# Zann for Apple platforms

SwiftUI macOS client over the Rust core. iOS and iPadOS targets come later;
the shared core is already built for them by `ZannCoreKit`.

```bash
apps/apple/ZannCoreKit/build-xcframework.sh debug
cd apps/apple
xcodegen --spec project.yml   # brew install xcodegen
open Zann.xcodeproj           # or: xcodebuild test -scheme Zann -destination 'platform=macOS,arch=arm64'
```

`project.yml` is the source of the Xcode project; `Zann.xcodeproj` is
generated and ignored, so parallel branches never conflict on `.pbxproj`.

## Boundaries

The app owns SwiftUI views and macOS adapters only. Crypto, sync, password
rules, URL normalization, field ordering and TOTP stay in Rust.

- `Zann/KeychainStores.swift` implements the core's `PlatformKeystore` and
  `PlatformSecretStore` ports with generic-password Keychain items.
- `Zann/AppModel.swift` sequences blocking core calls off the main actor;
  `ZannTests` drive it against the real core over a temporary database.
- `Zann/Vault/` is vault home: sidebar categories -> item list -> item
  detail, as `docs/ux/Layout-Responsive-Spec.md` orders them and COSMIC lays
  them out. Categories, filtering, field order, masking, field labels and TOTP
  come from zann-ui-core; labels read the shared `i18n/` catalogue.
  Create (⌘N) and edit (⌘E) open a sheet over a zann-ui-core `ItemDraftFfi`,
  which owns the type templates, validation and the stored payload.
- `Zann/Platform/` holds the macOS adapters: a pasteboard writer that marks
  values concealed and clears them on the configured timer, and the held
  Option key that reveals masked values while pressed.

The database lives in `~/Library/Application Support/com.rlyeh.zann.apple/`,
apart from the Tauri desktop app's. The build is ad-hoc signed and not
sandboxed yet, so Keychain items use the login keychain.
