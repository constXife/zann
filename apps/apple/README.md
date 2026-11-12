# Zann for Apple platforms

SwiftUI macOS client over the Rust core. iOS and iPadOS targets come later;
the shared core is already built for them by `ZannCoreKit`.

```bash
apps/apple/ZannCoreKit/build-xcframework.sh debug
cd apps/apple
xcodegen --spec project.yml   # brew install xcodegen
open Zann.xcodeproj           # or: xcodebuild test -scheme Zann -destination 'platform=macOS,arch=arm64'
```

The server tests run against a live server with password sign-in, and skip
without one:

```bash
TEST_RUNNER_ZANN_REMOTE_URL=http://127.0.0.1:18081 \
  xcodebuild test -project Zann.xcodeproj -scheme Zann -destination 'platform=macOS,arch=arm64'
ZANN_REMOTE_URL=http://127.0.0.1:18081 cargo test -p zann-ffi --test remote_sync -- --ignored
```

`project.yml` is the source of the Xcode project; `Zann.xcodeproj` is
generated and ignored, so parallel branches never conflict on `.pbxproj`.

## Signing and Touch ID

Builds are ad-hoc signed by default (`Signing.xcconfig`), which is all CI and
the tests need. Touch ID unlock keeps the device key in the data protection
keychain behind a biometric access control (#146), and macOS lets only a
team-signed build with a provisioning profile use it. To try Touch ID locally:

```bash
cp apps/apple/Local.example.xcconfig apps/apple/Local.xcconfig   # set DEVELOPMENT_TEAM
cd apps/apple && xcodegen --spec project.yml && open Zann.xcodeproj
```

`Local.xcconfig` is ignored by git, so your team ID stays on your machine.
Without it Settings shows Touch ID as unavailable; the key is never stored
anywhere weaker.

## Boundaries

The app owns SwiftUI views and macOS adapters only. Crypto, sync, password
rules, URL normalization, field ordering and TOTP stay in Rust.

- `Zann/KeychainStores.swift` implements the core's `PlatformKeystore` port
  over the data protection keychain with a `.biometryCurrentSet` access
  control, and `PlatformSecretStore` with plain generic-password items.
- `Zann/AppModel.swift` sequences blocking core calls off the main actor;
  `ZannTests` drive it against the real core over a temporary database.
- `Zann/Vault/` is vault home: sidebar categories -> item list -> item
  detail, as `docs/ux/Layout-Responsive-Spec.md` orders them and COSMIC lays
  them out. Categories, filtering, field order, masking, field labels and TOTP
  come from zann-ui-core; labels read the shared `i18n/` catalogue.
  Create (⌘N) and edit (⌘E) open a sheet over a zann-ui-core `ItemDraftFfi`,
  which owns the type templates, validation and the stored payload.
  The sidebar's folder section is zann-ui-core's `build_folder_tree`.
- `Zann/Platform/` holds the macOS adapters: a pasteboard writer that marks
  values concealed and clears them on the configured timer, the held Option
  key that reveals masked values while pressed, and the lock triggers (input
  as activity, the idle tick, focus loss, hiding and minimizing) whose effect
  `AppModel` decides from `DevicePreferences`.

- `Zann/Connect/` signs this Mac in to a server through the core's
  `RemoteSession`: probe and pin the server, confirm a changed fingerprint,
  then a password or browser sign-in. The core pins trust, keeps the session
  and decides when registration is offered. The account's personal vault
  then opens with its master password (or a new account creates one) and
  syncs once; the core then moves the still-empty session to the server's
  personal vault and keeps choosing it after a restart.
- Every later unlock opens the vault at once and syncs in the background;
  ⌘R syncs on demand. A vault that only lives on this Mac has no sync.

- `Zann/SettingsView.swift` is the Settings window (⌘,) over the shared
  device preferences. `Zann/PreferencesFile.swift` keeps them in this app's
  own `preferences.json`, the client-private file docs/Architecture.md
  allows; zann-ui-core owns the stored form, defaults and option labels.

The database and `preferences.json` live in
`~/Library/Application Support/com.rlyeh.zann.apple/`, apart from the Tauri
desktop app's. The app is not sandboxed yet, so session tokens use the
login keychain.
