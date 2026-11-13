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
  The form separates name and optional folder, labels standard inputs from
  the shared schema, and keeps editable keys/types under Additional fields.
  In search, Down or Return moves to the first result; the list then uses
  native arrow-key navigation. An empty result offers Clear search.
  Empty categories offer creation of their schema-selected type directly in
  the list; Trash has no creation action.
  Detail values are copy buttons with an icon, hover help and checkmark feedback;
  website fields have a separate browser action from the shared field projection.
  The sidebar's folder section is zann-ui-core's `build_folder_tree`.
- `Zann/Platform/` holds the macOS adapters: a pasteboard writer that marks
  values concealed and clears them on the configured timer, the held Option
  key that reveals masked values while pressed, and the lock triggers (input
  as activity, the idle tick, focus loss, hiding and minimizing) whose effect
  `AppModel` decides from `DevicePreferences`.
  The menu-bar key icon offers Open, Lock and Quit. Closing the window keeps
  Zann running; Open raises or restores its single window. Lock-on-hidden and
  idle lock continue to apply with the window closed, and Quit still honours
  clear-on-exit. Security event observers live for the app's lifetime.

- `Zann/Connect/` signs this Mac in to a server through the core's
  `RemoteSession`: probe and pin the server, confirm a changed fingerprint,
  then a password or browser sign-in. The core pins trust, keeps the session
  and decides when registration is offered. The account's personal vault
  then opens with its master password (or a new account creates one) and
  opens cached content immediately. The first sync runs in the background;
  the core then moves a still-empty session to the server's personal vault
  when no editor is open, and keeps choosing it after a restart.
- Card reads use one `item_detail` FFI call returning ordered/masked fields.
  Rust transfers payload field strings into the shared presentation projection;
  no full payload JSON crosses into Swift and back. `ItemDetailLoader` owns one
  read operation and cancels it on replacement, lock or release. Cancellation
  interrupts a pending SQLite future; an in-progress bounded crypto call can
  finish, after which its cancelled result is discarded.
  Replacing a card keeps the previous layout until the new projection is ready,
  masks its revealed values and disables its actions. Reveal/copy state resets
  with each selection; only an initial read longer than 150 ms shows a spinner.
- Every unlock opens cached content and syncs in the background.
  While unlocked the vault syncs on the core's `AutoSyncSchedule`: a couple
  of seconds after each save and every minute otherwise, one sync at a time;
  ⌘R syncs on demand and lock stops it. Lock is available through ⌘L and
  the Vault menu; it has no toolbar button. A vault that only lives on this Mac
  has no sync. The sidebar header selects the server/account storage with its
  compact sync icon; the vault selector stays in the row below.
  Sync progress stays in that icon. Clicking it shows the server address, last
  completed sync, errors and sync/reconnect/forget actions; no workspace banner
  appears during synchronization.
  Server and vault navigation remains available during network sync. Progress
  follows its original server; a late completion reloads only the current
  context and never restores a previous selection. Explicit navigation also
  cancels the first-sync automatic storage handoff.

- `Zann/SettingsView.swift` is the Settings window (⌘,) over the shared
  device preferences. `Zann/PreferencesFile.swift` keeps them in this app's
  own `preferences.json`, the client-private file docs/Architecture.md
  allows; zann-ui-core owns the stored form, defaults and option labels.

The database and `preferences.json` live in
`~/Library/Application Support/com.rlyeh.zann.apple/`, apart from the Tauri
desktop app's. The app is not sandboxed yet, so session tokens use the
login keychain.
