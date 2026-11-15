# Zann for Apple platforms

SwiftUI macOS client over the Rust core. iOS and iPadOS app targets are planned;
`ZannCoreKit` can also package the core for those platforms.

## Prerequisites (Apple silicon)

- Full Xcode, selected with `sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer`.
  Open Xcode once to accept its license and finish initial component installation.
  Command Line Tools alone do not provide XCFramework packaging.
- Rust installed through [rustup](https://rustup.rs/). The repository's
  `rust-toolchain.toml` selects the workspace toolchain.
- `jq` (the build script reads Cargo metadata and `Package.swift`) and
  XcodeGen (generates the app project):

```bash
brew install jq xcodegen
rustup target add aarch64-apple-darwin
```

Run these commands from the repository root so rustup uses its pinned toolchain.
The local build requires only the macOS SDK and Rust target; iOS components are
not needed.

## Build and run

For a new account, first [start the development server](../../README.md#1-start-a-server)
or use an existing server. From the repository root:

```bash
apps/apple/ZannCoreKit/build-xcframework.sh debug
cd apps/apple
xcodegen --spec project.yml
open Zann.xcodeproj
```

Run the Zann scheme in Xcode, connect to `http://localhost:8080` (or your server),
sign in or register, then create/unlock your personal vault with its master
password. After the first sync, cached vaults can be used offline.

`build-xcframework.sh <debug|release>` replaces `Generated/` with a macOS-only
XCFramework and Swift bindings. For the full arm64 macOS + iOS + iOS simulator
package used in CI, install the iOS SDK/platform components in Xcode and run:

```bash
rustup target add aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim
apps/apple/ZannCoreKit/build-xcframework.sh debug --all-platforms
```

The script checks tools, Rust targets and the requested SDKs before compiling.
Deployment versions come from `ZannCoreKit/Package.swift`.

## Tests

```bash
swift test --package-path apps/apple/ZannCoreKit
cd apps/apple
xcodebuild test -project Zann.xcodeproj -scheme Zann -destination 'platform=macOS,arch=arm64'
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

## iPhone and iPad target (#273)

Build the debug XCFramework with `--all-platforms` and generate the project as
above, then select the `ZannMobile` scheme. One application supports both device families;
its source list contains common models, connect/unlock and item detail UI, not
AppKit, Carbon, desktop pairing or the daemon lifecycle. There are no production
fake secret adapters or automatic fixture activation.

`project.yml` defines the mobile bundle/App Group/DWK service/Keychain group
identities once. XcodeGen generates the ignored `Mobile/Info.plist`; Xcode
expands the same settings into that plist and `Mobile/ZannMobile.entitlements`.
`ZannCoreKit/build-xcframework.sh` generates `Generated/BuildSettings.xcconfig`
from `Package.swift`, so the application and Rust slices share the iOS 16 floor.
Test runners alone use the iOS 17 XCTest floor in `MobileTests.xcconfig`.

Run the app, shared composition tests, synthetic-replica smoke test and launch
UI test on both device families using installed simulator runtimes:

```bash
bash apps/apple/test-mobile.sh
```

The script selects one iPhone and the iPad mini (A17 Pro) profile from the
newest installed iOS runtime. It creates that exact mini simulator if needed,
runs both destinations serially with a separate Xcode invocation and result
bundle for each, and errors when the required runtime/profile is unavailable.
This keeps the reference tablet aligned with the physical mini.
It never downloads a runtime or substitutes another test platform. The Apple
CI job runs it after macOS tests and retains mobile `.xcresult` bundles on every run.
Blocking FFI effects use the shared `BlockingCore.run` Dispatch adapter so a
network, storage or native-prompt wait cannot occupy Swift's cooperative pool.
Operation admission and cancellation remain with the existing flow/core ports;
CI tests run with a single cooperative worker to check forward progress.
Test ports live in `DebugSupport/` and are compiled for tests and the explicit
Debug UI-fixture host only; Release excludes their definitions. The replica
fixture comes from the existing Rust `test-support` debug binding.
The Debug unit-test host opens an empty scene so tests own every temporary
core; this host is excluded from Release.

`MobileWorkspaceTests` explicitly passes `--mobile-ui-fixture` to launch a
fresh temporary replica and `--mobile-ui-large-text` for accessibility text.
Neither argument activates test code in Release. The UI tests capture
portrait/landscape navigation, scroll retention, masked detail, editor drafts
with the software keyboard, settings and onboarding. CI exports the retained
attachments as `mobile-ui-captures`; inspect those images before accepting the
layout on both families. Local execution still requires an installed runtime.

The local reference tablet is iPad mini (A17 Pro). The iPadOS 27.2 simulator
passes the mobile suite, including keyboard/rotation draft retention,
portrait/landscape scroll retention and accessibility text in the editor and
settings. These simulator checks do not replace signed-device acceptance on
the physical mini running iPadOS 27.0.1.

For real-device HTTPS acceptance, run only `LiveConnectionTests` with
`TEST_RUNNER_ZANN_LIVE_SERVER` set to the intended HTTPS server. Its native
URLSession request checks system CA trust before the actual application's
connect probe. It uses no fixture, passwords or vault mutations. iOS uses the
system TLS backend for every shared-core HTTP client, so a private CA must be
installed and explicitly trusted on the
device. Apple's native TLS backend currently negotiates TLS 1.2.

`LiveConnectionTests/testInteractiveSignInAndInitialSync` additionally requires
`TEST_RUNNER_ZANN_LIVE_INTERACTIVE=1` and `TEST_RUNNER_ZANN_LIVE_ISSUER`.
It opens the configured OIDC provider, while the device owner supplies
credentials, master-password unlock and biometrics. It waits for a successful
first sync, runs a manual sync and verifies that the success timestamp changes.
Run this test individually on the paired device with
`-collect-test-diagnostics never`; it does not create or edit vault records.

Signed-device acceptance of `main` (`0c6bef4`) on iPad mini (A17 Pro),
iPadOS 27.0.1, passed on 2026-11-15 with the integrated account/device key model:
Rauthy OIDC sign-in, device-password setup, account-key unlock, initial record
synchronization, password/Touch ID unlock after relaunch and manual sync with
a new success timestamp. The final live UI test passed over USB without runtime
warnings. It activates an existing session and selects the visible sync button;
compact navigation can retain hidden toolbar buttons from earlier screens.
The earlier development replica used a different migration 0005. Its owner-only
snapshot was verified to contain no unsent changes before the owner explicitly
approved local reinitialization and a fresh server sync. No migration checksum
was bypassed, and no automatic reset or compatibility path was added.
Bidirectional edit propagation, offline behavior and the remaining lifecycle
scenarios below still require separate device acceptance.

## Adaptive workspace (#275)

iPhone and narrow iPad windows use full-screen context/list/detail navigation.
At regular widths of 900 points or more, iPad shows three native columns;
accessibility text uses the stack. Context, selection, list bookmarks and
the shared Rust editor draft survive that switch. Editing is a full-screen,
scrolling form with Save/Cancel reachable above the keyboard. Settings reuse
the macOS language, lock, clipboard, reveal and biometric preference controls.
The layout contract is in `docs/ux/Layout-Responsive-Spec.md`.

For a signed device build, copy `Mobile.Local.example.xcconfig` to
`Mobile.Local.xcconfig`, set your Apple team, and register/enable the target's
App Group and both Keychain access groups in Xcode. Select your connected
iPhone/iPad and build `ZannMobile`. The local file is ignored; do not reuse the
macOS signing override, which selects different entitlements.

Before any Release build, regenerate bindings without test-support:

```bash
apps/apple/ZannCoreKit/build-xcframework.sh release --all-platforms
xcodebuild build -project apps/apple/Zann.xcodeproj -scheme ZannMobile \
  -configuration Release -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO
```

The mobile build phase rejects a Debug/Release mismatch with the generated
Rust profile. CI also rejects fixture exports in release bindings and builds
both device and simulator Release artifacts. The workspace preserves host
build-tool symbols to avoid [Rust's Mach-O stripping bug](https://github.com/rust-lang/rust/issues/157750)
on macOS 27; shipped Rust libraries keep their normal release profile.
Regenerate `debug` bindings before returning to app tests. An unsigned build
does not validate entitlements; signed acceptance requires a configured team.

## Offline use, maintenance and release gate (#276)

Stage 1 maintenance, offline/foreground regression coverage and the remaining
signed-device release gate are tracked in
[device-validation.md](device-validation.md). Settings now exposes the canonical
JSON export, encrypted snapshots and integrity verification on both Apple
platforms. Automatic snapshots run at launch and foreground opportunities;
foreground sync and post-edit debounce retain canonical scheduler admission.

## Storage and mobile composition (#272)

macOS keeps `Application Support/<app bundle identifier>/local.sqlite`, its
existing bundle-identifier DWK service and the core-owned token namespaces.
The platform composition resolves that root once for both core and preferences.
The Rust native opener canonicalizes the database parent and owns Config v2,
lock files and snapshots below that same root. No data is relocated.

`MobileIdentity` requires four explicit target-configured values: App Group
identifier, DWK service, vault Keychain access group and app-only token Keychain
access group. App and future provider must use the same App Group, DWK service
and vault group; the provider must not receive the app's token group entitlement.
DWK account naming stays in the platform keystore; token service/account naming
stays in the Rust credential owner. No identity comes from the extension's bundle ID.

`MobileComposition` resolves only the requested App Group container, using
`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)` when the
mobile target supplies the resolver. Its permanent relative client root is
`Library/Application Support/Zann/`, containing `local.sqlite` and
`preferences.json`. An unavailable container, unresolved identity setting or
invalid root is an error, without a private-container fallback. Token and vault
groups must differ; the token group cannot be the shared App Group itself.

The mobile target supplies configuration and App Group entitlements. Its
Keychain adapters apply the exact access group to
every Keychain add/read/update/delete and let missing entitlements fail closed.
The common opener never starts desktop IPC. Cross-process provider access,
independent unlock and grant revocation remain #277; a shared directory alone
does not establish their authorization or migration contract.

`CompositionTests` uses temporary roots and in-memory ports to verify root and
namespace selection, error propagation and the absence of desktop IPC.

## Mobile authentication and lifecycle (#274)

The iOS composition opens the configured App Group replica with the shared
Keychain ports. The DWK uses `WhenPasscodeSetThisDeviceOnly` plus
`biometryCurrentSet`; tokens use the distinct app-only group and
`AfterFirstUnlockThisDeviceOnly`. Actual Keychain operations enforce each
entitlement; iOS does not use macOS's `SecTask` API or substitute another store.
The prompt reason comes from the shared language catalogue, and an active
`LAContext` is invalidated when backgrounding cancels an unlock.

Password registration/login, TOFU challenges, device-password setup/unlock and account-key enrollment
and credential-aware logout use the existing Rust application facade. Logout
locks locally first and retains the offline replica. The mobile workspace
exposes manual sync and remembered biometric unlock alongside read/search/copy.
The mobile unlock screen also offers server sign-in again; backing out returns
to offline unlock without deleting the replica.

For OIDC, register the exact generated `ZannOIDCRedirectURI` with the existing
**public/native IdP client** using Authorization Code + PKCE S256. The default
is `com.rlyeh.zann.mobile:/oidc/callback`; it derives from
`ZANN_OIDC_CALLBACK_SCHEME` in `project.yml`. Keep the desktop loopback redirect
policy for desktop clients. Do not add a client secret to the app or relax
redirect/TLS rules. The Zann server's issuer/client ID configuration and HTTP
API are unchanged; the IdP registration needs this additional redirect URI.

`ASWebAuthenticationSession` receives the authorization URL and returns only
its OS-delivered callback URI. Rust checks the exact redirect, unique query
fields and state before exchanging the code with the same URI and verifier.
Provider/Zann tokens and the PKCE verifier never enter Swift. The callback URI
is transient and is never logged or persisted. The prepared login is consumed
once; cancellation/deadline stops provider I/O, while the existing session owner
retains its durable dispatch/commit rules. The system sheet uses the remaining
Rust operation deadline and is dismissed on cancellation/backgrounding.

UIKit installs an opaque window cover synchronously on loss of activity and
resets transient reveal/password view state. Background invalidation happens
before awaiting key cleanup. A late KDF/biometric result cannot reopen the UI;
the core is closed again after it finishes. A bounded OS background execution
lease gives cleanup time; auth recovery still tolerates process death.

Mobile clipboard writes are local-only and carry the configured native
expiration date, which works while the app is suspended. Generation/change-count
checks protect a newer clipboard from old timers or foreground reconciliation.
Configured clear-on-lock/exit effects run before suspension, without depending
on a termination callback.

Shared security tests cover clipboard ownership and the background/unlock race
using temporary replicas and in-memory ports; Rust tests cover callback/state,
PKCE exchange and cancellation. Device-only acceptance still requires a signed
iPhone and iPad: password and OIDC-only servers, cancel/retry, Face ID/Touch ID,
biometric enrollment changes, protected-data unavailability, app-switcher
redaction, background/kill/relaunch and clipboard replacement across suspension.

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
  Left-clicking the menu-bar key icon opens its single window; right-clicking
  (or Ctrl-clicking) offers Open, Lock and Quit. Closing the window keeps
  Zann running; Open raises or restores its single window. Lock-on-hidden and
  idle lock continue to apply with the window closed, and Quit still honours
  clear-on-exit. Security event observers live for the app's lifetime.
  By default, closing the last window also hides the Dock icon; reopening a
  window restores it. Minimized windows keep the icon. General settings can
  keep the icon visible after closing, using a macOS-only UserDefaults preference.

- `Zann/Connect/` signs this Mac in to a server through the core's
  `RemoteSession`: probe and pin the server, confirm a changed fingerprint,
  then a password or browser sign-in. The core pins trust, keeps the session
  and decides when registration is offered. The account's personal vault
  then opens with its master password (or a new account creates one) and
  opens cached content immediately. The first sync runs in the background;
  the core selects the first catalog when it arrives. Until then the workspace
  has no selected replica or vault, and cannot create records. No standalone
  identity or fallback Local vault is created.
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
  the Vault menu; it has no toolbar button. The sidebar header selects the
  server/account storage with its compact sync icon; the vault selector stays
  in the row below.
  Sync progress stays in that icon. Clicking it shows the server address, last
  completed sync, errors and sync/reconnect/forget actions; no workspace banner
  appears during synchronization.
  Server and vault navigation remains available during network sync. Progress
  follows its original server; a late completion reloads only the current
  context and never restores a previous selection. Explicit navigation also
  is preserved when the first catalog arrives.
  The local port reports durable catalog/page commits through a metadata-only
  FFI callback. The first catalog exposes server/vault selectors before the
  pull completes; each committed page can refresh the current list. Both the
  Rust bridge and Swift relay retain only the latest pending notice, with one
  UI reload at a time. First-sync empty views explain that items are arriving;
  cached background sync does not replace the workspace with a loading screen.

- `Zann/SettingsView.swift` is the Settings window (⌘,) over the shared
  device preferences. `Zann/PreferencesFile.swift` keeps them in this app's
  own `preferences.json`, the client-private file docs/Architecture.md
  allows; zann-ui-core owns the stored form, defaults and option labels.

The database and `preferences.json` live in
`~/Library/Application Support/com.rlyeh.zann.apple/`, in the Apple shell's
explicit application-data container. The app is not sandboxed yet, so session tokens use the
login keychain.
