# Stage 1 device and release gate (#276)

Status: **open**. Automated synthetic-replica and simulator results do not
qualify a physical device or a signed Release. Stage 2 (#277 onward) remains
gated on the complete record below. Publication is a separate action.

## Repeatable signed artifact preparation

Configure the ignored `Mobile.Local.xcconfig` with the signing team as described
in [README.md](README.md). Provision the mobile bundle ID, App Group and both
Keychain groups for distribution, and install the team's distribution signing
certificate/profile. Copy `Mobile.ExportOptions.example.plist` outside the
repository and replace its team ID. Keep `destination=export`: the script
exports locally and never submits to TestFlight.

From a clean committed checkout, with an unused absolute artifact directory
and an explicit App Store Connect build number:

```bash
bash apps/apple/release-mobile.sh /private/tmp/zann-stage1-release 123 /absolute/path/ExportOptions.plist
```

The script regenerates Release Rust slices/bindings, rejects fixture exports,
archives with the configured signing identities, checks executable symbols and
the signature, and exports the IPA. Retain the archive, IPA, SHA-256 manifest,
source revision, tool versions, export options and signed entitlements together.
Build number and source/toolchain identity make the procedure repeatable;
signatures/provisioning timestamps prevent a byte-identical-build promise.
Do not distribute an archive that has not passed the device gate. Regenerate
Debug bindings before returning to unit/UI tests.

## Verification record

For each run record the exact source revision, archive/IPA digest, build
number, device model, OS version, signing team, server revision and desktop
client revision. Keep passwords, tokens, key material and plaintext exports
out of reports, screenshots and diagnostic bundles. Use disposable test data
for mutation/termination tests. Remove exported destination copies afterward.

The earlier signed Debug acceptance on iPad mini (A17 Pro), iPadOS 27.0.1,
recorded in README, covers OIDC/unlock/initial and manual sync only. It does
not qualify this change or its Release archive. No iPhone or Release evidence
for #276 is recorded yet.

| Scenario | Physical iPhone | Physical iPad |
|---|---|---|
| Signed Release install; fixture symbols absent; expected entitlements | pending | pending |
| Fresh onboarding, password and OIDC; trust challenge; cancel/retry | pending | pending |
| First catalog visible before final page; personal and shared reads | pending | pending |
| Switch accounts on one server and vaults during sync; no key/context drift | pending | pending |
| Create/edit; desktop round-trip preserves item ID and count | pending | pending |
| Disable networking; relaunch; unlock/read/search/edit; pending data retained | pending | pending |
| Reconnect; drain pending changes; desktop sees one edited item | pending | pending |
| Refresh rejection/reconnect/logout preserve offline replica | pending | pending |
| Terminate during login, catalog/page sync and local save; relaunch | pending | pending |
| Network loss during login/push/pull; typed error and explicit recovery | pending | pending |
| Background with lock enabled and disabled; foreground/post-edit sync | pending | pending |
| Biometry change, protected-data loss, privacy cover and clipboard expiry | pending | pending |
| Export via Files; cancel, lock, background and process death remove temp data | pending | pending |
| Independent JSON parsing: v1, counts, item IDs, fields and metadata | pending | pending |
| Manual snapshot and verify; retained pending data; daily due check on resume | pending | pending |

For interruption cases capture whether the operation was pre-dispatch,
dispatched, durably committed or ambiguous. After relaunch check actual item
IDs, pending count and server state; a spinner disappearing is insufficient.
Ambiguous auth is recovered by the canonical journal and must not be silently
replayed. Local edits remain transactional and sync pages retain atomic
checkpoints. Existing Rust recovery tests exercise these boundaries; device
termination adds OS lifecycle evidence.

## Capabilities and limits

- Foreground sync and post-edit debounce use `AutoSyncSchedule`. Suspension
  stops the shell timer, and foreground admission preserves any running sync.
  No continuous execution while suspended is promised.
- Snapshot due/retention checks and manual snapshots use the canonical core
  operations. Launch and active-foreground opportunities run the daily check;
  there is no suspended timer. Encrypted snapshots stay in the App Group root
  and include the encrypted keyring and pending changes. A failed automatic
  snapshot is visible in Settings and does not prevent offline unlock.
- Export is the existing plaintext v1 JSON for all enrolled local account
  replicas. It requires unlock and every relevant account key. The native
  picker saves an explicit copy. Private staging is removed on completion,
  cancellation, dismissal, lock/background, partial failure and next launch
  after process death. A destination copy deliberately remains with its owner.
- Verify reports checked/readable items, skipped vaults and actual problems.
  Skipped vaults are never reported as verified. Mobile import and snapshot
  restoration UI are outside the supported surface. Pre-migration snapshot
  automation remains #246.
- The app deployment floor remains iOS 16; XCTest requires iOS 17. Record real
  coverage separately for the oldest supported OS and the tested current OS.

## Automated evidence

The mobile target runs the same progressive catalog/page, account/vault
navigation, offline/reopen, background scheduler and maintenance tests as
macOS. `MaintenanceTests` independently parses exported JSON and checks private
permissions, partial/late export cleanup, launch cleanup, snapshot due behavior,
integrity and pending-data restoration. UI tests cover the native maintenance
controls and their results on both simulator families. The CI Apple job also
builds Release device/simulator artifacts and rejects fixture symbols. Attach
the actual `.xcresult` and CI links to the release record when executed.

Local implementation verification on 2026-11-15 (working tree based on
`9a1e0d3`, Xcode 27.2, macOS 27.0.1):

```bash
cargo fmt --check
cargo fmt --manifest-path apps/cosmic/Cargo.toml --check
cargo clippy -p zann-client -p zann-ffi --all-targets --all-features -- -D warnings
cargo clippy -p zann-client-sqlite --all-targets --all-features -- -D warnings
cargo test -p zann-client --all-features
cargo test -p zann-ffi --features test-support
cargo test -p zann-client-sqlite --features local-vault
./scripts/check-client-architecture.sh
./scripts/check-audit-surface-deps.sh
apps/apple/ZannCoreKit/build-xcframework.sh debug --all-platforms
swift test --package-path apps/apple/ZannCoreKit
xcodebuild test -quiet -project apps/apple/Zann.xcodeproj -scheme Zann -destination 'platform=macOS,arch=arm64' -derivedDataPath apps/apple/build
bash apps/apple/test-mobile.sh
```

These checks passed. The full macOS run passed 93 tests and skipped 5 live-server
tests; the final focused maintenance/offline run passed 8 tests, including stale
picker completion. Swift bindings passed 6 tests. On iOS/iPadOS 27.2, both
iPhone 17 and iPad mini (A17 Pro) simulators passed 67 tests and skipped 2 live
connection tests. Retained `.xcresult` bundles are under `apps/apple/build/Logs/Test`
and `apps/apple/build/mobile/Logs/Test`. Existing Swift retroactive-conformance
warnings and a test-only QoS warning remain; they do not count as clean runtime
qualification of real devices.

The COSMIC test command was also attempted. The root Rust 1.92 toolchain is too
old for libcosmic; with installed Rust 1.99.1, compilation reaches the existing
`cosmic::dialog` imports, unavailable on macOS without Linux portal support.
COSMIC execution remains a Linux CI check. No dependency or platform feature was
changed to hide this limitation. This host has Apple Development identities,
but no Apple Distribution identity; TestFlight signing/export is still pending.

The final maintenance/offline/picker regression also passed with
`TEST_RUNNER_LIBDISPATCH_COOPERATIVE_POOL_STRICT=1`: 9 tests on each simulator
and 8 focused macOS tests. A separate macOS regression confirms that replacing
an existing `0644` destination retains the export's `0600` permissions.

A local **Apple Development-signed Release** archive was prepared at
`apps/apple/build/stage1-276/ZannMobile-development.xcarchive`, with signature
verification, signed entitlements and binary SHA-256 beside it. Its executable
digest is `ee31a8b0733ad8b8d9e9fb4854a103363f191d57ced9977480123ffd51ced3f5`.
Release bindings and both device/simulator binaries were checked for fixture
exports and test-support classes; none were found. The Release simulator build
also passed. This is a working-tree validation artifact, recorded by
`source-base.txt` / `source-status.txt`, not a clean-source distribution or a
device-qualified build. It has not been installed or published. Use the clean
checkout procedure above for the eventual distribution archive and TestFlight
IPA. Debug bindings were restored for normal development afterward.
