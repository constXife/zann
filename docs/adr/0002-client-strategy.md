# ADR 0002: Client strategy — Rust core and thin native shells

- **Status:** Accepted
- **Date:** 2026-08-09
- **Updated:** 2026-10-25
- **Context:** [ADR 0001](0001-shared-client-core.md) settled *how* clients
  share code (`[CORE]` in `zann-client::app` + `[PRESENTATION]` in
  `zann-ui-core` and `zann-flows`, with `zann-ffi` as the UniFFI edge adapter
  for non-Rust consumers). This ADR defines *which* clients exist, which trust
  model each serves, and in what order they are built.

## Context

### The product is two trust models

The split is a type in `zann-core`:

```rust
pub enum VaultEncryptionType { Client = 1, Server = 2 }
```

| | Personal + `Client` | Shared + `Server` |
|---|---|---|
| Who can read the payload | the client only | the server too |
| Server's role | opaque storage | trusted authority holding `ZANN_SMK` |
| Evidence | `vaults/service.rs:325` gates personal vaults on `Client` | `secrets/service.rs:751` unwraps SMK → vault key → payload and returns plaintext |
| Target clients | Native apps (COSMIC, Apple SwiftUI, Android Compose, Tauri desktop), Browser extension + local daemon | CLI (`run`, `materialize`, `template`, contexts, tokens), Web admin console |

`crates/zann-server/SECURITY.md:64-65` states it plainly: service accounts are
read/list, and only for shared server-encrypted vaults. These are two trust
models, and every client decision resolves once you ask which half it belongs
to.

### Why personal-vault clients must be native shells over the Rust core

For a password manager and passkey provider, the main application window is
used far less often than OS integration surfaces:

1. **System autofill and passkey extensions have tight memory and startup budgets.**
   On iOS and iPadOS, `ASCredentialProviderExtension` runs in a separate process
   under a ~120 MB memory ceiling and strict cold-start limits. On Android 14+,
   `CredentialProviderService` and `AutofillService` are invoked inline over
   arbitrary apps. Heavy cross-platform UI runtimes (WebView, JS VMs, or secondary
   engines) struggle under these constraints, and Argon2id cannot be lowered
   on-device because `kdf_fingerprint` binds `memory_kb` into the vault's
   identity (`crates/zann-crypto/src/passwords.rs`). The extension must unwrap a
   stored key from the platform keystore and query SQLite through a compact
   native binary (`libzann_ffi`).
2. **One Apple SwiftUI package covers three platforms.**
   Because macOS, iOS, and iPadOS share SwiftUI and the
   `ASCredentialProviderExtension` API, a native macOS app is a second build
   target of the same Swift package rather than a separate codebase.
3. **85–90% of client complexity is toolkit-neutral.**
   Cryptography (`zann-crypto`), SQLite persistence (`zann-db`,
   `zann-client-sqlite`), authentication, OIDC, TOFU trust, and bidirectional
   sync (`zann-client::app`), domain matching (`zann-autofill`), CTAP2 passkey
   ceremonies (`zann-passkey`), and presentation policy (`zann-ui-core`,
   `zann-flows`) live once in Rust. Each native client is a thin declarative UI
   shell (~1.5k–2.5k lines) plus 4–5 OS port adapters.

### Data portability and durability evidence come first

A client that holds personal data must be able to export that data unaided and
verify its local store. The storage layer (`crates/zann-db/src/lib.rs`) uses
SQLite WAL, `synchronous=Normal`, and a 5s busy timeout, complemented by:
- plain and encrypted backup export/import shared across Desktop and COSMIC;
- periodic consistent snapshots via SQLite `VACUUM INTO` into `~/.zann/snapshots/`;
- an unlocked `verify` pass that walks every item, decrypts it, and checks
  `payload_checksum`.

## Decision

**1. One Rust core, thin native shells per platform ecosystem.**
All security-, sync-, and presentation-sensitive logic lives in the Rust crates
defined in [`docs/architecture/capabilities.md`](../architecture/capabilities.md).
Native shells own only toolkit widgets and OS integration:

- **Linux (`apps/cosmic`):** Native `libcosmic` (Iced) client. Links Rust crates
  directly (`zann-client::app`, `zann-ui-core`). Serves as the reference client
  and pacesetter for the Rust core.
- **Apple — macOS, iPhone, iPad (`apps/apple`, planned):** A single multiplatform
  SwiftUI package consuming `zann-ffi` (UniFFI Swift bindings), paired with a
  native `ASCredentialProviderExtension` for system-wide password, TOTP, and
  passkey autofill across iOS, iPadOS, and macOS.
- **Android (`apps/android`, planned):** Native Kotlin and Jetpack Compose client
  consuming `zann-ffi` (UniFFI Kotlin bindings), paired with Android
  `CredentialProviderService` and `AutofillService`.
- **Desktop cross-platform (`apps/desktop`):** Existing Tauri (Vue + Rust) client
  covering Windows and cross-platform desktop workflows, migrating its legacy
  backend fork onto `zann-client::app` and `zann-ui-core` per
  [ADR 0001](0001-shared-client-core.md).

**2. COSMIC is the reference client for the Rust core.**
It is the daily driver used to prove new capabilities in `zann-client::app`,
`zann-ui-core`, and `zann-flows` in pure Rust before projecting them across
`zann-ffi` to Swift and Kotlin. Where a design choice trades shell convenience
against core clarity, core clarity wins.

**3. Export, snapshots, and integrity verification are mandatory baselines.**
Any client that can hold personal data must expose backup export, automatic and
manual SQLite snapshots (`VACUUM INTO`), and cryptographic payload verification
(`verify`).

**4. A web client is scoped to the server-encrypted half, permanently.**
Shared vaults and administration only (`/v1/groups`, `/v1/vaults/:vault_id/members`,
service accounts, policies); personal vaults never appear in a browser. For
shared server-encrypted vaults, the server holds `ZANN_SMK` by construction, so
a web UI concedes nothing outside the threat model and requires no client-side
vault cryptography.

**5. The browser extension and local daemon are the highest-value additions for
personal vaults on desktop.**
The browser extension is a thin view communicating with a stateless Rust
native-messaging host (`zann-native-host`) connected to `zann-daemon`:

```text
zann-daemon  (unlocked session, ~/.zann, zann-client::app)
    ├── COSMIC UI / desktop shell
    ├── zann-native-host → browser extension (autofill + passkeys)
    └── CLI and future local adapters
```

**6. Native Apple (iOS/iPadOS/macOS) and Android clients follow facade and
autofill stabilization.**
Because `zann-autofill`, `zann-passkey`, `zann-ui-core`, and `zann-client::app`
are written and tested in Rust first (via COSMIC and the browser host), the
SwiftUI and Jetpack Compose clients arrive onto a stable, battle-tested UniFFI
contract rather than debugging sync and domain matching across three languages.

## Consequences

**Good.**
- Every platform gets first-class native UX, minimal memory footprint (~25 MB
  anonymous RSS in COSMIC, <30 MB in mobile autofill extensions), and native OS
  credential-provider integration.
- Security and sync fixes land once in Rust.
- One SwiftUI codebase covers iPhone, iPad, and native macOS (including Safari
  and system AutoFill).
- Stabilizing the core on COSMIC and the native-messaging host first prevents
  cross-language churn in Swift and Kotlin.

**Bad.**
- Maintaining native view layers (`libcosmic`, SwiftUI, Jetpack Compose)
  requires strict discipline so presentation rules stay in `zann-ui-core` and
  never drift into UI code.
- `zann-daemon` introduces an additional local process to supervise on desktop.
- Shared-Core crates (`zann-client`, `zann-ui-core`, `zann-ffi`) must keep their
  dependency graphs free of desktop-only C libraries so cross-compilation to
  `aarch64-apple-ios`, `aarch64-apple-darwin`, and `aarch64-linux-android`
  remains frictionless.

## Sequencing

1. **Durability baseline (Complete):** Shared backup export/import, `VACUUM INTO`
   snapshots, and `verify` across Desktop and COSMIC.
2. **Core & COSMIC reference alignment (Active):** Complete [ADR 0001](0001-shared-client-core.md)
   migrations (`MIG-001`..`MIG-008`), keeping COSMIC and Desktop on canonical
   `zann-client::app` and `zann-ui-core`.
3. **Browser integration & passkeys:**
   `zann-autofill`, `zann-passkey`, `zann-daemon`, `zann-native-host`, and the
   Chromium/Firefox extension.
4. **UniFFI surface lock & Apple / Android native clients:** Turn on CI binding
   generation (`swift` / `kotlin`) and cross-compile checks on `zann-ffi`, then
   build `apps/apple` (iOS/iPadOS/macOS SwiftUI + AutoFill extension) and
   `apps/android` (Jetpack Compose + Credential Provider).
5. **Web administration console:** Over the shared server-encrypted half.

## Alternatives considered

**A cross-platform mobile/desktop UI framework everywhere (Flutter, React Native, or Tauri Mobile).**
Rejected: mobile password managers live or die by their system AutoFill and
Passkey credential provider extensions, which require native extension targets,
strict memory limits (~120 MB on iOS), and native biometric/keystore bridges.
Sharing 85–90% of the code in Rust while keeping the 10–15% view layer native
in SwiftUI, Jetpack Compose, and `libcosmic` yields a smaller, faster, and more
reliable product.

**A web UI over personal vaults too.**
Rejected: puts the end-to-end encryption guarantee at the mercy of every page
load for a convenience the browser extension and native clients serve safely.

**An extension that talks to the server directly instead of a local daemon.**
Rejected: personal vaults are client-encrypted, so the extension would need the
master key inside the browser profile and offline-first would be lost.

**Dropping COSMIC and standardizing only on Tauri.**
Rejected: COSMIC is the maintainer's daily driver, exercises the Rust core
directly in `cargo test` without a WebView, and costs only ~6k lines of native
view code.
