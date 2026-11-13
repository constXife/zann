# ADR 0002: Client strategy — Rust core and thin native shells

- **Status:** Accepted
- **Date:** 2026-08-09
- **Updated:** 2026-11-13
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
| Target clients | Native apps (COSMIC, Apple SwiftUI, Android Compose), Browser extension + local daemon | CLI (`run`, `materialize`, `template`, contexts, tokens), Native apps (device/member/group management), optional post-`1.0` Web admin console |

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
- **Apple — macOS, iPhone, iPad (`apps/apple`; macOS active, iOS/iPadOS planned):**
  A single multiplatform SwiftUI package consuming `zann-ffi` (UniFFI Swift
  bindings), paired with a native `ASCredentialProviderExtension` for
  system-wide password, TOTP, and passkey autofill across iOS, iPadOS, and macOS.
- **Android (`apps/android`, planned):** Native Kotlin and Jetpack Compose client
  consuming `zann-ffi` (UniFFI Kotlin bindings), paired with Android
  `CredentialProviderService` and `AutofillService`.
- **Legacy Tauri desktop (`apps/desktop`, scheduled for Pre-GA removal):** Now
  that native Linux (`apps/cosmic`) and macOS (`apps/apple`) clients exist, the
  ~27k-line Vue + `src-tauri` fork carries disproportionate `MIG-*` and CI
  overhead solely for Windows. Rather than migrating its legacy backend,
  `apps/desktop` will be retired Pre-GA; Windows workflows will be served by
  `zann-daemon` + the browser extension and a thin native/Iced shell over the
  stabilized core.

Until that removal lands, Tauri remains a shipping legacy consumer subject to
the existing capability map, `MIG-*` limits and GUI parity rules. This decision
does not mark its replacement Windows shell or browser integration as shipped.

**2. COSMIC is the reference client for the Rust core.**
It is the daily driver used to prove new capabilities in `zann-client::app`,
`zann-ui-core`, and `zann-flows` in pure Rust before projecting them across
`zann-ffi` to Swift and Kotlin. Where a design choice trades shell convenience
against core clarity, core clarity wins.

**3. Export, snapshots, and integrity verification are mandatory baselines.**
Any client that can hold personal data must expose backup export, automatic and
manual SQLite snapshots (`VACUUM INTO`), and cryptographic payload verification
(`verify`).

**4. No interactive web UI pre-`1.0`; human administration lives in native clients and CLI.**
Personal vaults never appear in a browser. Furthermore, keeping `zann-server` a
pure Bearer-authenticated JSON API avoids introducing cookie sessions, CSRF,
stored XSS adjacent to `ZANN_SMK`, and unpinned browser sessions pre-`1.0`:
- Human administration (`devices`, `members`, `groups`, shared-vault access) is
  exposed over the existing JSON API through `zann-client` in native shells
  (`COSMIC`, `Apple`) and `zann-cli`.
- `GET /` on `zann-server` serves only a static, cookie-free, JS-free read-only
  status and onboarding card (`Content-Security-Policy: default-src 'none'`).
- Any future interactive web console post-`1.0` remains permanently scoped to
  the shared server-encrypted half and disabled by default
  (`web_admin.enabled = false`).

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

### Server-anchored offline replicas (#241)

Native clients require server login or registration before setting a master
password. Config v2's account identity is the single KDF source; SQLite starts
without a storage or vault. The first sync supplies the server catalog and
personal key. There is no standalone serverless vault mode.

Once synced, cached vaults remain usable offline, including unlock, reading,
search, editing with pending changes, backup export, snapshots and verify.
Forgetting a connection retains that disconnected replica. Personal vault keys
and plaintext remain inside the client boundary; server-first setup does not
change the personal/shared trust split.

The implementation reuses Config v2 authentication and the existing sync CAS,
local-vault port and native persistence owner. A feature-gated synthetic server
replica supplies network-free development and UI tests. Migration 0004 removes
only empty legacy local storages; nonempty local-only data aborts transactionally
and requires export with the older client before upgrading. See the
[cutover guide](../migrations/server-first-clients.md).

The repository has no separate values manifest. Against the invariants in
`AGENTS.md` and the capability map, each mechanism has the following tradeoff:

- **Account-owned identity and catalog:** one source replaces local salts and
  fallback vault creation. The existing trust and credential transactions stay
  authoritative; personal E2EE is unchanged. First use requires network access,
  while subsequent offline access adds no network dependency.
- **Fail-closed migration:** preserves secret custody and crash safety rather
  than reinterpreting data under a different account key. Upgrade requires one
  schema transaction; owners of nonempty legacy local data must export before
  upgrading. No automatic conversion or recovery protocol is added.
- **Explicit fixtures:** reuse the native adapter and crypto owner. Synthetic
  data is confined to an opt-in test/dev feature, with no authenticated session
  or production fallback. The same fixture serves Rust and Swift tests.

Keeping both standalone and server-backed modes was rejected: it preserves two
KDF origins and cross-shell selection branches without a coherent account
transition. This pre-GA cutover removes those paths in place.

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
   snapshots, and `verify` in `zann-client-sqlite` across native clients.
2. **Retire `apps/desktop` (Tauri) & finish core alignment (Active):** Port
   server-backed plain backup import into canonical `LocalVault`, delete
   `apps/desktop` and its JS/WebDriver CI jobs, and retire the Tauri-only
   `MIG-001`..`MIG-006` legacy exceptions, keeping `COSMIC` and `Apple` on
   canonical `zann-client::app` and `zann-ui-core`.
3. **Browser integration & passkeys:**
   `zann-autofill`, `zann-passkey`, `zann-daemon`, `zann-native-host`, and the
   Chromium/Firefox extension.
4. **UniFFI surface lock & Apple / Android native clients:** Turn on CI binding
   generation (`swift` / `kotlin`) and cross-compile checks on `zann-ffi`,
   expand `apps/apple` (`ASCredentialProviderExtension` + iOS/iPadOS targets),
   and build `apps/android` (Jetpack Compose + Credential Provider).
5. **Native administration & read-only server status card:** Serve a static,
   cookie-free/JS-free status card on `GET /` in `zann-server`, and expose
   `devices`, `members`, and `groups` management in `zann-client`, native shells
   (`COSMIC`, `Apple`), and `zann-cli` (deferring any opt-in web admin console
   past `1.0`).

## Alternatives considered

**A cross-platform mobile/desktop UI framework everywhere (Flutter, React Native, or Tauri Mobile).**
Rejected: mobile password managers live or die by their system AutoFill and
Passkey credential provider extensions, which require native extension targets,
strict memory limits (~120 MB on iOS), and native biometric/keystore bridges.
Sharing 85–90% of the code in Rust while keeping the 10–15% view layer native
in SwiftUI, Jetpack Compose, and `libcosmic` yields a smaller, faster, and more
reliable product.

**Keeping `apps/desktop` (Tauri) alive alongside `apps/cosmic` and `apps/apple`.**
Rejected: `apps/desktop` (~19.5k lines of Vue/TS + ~7.3k lines of legacy
`src-tauri` Rust) exceeds `apps/cosmic` (~7.6k lines) and `apps/apple` (~3.4k
lines) combined by 2.5×, owns nearly the entire `MIG-001`..`MIG-006` debt ledger
and five dedicated CI jobs, and duplicates Linux and macOS coverage already
served natively.

**A web UI over personal vaults too.**
Rejected: puts the end-to-end encryption guarantee at the mercy of every page
load for a convenience the browser extension and native clients serve safely.

**Shipping an interactive web admin console before `1.0`.**
Rejected for Pre-GA: turning `zann-server` from a Bearer-only JSON API into an
interactive HTML/JS application introduces cookie/CSRF, stored-XSS, and
unpinned browser session risks adjacent to `ZANN_SMK`, whereas `devices`,
`members`, and `groups` JSON endpoints already exist and can be driven safely
from native shells and `zann-cli`.

**An extension that talks to the server directly instead of a local daemon.**
Rejected: personal vaults are client-encrypted, so the extension would need the
master key inside the browser profile and offline-first would be lost.

**Dropping COSMIC and standardizing only on Tauri.**
Rejected: COSMIC is the maintainer's daily driver, exercises the Rust core
directly in `cargo test` without a WebView, and costs only ~6k lines of native
view code.
