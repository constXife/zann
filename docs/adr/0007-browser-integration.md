# ADR 0007: Browser integration — trust boundary, matching, and what lives in JavaScript

- **Status:** Proposed
- **Proposed:** 2026-09-02
- **Scope:** the native-messaging host and browser extension of
  [ADR 0002](0002-client-strategy.md), Decision §5, a new
  `zann-autofill` crate, and the `login` payload
- **Related:** [ADR 0006](0006-passkey-provider.md) rides the same channel
- **Out of scope:** global autotype (see ADR 0006, *Alternatives considered*)

This proposal defines owners and trust boundaries. Phases 0–4 now have
implementation contracts below (#198, #199, Chromium #25); Firefox and store
publication remain distribution work with their own platform admission checks.

## Context

ADR 0002, Decision §5 decided two things about the extension and stopped: it reaches
the core through a native-messaging host, and a daemon owns the unlocked session
because the host cannot share COSMIC's. At proposal time none of the host, daemon or extension existed. Everything below is still open, and three of
the open questions are security decisions rather than engineering taste.

It helps to see the integration as four layers that fail in unrelated ways.

**Transport is the easy layer.** A stdio binary, a manifest under
`~/.mozilla/native-messaging-hosts/` and `~/.config/google-chrome/NativeMessagingHosts/`,
`allowed_extensions` / `allowed_origins` bounding who may launch it. The
message-size ceiling (about 1 MB toward the browser) settles one design question
by itself: attachments do not travel this way.

**Peer trust is not.** The host is not a privileged intermediary; it is an
ordinary client of a socket under `~/.zann`, and *any process running as the user
can open that socket*. Filesystem permissions separate users, not processes.
Without an explicit answer here, a shell script in the user's session asks the
daemon for passwords and gets them. The daemon is also the wrong place to be
casual about this, because ADR 0006 puts passkey assertions on the same channel.

**Matching is where a naive implementation is a vulnerability, not a bug.**
At proposal time a `login` carried a single `url` — `schemas/security_profiles.yaml` lists
it under `exposable_public_attrs` — and there is no notion of a matching rule.
The only URL handling in the shared code is
`zann_ui_core::server_url::normalize_server_url`
(`crates/zann-ui-core/src/server_url.rs:5`), which prefixes `https://` onto what
the user typed into the connect field. That is the right function for its job and
useless for this one. Comparing hostnames without a public-suffix list collapses
`foo.co.uk` and `bar.co.uk`; comparing them too loosely offers the
`admin.example.com` credential on `blog.example.com`; comparing them too strictly
breaks every site whose login lives on a different subdomain than its content.
`zann-ui-core` deliberately carries five small dependencies
(`crates/zann-ui-core/Cargo.toml`) and is the wrong home for a vendored list of
every public suffix on the internet.

**Autofill is where the page is the adversary.** Field detection has to survive
shadow DOM and SPA re-renders; an in-page picker rendered into a hostile document
is clickjackable; filling on page load hands credentials to anything that
navigated the user there.

Two facts constrain all of it. `zann_ui_core::totp::generate_totp`
(`crates/zann-ui-core/src/totp.rs:55`) is already shared, so TOTP is nearly free
once the channel exists. And a new crate is not free: `config/architecture-boundaries.json`
enumerates `internal_packages`, `allowed_internal_dependencies` and
`forbidden_direct_dependencies`, and CI enforces all three.

## Decision

**1. The extension is a view. Nothing security-relevant lives in JavaScript.**
No matching, no policy, no origin derivation or vault crypto. The platform
identity/Noise adapter may execute the canonical Rust crypto owner or standard
platform signing primitives; it does not implement a second protocol or cipher. The JS does DOM work —
find fields, insert values, render the browser-provided surface — and shuttles
messages. Everything else is Rust, behind tests. Two reasons: the reviewed
artifact in the store stays small enough to audit, and the rules that decide
whether a secret is released are exercisable in `cargo test` without a browser.

**2. The host is a shim; the daemon holds everything.** The native-messaging
binary does no crypto, keeps no state and makes no decisions: it frames stdio
messages onto the daemon socket. It is a thin client on the facade exactly as
ADR 0002, Decision §5 anticipated. It transiently forwards released secret values
as transport, but must not persist them or gain independent authority to request
them. Authorization and secret lifetime remain owned by the daemon.

**3. Peer trust is explicit: `SO_PEERCRED` plus pairing.** The socket checks peer
credentials, and beyond that every client pairs. On first connection the
extension generates a key pair; the user issues a short-lived code in native UI
and enters it in the extension. Channel-bound PAKE establishes persistent trust;
subsequent requests are signed.
Unpaired clients get no data — not even item metadata. Pairings are listed and
revocable next to devices in settings. Peer credentials alone are explicitly
insufficient: they distinguish users, and the threat is a second process of the
same user.

**4. The browser never receives the master key and never decrypts.** Queries
return metadata — which items match this origin, their names and usernames. A
secret value crosses the channel only on an explicit user gesture, one value per
gesture, and the extension does not cache it. This extends ADR 0002's rejection
of a server-talking extension to its logical end: the browser is the most
attacked process on the machine and is treated as such.

**5. Matching moves into a new headless `zann-autofill` crate, and it owns
origins for the whole workspace.** It holds the public-suffix logic,
registrable-domain derivation, per-item match rules, the equivalent-domain list
and the fill policy. `zann-passkey` (ADR 0006 §5) depends on it for `rp_id`
derivation rather than deriving its own: two implementations of "what is a
registrable domain" is precisely the drift class
[ADR 0001](0001-shared-client-core.md) guards against,
and here the two copies would disagree about a phishing boundary. The crate is
registered in `config/architecture-boundaries.json` with `zann-core` as its only
internal dependency.

**6. The public-suffix list is vendored and digest-pinned.** Fetching it at
runtime is a supply-chain hole; letting it rot is a correctness bug. It is
updated by an ordinary PR, the same idiom `docs/Architecture.md` already uses for
digest-pinned sources.

**7. `login` gains explicit match rules.** A `match_rules` field with modes
`registrable-domain` (default), `host`, `exact`, `regex` and `never`, plus an
equivalent-domain list shipped as data. `never` matters as much as the rest: it
is how a user says "this credential is not for autofill".

**8. Fill policy, stated as rules the crate enforces.** No filling on page load —
a user gesture is required. The toolbar is available with `activeTab`; an
extension-origin field chooser may also run on an individually granted HTTPS
host, under the inline contract below. This replaces the initial toolbar-only
decision; page clickjacking remains an accepted UX tradeoff. Iframes are matched on the frame's
own origin, and cross-origin frames are refused by default. The picker never
shows an item the origin did not match, so an incorrect match cannot be repaired
by the user clicking through.

**9. Chromium and Firefox first; Safari is a macOS app target, not a build
flag.** Safari integration is a separate Apple target after the shared channel
and policy are proven. The existing macOS app does not itself provide a browser
extension.

**10. Minimal permissions, no remote code, reproducible builds.** The extension
is the only artifact users obtain through a distribution channel we do not
control, so its build must be reproducible from the tag and its permission list
must be defensible line by line.

## Consequences

**Good.** The security-critical surface ends up in two testable Rust crates
rather than in content scripts, and `zann-autofill` serves the extension,
passkeys and any future client at once. TOTP arrives almost free. The pairing
model gives the daemon a general answer for every local client, not an
extension-specific patch.

**Bad.** The daemon becomes a hard dependency of the browsing experience: not
running means the extension is dead, and "the daemon isn't running" is the new
failure mode ADR 0002 already warned about, now on the user's critical path. The
inline chooser requires a persistent site grant and accepts page-controlled
positioning/clickjacking risk. Vendored
public-suffix and equivalent-domain lists are maintenance we have to actually
perform. And pairing adds an onboarding step at the exact moment a user is least
patient.

**Unresolved.** The MV3 service-worker lifetime against a long-lived port: an
active port extends the worker's life, but relying on it is fragile, so the
extension needs state that survives a restart and a reconnect path — the details
belong in the phase that builds it. Whether a pairing survives extension updates
and cleared extension storage, or whether users re-pair. What the daemon does
when the vault is locked and a fill is requested: prompt, or fail quietly. And
the equivalent-domain list has no obvious owner yet.

## Plan

| | Phase | Risk |
|---|---|---|
| 0 | `zann-autofill`: origins, public-suffix list, match rules, fill policy — pure functions, adversarial tests, no client | low |
| 1 | `match_rules` on the `login` payload, security profile and UI in COSMIC; migration defaults to `registrable-domain` | low |
| 2 | Daemon: socket, `SO_PEERCRED`, pairing, revocation UI, session ownership | **high** |
| 3 | Native-messaging host: stdio framing, manifests for both browsers, nothing else | low |
| 4 | Extension: password and TOTP autofill, save prompt, generator | **high** |
| 5 | ADR 0006 phases 3–4 ride the same channel | **high** |
| 6 | Reproducible build and store publication | medium |

Phase 2 is the one to be careful with: it is where a mistake is a local privilege
boundary, and it is a prerequisite for both this ADR and ADR 0006.

## Alternatives considered

**Matching in JavaScript, in the extension.** Every shipping manager does it, it
is where the DOM already is, and it avoids a crate. Rejected: the phishing
boundary would then live in the least testable, most exposed, store-distributed
part of the system, and `zann-passkey` could not reuse it.

**A localhost WebSocket or TCP port instead of native messaging.** Simpler to
develop against and browser-agnostic. Rejected: a web page can attempt a
WebSocket connection to localhost, so the port needs its own origin
authentication, and we would have built a second, weaker copy of the pairing
problem while also being reachable from the network stack. A unix socket plus a
browser-launched host is strictly narrower.

**Naive hostname comparison now, public-suffix list later.** Ships phase 0 in a
day. Rejected: the failure mode is offering the right credential on the wrong
site, which is the one outcome a password manager exists to prevent.

**The master key in the browser, decrypting locally, daemon optional.** Removes
the daemon from the critical path and makes the extension usable standalone.
Rejected on the same grounds as ADR 0002's rejection of a server-talking
extension, only more so: extension storage is readable by anything that achieves
code execution in the browser profile.

**An in-page autofill overlay.** Initially rejected because a page can clickjack
an embedded one-click picker. Revisited after testing the toolbar flow: the
explicitly requested per-site chooser below accepts that residual risk without
moving matching/secret custody into page JavaScript or enabling ambient hosts.

**One matcher shared with global autotype.** Tempting symmetry. Rejected: the
inputs are not the same kind of thing. An origin is supplied by the browser and
is trustworthy; a window title is supplied by the application and is not. Sharing
the code would invite sharing the trust assumption.


## Implementation contract — #198 and #199 (2026-11-14)

Measured in the tree: `zann-autofill` owns matching; `zann-daemon::engine`
owns the local IPC capability; `zann-client::app::local` exposes bounded browser
reads/delivery over the one native vault. `zann-native-host` is a separate
DB/crypto-free framing binary. The complete wire, custody and deployment
contract is [Local browser session and native messaging](../browser-ipc.md).
This section accepts that implementation slice, not the future extension UI,
passkey ceremonies or store admission described elsewhere in the proposal.

### Composition and authorization

A daemon service accepts an existing `Arc<dyn LocalVaultService>`. COSMIC hosts
it in `Session`; the macOS production composition explicitly starts it on the
same FFI `CoreFacade`. `create_core` remains a storage factory; explicit
`start_browser_service` is an idempotent native lifecycle operation. The native
Settings view gets an in-process, non-serializable `DaemonControl`. Code issuance,
revocation, unlock and selection are not socket commands. The standalone binary
composes the same service and port with a terminal UI. Exactly one host binds a
root, with no fallback to another process, session or directory.

Kernel peer credentials are necessary but insufficient. The client proves an
Ed25519 key before enrollment; a native-issued one-time code authenticates
that exact key and the daemon identity through channel-bound PAKE. Every later request binds the server key,
fresh connection nonce, direction, sequence and exact body bytes. Metadata
requires pairing too. Revocation is serialized with delivery and durable before
success. Identity/pairing snapshots are strict and owner-only; malformed or
future snapshots fail closed. A failed revoke closes live authority.

Signatures alone do not hide released values from a transparent relay. A
standard `Noise_NK_25519_ChaChaPoly_BLAKE2s` handshake therefore precedes every
application request. The signed server hello binds its Noise key; the exact
hello is the Noise prologue. Application signatures then travel inside Noise.
The host has neither endpoint keys nor independent authority. Crypto remains
in `zann-crypto`, including the optional pure Rust Noise feature. This adds one
local handshake round trip, not a custom KDF/cipher or another vault envelope.

The native browser adapter holds its context lease through a bounded response
callback. Lock/selection cannot complete before an earlier secret delivery
finishes or fails. SQLite examines an indexed page of at most 32 login candidates
with one vault-key unwrap, not an item lookup per result. Random, expiring,
single-use continuation tokens bind origin context, native selection and client
connection; unmatched item IDs never become wire cursors. Only the matching
password and optional TOTP code are released, never a seed or arbitrary payload.

### Per-lever values interrogation

The repository has no separate values manifest. These tests use the explicit
invariants in `AGENTS.md` and the capability map; each mechanism is evaluated
separately rather than assigning a net security score.

| Mechanism | Trust separation and custody | Single owner | Crash/idempotency | Bounds and operability |
|---|---|---|---|---|
| Existing-vault service plus explicit native activation | Browser never obtains a master key or unlock route; native storage can open independently of IPC | Reuses `LocalVaultService` and resolved `ClientPaths`, without a second vault/session | Start is idempotent; another root owner is refused | Explicit `NotRunning`/`PathTooLong`; Unix address limits do not create a second storage root |
| Kernel peer check plus code pairing and native control handle | UID alone grants nothing; only native UI issues codes | Pairing/authorization in one engine; native UI projects its handle | Atomic private snapshot; repeated enrollment/revoke converge; failed revoke closes live authority | 16 connections, one two-minute/five-attempt window, 64 approvals |
| Noise plus signed exact request transcripts | Relay without endpoint keys sees no secrets; nonce/direction/sequence prevent replay/reflection | Canonical crypto owner and `snow`; no bridge crypto | Fresh handshake on reconnect; an ambiguous fill is not automatically replayed | One local handshake round trip; bounded whole frames and authenticated chunk lengths |
| Indexed browser page and opaque scoped cursors | Only origin-matched metadata; continuation hides unmatched IDs and never releases a field | SQLite owns persistence, `zann-autofill` owns matching | Stale native selection or a consumed/expired cursor is refused | 32 candidates, byte bounds, no per-item DB round trips; 128 cursors total/four per connection |
| Delivery lease, explicit gesture and shared TOTP generator | One signed action releases password plus optional code; no TOTP seed | Reuses native context gate and `zann-ui-core`; no shell TOTP implementation | Lock/revoke linearize with complete response delivery | Two-second DB-await deadlines and five-second whole-frame deadlines; locking can wait for a bounded preceding write |
| Strict framing and explicit manifest installer | Stateless host forwards only encrypted application packets; allowlist names one extension | One framing feature shared by host and daemon | Atomic files; repeat exact installation succeeds, differing operator files remain intact | 1 MiB before allocation; no implicit HOME discovery or wildcard IDs |

Costs/debt are explicit. A native lock may wait for its preceding bounded write;
the values-true alternative would cancel a cancellable transport with a typed
release outcome, not publish a locked UI while still releasing a secret. The
current synchronous port deliberately favors its proven lease ordering. Root
path length is a platform constraint, surfaced by one shared validator; an
out-of-process GUI client remains future work, not an automatic fallback.
Same-UID filesystem/endpoint-key compromise remains outside pairing's caller
boundary and is documented in the IPC threat contract. No new `MIG-*` exception
or vault-format compatibility path is introduced by this slice.

### System alignment and proportionality

- `LocalVaultService`, Config v2 roots and native selection: **reuse/aligned**;
  the service borrows the existing instance, never reconstructs KDF or target
  selection in a shell. Standalone and embedded are explicit compositions.
- `zann-autofill`, TOTP and crypto: **reuse/aligned**; the new transport is a
  justified divergence from vault envelopes (ephemeral IPC confidentiality,
  different authority and lifetime). Vault v1 golden fixtures remain unchanged.
- `item_read`: **justified divergence** for browser delivery. A normal detail
  read returns local presentation data; browser release needs a context lease
  covering the final bounded write, plus a page that does not query per item.
- Native Settings and FFI: **realign now** to project the one management handle;
  mobile exports explicitly report unsupported hosting and do not link the
  desktop daemon. No duplicate pairing database or Swift policy is introduced.
- Native host registration: **new narrow adapter**, not an HTTP/WebSocket
  service. Browser directory and extension ID are explicit installation inputs.

The Pre-GA implementation cuts over directly: no dual writer, handshake
negotiation fallback, permissive manifest, second crypto envelope version or
manual recovery command. Each immutable frame is authenticated once by the
Noise owner; request signatures separately establish client authority. Durable
pairing publication has one private snapshot and directory fsync, not an OS
credential/SQLite dual-write transaction. Concurrent tests use isolated client
roots; one root's listener lock does not serialize unrelated roots. Existing
Cargo/architecture/security registries are updated once for the new capability;
adding a paired client is data and requires no source registry change.

Verification is attached to the owner tests (`zann-daemon/tests`, crypto IPC and
v1 compatibility tests, native framing/installer tests, FFI hosting tests),
architecture/dependency guards, and native binding/app build checks. These are
regression evidence, not a declaration that this release has been audited.

## Implementation contract — Chromium #25 (2026-11-14)

Phase 4 is implemented by `apps/extension` (MV3 toolbar and opt-in field chooser) and `zann-browser`
(the WASM projection). Store publication, Firefox packaging and passkey ceremonies
remain outside this accepted slice. [The deployment/threat contract](../chromium-extension.md)
records the permission rationale and test limits.

The protocol DTOs, transcripts and single-flight client moved directly from the
daemon to `zann-client::browser_ipc`; the old daemon protocol module is deleted.
That opt-in feature has no remote/config/Tokio/SQLite/keystore closure. WASM uses
the same `zann-crypto` Ed25519/Noise and OS/browser entropy, not JS protocol or
cipher implementations. A connection with an invalid transition or authentication
failure is poisoned. A fresh explicit action may reconnect before dispatch;
ambiguous dispatched operations are never replayed.

Native Settings issues a one-time code. The dedicated bootstrap client
authenticates both endpoint identities and the final Noise transcript using
SPAKE2 and mutual confirmation, then publishes a pin after native enrollment.
The versioned client signing seed and server pin persist in trusted-context-only
local extension storage; the later MRU contract adds bounded opaque usage IDs.
The identity fields are endpoint custody, not password/master-key custody; browser profile compromise
requires native revocation. No storage.sync, window-message bridge, external
runtime entry point or default host grant is installed. The site-grant and
inline lifecycle is specified by the later contract below.

Save is a typed, explicit create operation, not arbitrary item mutation. The
native selection generation from the query must still match under the context
lease. Only the canonical HTTPS origin is saved; URL query/path/fragment are
removed. `LocalServices::put_item_with_metadata` owns one atomic item/history/pending-change
transaction for browser and native creation; this replaces the old multi-commit
create path, rather than creating a second browser writer. Duplicate paths fail.
The generator projects the shared native CSPRNG owner, `zann-ui-core::generator`, and
never writes a vault entry without a separate review confirmation.

### Per-lever values and alignment

The normative invariants remain those in `AGENTS.md` and the capability map.
Each added mechanism is evaluated separately:

| Lever | Custody / trust separation | Single owner / subtraction | Crash safety / bounds |
| --- | --- | --- | --- |
| Shared Rust protocol + thin WASM projection | Browser has an IPC identity, no vault/master key or remote credentials | Deletes daemon DTO/transcript copy; reuses crypto and canonical origin admission | Single flight; poisoned failures; no ambiguous replay; existing frame/body limits |
| Native-issued code and authenticated pin | No automatic server replacement; browser cannot issue a code | Native control handle plus canonical PAKE owner; manual key approval removed | Web Locks serialize identity publication; stale snapshots refuse; atomic Forget; seed/pin survive updates |
| Toolbar-only `activeTab` surface | No page-origin/user-gesture claims or page message handler; browser APIs supply URLs | JS owns browser/DOM capability adapters only; Rust owns matching and secure-context policy | Exact document ID + URL continuity; bounded open-shadow traversal; disconnected/ambiguous fields require refresh |
| Typed review/save plus selected-generation lease | No background capture or arbitrary fields; wrong/stale native target refuses | Native port and canonical create service; old three-commit creation removed | Item/history/pending are one transaction; duplicate path refuses; no save replay after uncertain dispatch |
| Shared generator | No remote generator, clipboard or automatic release | One `zann-ui-core` implementation, exported by WASM | 16–128 characters; transient masked value; separate click to insert/save |
| Packaged-only CSP and locked build | No network scripts, site favicon fetch or cloud session | One source package plus generated local glue; test hooks never ship | Locked Rust/JS/tool versions; Chromium test profile is disposable; CI emits reviewable artifact |

Costs are explicit. Manual capture and a browser popup cost convenience; unsupported
or ambiguous forms fail rather than adding permissive fallbacks. Full-page browser
tests substitute the native launcher and active-tab invocation, so real OS
registration and toolbar permission grants remain manual installation checks;
wire crypto, real host/socket/daemon and Chrome document injection are exercised.
JS/browser copies cannot guarantee forensic memory erasure. Firefox and store
publication are distribution work, not a hidden compatibility path. No new MIG
exception, vault v1 envelope or KDF/AAD change is introduced.

## Implementation contract — per-site field chooser (2026-11-14)

Measured before this change: the toolbar required a separate form selection,
`activeTab` supplied temporary access, `BrowserPage` supplied document identity,
`pageFields` supplied bounded DOM operations and Rust `LoginSearch` aggregated
all matches. The user requested focus-triggered suggestions after manually
checking fill/save/generation/TOTP. This extends this ADR, not another matcher,
vault session, wire version or credential writer.

### Decision and lifecycle

- Chrome optional permissions are the only persistent site-grant authority.
  The popup requests one exact HTTPS hostname, without subdomain wildcards;
  Chrome patterns cover all ports on that host. Declaring `https://*/*` as
  optional capability grants no access. One dynamic registration reconciles
  from Chrome grants; no copied allowlist or credentials enter storage.
  Grant/revoke handling lives in the worker so Chrome consent may close the
  toolbar safely; activation installs in already-open granted documents.
- Only granted top documents install the packaged isolated adapter. Focus or
  its key button opens an extension-origin iframe anchored above/below the
  field. The page cannot read chooser contents; closed shadow encapsulates
  layout only. No window `message` listener or external runtime handler exists.
- The worker admits internal ports using Chrome sender identity, tab/top
  document URL and ID, exact host permission, then a random chooser capability
  plus runtime iframe document identity and browser-read-only ancestor origins.
  Chrome does not expose extension subframes through `webNavigation`. It rechecks the
  current active document and grant around search and before injection.
  Capabilities expire with the chooser (60 seconds maximum); they are transient
  document associations, not durable operation permits or recovery records.
- Native matching/search/crypto and the bounded DOM adapter are reused. Each
  surface keeps independent field references so an inline focus cannot replace
  toolbar capture's selection. Results are metadata only. Trusted clicks or
  keyboard events in the packaged UI trigger fill; no page-load fill or submit.
  Password/TOTP go from the worker directly to the checked isolated injection,
  not to the chooser iframe. Generated passwords are transient worker values,
  with a separate use click; save remains toolbar review.
- Close, field replacement, URL/navigation, hidden tab, revoked grant and
  identity change invalidate authority and clear metadata/generated values.
  Successful fill closes the chooser; an admitted chooser retains retry on
  native/locked-vault errors. Native failure is not an iframe admission failure.
  Errors never replay a dispatched operation. A fresh explicit action can
  establish another Noise channel. Worker restart loses ephemeral state and
  a new focus opens a new chooser; there is no persistent secret cache.

### Per-lever values interrogation

There is no separate values manifest; the tests are the repository invariants
in `AGENTS.md` and the canonical capability map.

| Lever | Trust/custody | Canonical owner and subtraction | Crash safety, bounds and operability |
| --- | --- | --- | --- |
| One optional HTTPS host grant | Mixed: persistent access is broader than `activeTab`, but opt-in, exact host and revocable | Chrome permission/registration state is SSoT; no local allowlist schema | Registration converges under one short Web Lock; one enable click per host, no native re-pairing |
| Embedded extension iframe | Mixed: page cannot inspect usernames or invoke extension JS, but can overlay, move or impersonate UI | Thin shell; no Rust policy duplicated; toolbar remains explicit management/save surface | Bounded viewport/list; keyboard and close actions; no remote code or favicon requests |
| Worker-bound runtime ports | Page-supplied URL/gesture claims grant no authority; iframe sender/parent and current granted document must agree | Reuses `BrowserPage`, shared scanner, existing Rust Noise/client and complete search; paired connection setup unified | At most 16 document controllers, one chooser per controller, 60-second chooser lifetime; search/native limits unchanged |
| Direct checked injection and invalidation | Secrets never visit chooser or storage; stale nodes/documents/grants refuse | One DOM adapter, two private reference namespaces; same native release and generator owners | Epoch/cancel guard rejects late results; no replay, automatic submit, capture or overwrite |

Debt is not hidden by the UX gain. Persistent host access weakens least privilege
relative to toolbar-only access; the narrower alternative is `activeTab`, which
remains available until a user enables this feature. Embedding weakens protection
against clickjacking: a browser-owned credential chooser or toolbar/side-panel
selection would keep that interaction outside page control. Chrome's public
extension surface does not offer an arbitrary browser-owned autofill picker;
this slice explicitly accepts the embedded risk, without claiming that iframe,
closed shadow, `isTrusted` or origin matching eliminates it. These are recorded
scope limitations, not untracked migration shims.

### Alignment, proportionality and verification

- Matching, native session, Noise, `LoginSearch`, TOTP and generator:
  **reuse/aligned as-is**. No daemon, core, crypto or envelope format changes.
- Toolbar DOM integration: **realign now** to share detection and injection while
  separating private selections; pairing reconnect setup has one helper.
- Chrome site grants: **justified divergence** from pairing storage: access to
  sites is Chrome-owned capability data, not shared vault configuration.
- Runtime messaging: **justified divergence** from toolbar-only lifetime; exact
  browser sender/document associations replace a page `postMessage` bridge.
- Safari/passkeys and native shells: **aligned as-is**, no new obligations or
  duplicated presentation/auth logic. No new `MIG-*` exception is needed.

The user performs one enable click and Chrome consent per host, then chooses an
account at the field. There is no per-login native approval or second vault.
Search uses its existing bounded native pages; fill establishes one fresh local
Noise connection before dispatch. Registrations reconcile idempotently without
recovery commands, central host source lists or a global development resource.
Disposable fixtures use independent roots/profiles; real Chrome site consent is
a manual test. Regression evidence covers original toolbar fill/save/generation,
full inline search, trusted click/keyboard fill/TOTP, synthetic gesture refusal,
node/URL invalidation, generator use and storage contents. Host grant/revocation
and exact-host registration also have fast unit tests.


## Implementation contract — one-time-code pairing (2026-11-14)

### Context and decision

Measured: the daemon already owns a private atomic identity/pairing snapshot,
signed requests, a Noise NK channel and delivery-linearized revocation. The
browser persists one signing seed/server pin under a Web Lock. Native Settings
previously required copying one full key and comparing another. This slice
replaces that onboarding contract directly, retaining those custody/persistence
owners and already enrolled public keys. It adds no second authorization mode,
protocol-version negotiation or vault-format change.

Native **Connect browser** issues six uniform decimal digits for 120 monotonic
seconds, with five starts total across all connections. Replacement invalidates
in-flight exchanges. `pair_start`/`pair_finish` use RustCrypto SPAKE2 0.4
(Ed25519 group) and directional BLAKE3 key confirmation. The canonical binding
contains both signing keys, name, nonce and final Noise handshake hash. The
browser's provisional self-verified hello cannot authorize application calls:
a dedicated bootstrap state machine publishes a pin only after mutual PAKE
confirmation and durable native enrollment. Codes never cross IPC or enter
persistent files. `pair_status` checks saved trust on strictly pinned reconnects.

A successful confirmation consumes the native window before persistence; no
other pending connection can reuse it. Missing final acknowledgement has an
ambiguous outcome and is never automatically replayed. A new native code can
repeat enrollment of the same retained browser key without duplicate records,
special recovery commands or a config/journal dual writer. Native revocation
continues to invalidate live and subsequent requests and cancels any active
code window, so an in-flight proof cannot undo revocation. It is durable before
success; a failed revoke closes live authority.

### Per-lever values interrogation

The source values are the strict invariants and Pre-GA proportionality in
`AGENTS.md`, plus the canonical capability owners. No separate values manifest
exists. Each mechanism is evaluated individually:

| Lever | Trust separation / custody | Single owner / subtraction | Crash safety / bounds |
| --- | --- | --- | --- |
| Native-issued short code | Mixed: removes manual full-key verification but introduces a bounded guessing probability, at most 5/1,000,000 per issued code; trusted native display/browser remain required | `DaemonControl` owns issuance; removes pending-key lists and manual approval API/UI | One volatile window, 120 seconds, five starts including malformed starts; restart invalidates it |
| SPAKE2 plus directional confirmation | Authenticates provisional signing keys without sending the code or permitting offline guesses from captured wire messages; Noise transcript prevents channel splicing | Optional `zann-crypto::ipc_pairing`; no JS/Swift crypto, copied matcher or vault crypto changes | One exchange per bounded connection; proofs consumed before checking; expiry/generation checked at commit |
| Pin publication after durable enrollment | No query/fill/save or provisional pin export from bootstrap; existing pins cannot be silently replaced | Shared `zann-client::browser_ipc::BrowserPairingClient`; thin WASM adapter | Native fsync/rename precedes acknowledgement; browser Web Lock performs one identity write; new-code retry converges after acknowledgement loss |
| Existing pairing snapshot/revocation | Personal keys remain local, browser receives only existing origin-scoped operations | Reuses daemon identity file and delivery lease; no extra DB/keychain writer | Restart retains approved keys; revocation rejects live requests and survives restart; no automatic operation replay |

The short-code probability is an explicit cost, mitigated by native-only
issuance, short lifetime, one-use success and the global attempt bound. Short
codes do not protect a compromised native UI or browser profile. The upstream
`spake2` crate states it has no independent security audit; the implementation
must not be described as audited. Rust-owned code/confirmation buffers are
zeroized; upstream SPAKE2 internals and shell copies have no forensic-erasure
promise. These limits are recorded in the IPC threat contract.

### Alignment, alternatives and proportionality

- **Reuse:** existing Noise transport, Ed25519 identity, atomic native snapshot,
  root ownership, browser identity Web Lock and native revoke/delivery ordering.
- **Realign now:** replace manual-key pending/approve paths in native controls,
  FFI, Chromium onboarding, fixtures and docs. Rust owns the whole protocol;
  Swift/JS only display the code or execute browser/OS operations.
- **Justified divergence:** SPAKE2 is a narrowly scoped optional crypto dependency
  because a short secret cannot safely authenticate an unpinned channel merely
  by being sent through it. Default crypto excludes it; WASM uses pure Rust.
- **Rejected:** sending plaintext codes over provisionally authenticated Noise
  (fake endpoint could collect the code), deriving a Noise PSK directly from six
  digits (offline guessing), truncating key fingerprints (different interaction
  and collision properties), keeping manual approval as a parallel mode
  (unnecessary Pre-GA compatibility and duplicate lifecycle).
- **Operational cost:** native click plus browser code entry replaces copying,
  comparison, approval and manual reconnect. Pairing adds two local application
  round trips once; reconnect still uses the existing Noise handshake/status.
  Only small identity snapshots are written. No central per-browser registry,
  global build lock, migration shim, `MIG-*` expansion or new recovery command.

Verification covers real socket/WASM/Chromium onboarding and ordinary fill/save,
wrong codes, cross-connection attempt budgets and proof swaps, one-use success,
malformed confirmations, monotonic expiry at start and commit, code replacement,
restart/revocation, pin poisoning, and vault-v1 golden compatibility. The crypto
and protocol clients build for WASM; native bindings/apps and architecture /
dependency guards are checked independently.


Verification commands for this slice:

```sh
cargo fmt --all --check
cargo clippy -p zann-daemon -p zann-browser -p zann-crypto -p zann-client -p zann-ffi --all-targets --all-features --offline -- -D warnings
cargo test -p zann-daemon -p zann-browser -p zann-crypto --all-features --offline
cargo test -p zann-client -p zann-ffi --all-features --offline
node --test apps/extension/tests/*.test.mjs
node apps/extension/build.mjs
node --test apps/extension/tests/browser/*.test.mjs
./scripts/check-client-architecture.sh
./scripts/check-audit-surface-deps.sh
apps/apple/ZannCoreKit/build-xcframework.sh debug
swift test --package-path apps/apple/ZannCoreKit
(cd apps/apple && xcodegen --spec project.yml && xcodebuild test -project Zann.xcodeproj -scheme Zann -destination 'platform=macOS,arch=arm64' -derivedDataPath /private/tmp/zann-code-pairing-build)
```

These passed (macOS app: 55 tests, five skipped). COSMIC verification on this
macOS host remains limited: the repository-pinned Rust 1.92 is below libcosmic's
1.93 MSRV; Rust 1.99.1 reaches the existing platform-gated `cosmic::dialog` import.
Enabling the existing `libcosmic/rfd` backend for validation instead reaches the
preexisting Apple-import `FileFilter::glob` API mismatch in `settings.rs`.
No toolchain, dialog backend or unrelated import behavior is changed here.


## Implementation contract — local successful-fill MRU (2026-11-14)

Measured: both extension surfaces already use shared complete-search aggregation
and checked isolated-world insertion; browser profile storage has an identity
Web Lock and explicit Forget. Previously matches retained native UUID order.
This slice reuses those owners and adds no native usage writer or sync path.

`LoginMatcher` supplies admitted-match quality (exact URL, origin, domain,
configured equivalent domain, other admitted pattern) without changing admission.
The strict Pre-GA wire record gains this field directly. `zann-client::browser_ipc::usage`
owns local schema, retention and stable ordering: quality first, then MRU; unseen
ties preserve native order. Thin WASM projects this owner; one JS adapter serves
both popup and inline. No shell matcher or ranking copy is introduced.

Local history is an ordered list of opaque daemon/storage/vault/item IDs, capped
at 4096 entries. Ordering alone represents recency: no clock, timestamp or
frequency counter is necessary. The browser profile is the device-local storage
boundary. Native vault items, SQLite, pending changes and remote sync are not
written. Only a confirmed isolated-world insertion moves an entry to the front;
queries, native release, save/generation and failed/ambiguous injection do not.
Successful OTP insertion counts as use of that login too.

| Lever | Trust/custody | SSoT / subtraction | Crash safety / bounds |
| --- | --- | --- | --- |
| Native quality plus Rust MRU rank | Ranking never admits a new item or grants release | Extends the existing matcher/search owners; replaces undifferentiated native-order display in both surfaces | Complete search only; stable ties; existing page/aggregate limits retained |
| Opaque profile-local MRU | Mixed: adds persistent activity metadata, but retains no sites, names, secrets or timestamps | One Rust schema/rank owner and one Chrome adapter; no SQL/sync writer | Strict version/shape/duplicate/byte validation; 4096-entry least-recent eviction |
| Success-only recording | Checked DOM acknowledgement precedes metadata; values cleared before storage I/O | Shared `fillAndRemember`, no copy of credential or masking policy | Failed/ambiguous fills never count; metadata failure accurately reports completed fill, never replay |
| Identity-serialized reset and updates | A late old-identity write cannot recreate activity after Forget | Reuses the existing identity lock/reset; no new recovery command or dual writer | One metadata snapshot per update; clear-before-identity-replacement reset; crash may lose history, never credentials |

The metadata tradeoff is explicit: even opaque IDs reveal relative activity to
code that compromises the browser profile. That is within the existing trusted
profile/approved-key boundary; no stronger anonymity claim is made. Local write
failure after successful fill is visible and has a different outcome from failed
insertion. Corrupt/future history requires the existing explicit Forget action;
there is no silent repair/fallback. Missing metadata after a browser crash is
acceptable preference loss; it cannot authorize a fill or modify vault records.

Alignment: reuse native matching, complete `LoginSearch`, isolated DOM insertion,
identity Web Lock and Chrome trusted-context storage. The justified new local
snapshot is ancillary browser preference metadata, not a second vault/config
owner. Direct wire cutover requires native rebuild plus extension reload, without
version negotiation/default quality. No MIG exception, package dependency,
crypto-envelope change or central per-account registry is introduced. One local
snapshot read per search and a bounded read/write after successful fill add no
native/server round trip; unrelated profiles remain independent. Verification
covers core rank/scope/schema/retention, real popup↔inline recency, reopen,
synthetic/failed insertion, generation/save non-use and explicit reset.


Verification for local MRU:

```sh
cargo test -p zann-autofill -p zann-client --no-default-features --features zann-client/browser-ipc --offline
cargo test -p zann-client -p zann-client-sqlite -p zann-daemon -p zann-browser --all-features --offline
cargo clippy -p zann-autofill -p zann-client -p zann-client-sqlite -p zann-browser -p zann-daemon --all-targets --all-features --offline -- -D warnings
node --test apps/extension/tests/*.test.mjs
node apps/extension/build.mjs
node --test apps/extension/tests/browser/*.test.mjs
cargo fmt --all --check
./scripts/check-client-architecture.sh
./scripts/check-audit-surface-deps.sh
apps/apple/ZannCoreKit/build-xcframework.sh debug
(cd apps/apple && xcodebuild build -quiet -project Zann.xcodeproj -scheme Zann -destination 'platform=macOS,arch=arm64' -derivedDataPath /private/tmp/zann-code-pairing-build)
```


## Implementation contract — filtered virtual login lists (2026-11-14)

Measured: complete search already has an 8192-match bound and native pagination;
both surfaces rank metadata before display, but previously mounted every result.
The shared presentation crate already owns case-insensitive public-field search.
This slice factors a prepared `TextQuery` from that implementation and reuses it
in a toolkit-neutral `LoginList` rather than implementing filtering in JavaScript.
The WASM edge maps admitted `BrowserMatch` labels onto that presentation port.
It gains one explicit `zann-ui-core` dependency, with no new third-party package,
feature fallback, DB/network/keystore dependency or native protocol change.

One shared DOM/keyboard adapter replaces both full-list renderers and the inline
index-selection loop. It mounts only visible rows plus two overscan rows on
either side; row height is bound from one component constant into CSS. Native
complete-search/ranking/usage owners remain unchanged. Search is transient,
public-title/username-only, stable and local; no native request or usage write
runs per keystroke. Item release retains the existing explicit gesture, document,
origin and native authorization checks, using the original selected item ID.

| Lever | Trust/custody | SSoT / subtraction | Bounds and operability |
| --- | --- | --- | --- |
| Prepared shared query and filtered indices | Only already-admitted public labels; no passwords, TOTP values or new matching | `zann-ui-core` owns text policy; native `matches_query` and browser lists share one implementation | 256-character query limit; stable rank; invalid queries do not mutate the index view |
| Coarse WASM windows and shared DOM list | Query/result memory is cleared with the document/list; no storage or page bridge | One window projection and one renderer replace two full DOM loops and duplicate selection logic | At most 64 records per WASM window; actual DOM at most 9/8 rows, tested on 1024 real matches and 8192 core entries |
| Global filtered selection and guarded handlers | Empty/stale/synthetic/IME events cannot fill a different item; native release policy is unchanged | Shared keyboard/focus/accessibility behavior; indices map to original IDs in the presentation owner | Navigation spans virtual windows; result counts and empty states are explicit; no manual page controls |

Alignment: reuse native query bounds, matcher quality/MRU ranking, prepared text
filter, worker admission and checked DOM insertion. The justified presentation
edge dependency keeps native domain code free of UI logic; no MIG exception is
expanded. Costs are one WASM presentation model per active list and full bounded
metadata collection before search, not progressive native streaming. This leaves
initial query latency governed by the existing 30-second bound; virtualization
addresses DOM size and navigation. No recovery command, persisted filter,
cryptographic format change or cross-device metadata writer is added.

Verification for filtered virtual lists:

```sh
cargo test -p zann-ui-core -p zann-browser --offline
cargo test -p zann-client --no-default-features --features browser-ipc --offline
cargo clippy -p zann-ui-core -p zann-browser --all-targets --all-features --offline -- -D warnings
node --test apps/extension/tests/*.test.mjs
node apps/extension/build.mjs
node --test apps/extension/tests/browser/*.test.mjs
cargo fmt --all --check
./scripts/check-client-architecture.sh
./scripts/check-audit-surface-deps.sh
```


Integration with current main (2026-11-14): the browser uses the shared native
`zann-ui-core::generator` policy; no second generator is added to crypto. Save
reuses `LocalServices::put_item_with_metadata` and supplies canonical new-item
metadata. Its existing atomic item/history/pending transaction remains the only
creation owner; browser-specific transaction helpers are removed. The bounded
login projection includes metadata and the search index uses migration 0006,
after the existing item-metadata migration. Retired Tauri paths stay removed.
