---
title: Audit-surface status
description: Security-sensitive modules, ownership, and audit readiness.
---

The audit surface is the small set of security-sensitive modules that receive
security labeling, explicit ownership and stricter CI checks. The list is
source-based: moving policy behind a new adapter does not remove it from the
surface.

## Current status

No release is designated as fully audited or “blessed” yet. Until that changes,
the automated gates provide regression protection but are not a substitute for
a focused security review.

The current surface covers:

- Apple path/credential-port composition and blocking-FFI execution in `apps/apple/Zann/Composition/**`,
  desktop service activation in `apps/apple/Zann/Platform/macOS/MacComposition.swift`,
  and native secret adapters in `apps/apple/Zann/Keychain*.swift`;
- Apple auth/unlock invalidation in `apps/apple/Zann/{AppModel.swift,Connect/**}`,
  owned clipboard delivery in `apps/apple/Zann/Platform/Clipboard*.swift`,
  and mobile system web-session/privacy lifecycle in `apps/apple/Mobile/**`;
- native backup staging, picker ownership, cleanup and lifecycle maintenance in
  `apps/apple/Zann/Maintenance/**`, and signed local mobile artifact preparation
  in `apps/apple/release-mobile.sh`;
- Apple transient reveal state in `apps/apple/Zann/Platform/FieldRevealState.swift`,
  security preference controls in `apps/apple/Zann/DevicePreferenceViews.swift`,
  and masked field editing/copying in `apps/apple/Zann/Vault/{ItemDetailView,ItemEditorView,FieldEditorRow,ItemDetailFieldRow,CopyValueButton}.swift`;
- compile-time isolation and temporary-replica activation of Apple UI-test
  ports in `apps/apple/DebugSupport/**`;
- OIDC callback transport, redirect/state/PKCE admission and provider request
  cancellation in `crates/zann-client/src/oidc{.rs,/**}` and its opaque FFI
  projection in `crates/zann-ffi/src/session/oidc.rs`;
- mobile identity/signing configuration in `apps/apple/{project.yml,Mobile.xcconfig,Mobile/**}`
  and fixture/profile selection in `apps/apple/ZannCoreKit/{build-xcframework.sh,check-build-profile.sh}`;

- website origin parsing, PSL/equivalent-domain matching, login rules and fill
  admission in `crates/zann-autofill/**`, including the vendored data and pins;
- local IPC authorization, replay protection, Noise/signature binding,
  private identity/pairing persistence and lifecycle in `crates/zann-daemon/**`;
- the stateless framing/registration bridge in `crates/zann-native-host/**`
  and `crates/zann-client/src/native_messaging.rs`;
- the browser port and delivery lease under `zann-client/src/app/local`, its
  native adapter, and bounded login page reads in
  `crates/zann-db/src/{services/browser.rs,local/item_repo/browser.rs}`;
- the login page bound in `zann-core/src/constants.rs` and the supporting
  `crates/zann-db/migrations/0006_browser_login_index.sql` index;

- cryptographic primitives and their compatibility fixtures in `zann-crypto`;
- core and server authentication and access-control policy;
- OS secret storage in `zann-keystore`;
- Config v2, credential lifecycle and their crash/recovery tests in
  `zann-client`;
- signed server-identity verification and its opaque trust proof in
  `zann-client`;
- the sync owner, secret-bearing payload-key models and persistence ports under
  `crates/zann-client/src/sync/**`;
- the DB-free authenticated application facade and operation-scoped sync-store
  factory port in `crates/zann-client/src/app.rs`;
- the production bidirectional SQLite sync adapter in `zann-client-sqlite`,
  including its pinned existing-file opener, exact Config v2 generation lease,
  bounded projection readers, initial personal-key publication and atomic
  storage/catalog/item/checkpoint CAS seams in `zann-db`;
- local payload decryption in `crates/zann-db/src/services/{mod,items}.rs`,
  including the list page's subtitle decryption, and the rule in
  `crates/zann-core/src/item_subtitle.rs` that picks which non-secret
  payload field a list row shows;
- payload-version admission in `zann-crypto/src/secrets/codec.rs`, local
  exact-source edit/history/pending transactions in
  `zann-db/src/local/item_repo/edit.rs`, and shared-server payload admission
  in `zann-server/src/domains/items/payload_admission.rs` and its item,
  secret and sync mutation callers;
- server audit-log infrastructure;
- privileged shared plaintext backup admission/publication in
  `zann-server/src/domains/backup/**`, its `cli/{export,import}.rs` adapters,
  and transaction/paged source reads in `zann-db/src/repo/{backup,vaults,devices,items}.rs`;
- native secret generation in `crates/zann-ui-core/src/generator/**` and its
  one-to-one `crates/zann-ffi/src/generator.rs` projection: bounded explicit
  policy, unbiased draws from OS entropy, fail-closed errors, dictionary
  integrity and redacted/zeroized generated values.

`CODEOWNERS`, the `t: security` labeler and the `audit-surface` CI job must be
updated in the same change whenever this list grows or moves. Client ownership
and dependency direction are additionally enforced by
`scripts/check-client-architecture.sh`.

## Release record

There are currently no blessed releases. A future entry must name the exact Git
revision, reviewed paths, review date, known limitations and the checks that
were run; a version number alone is not sufficient.

Local vault port and maintenance ownership: `crates/zann-client/src/app/local/**`,
`crates/zann-client-sqlite/src/local_vault/**`, and SQLite maintenance/row decoding
under `crates/zann-db/src/{domain_row.rs,local/maintenance.rs,local/sync_repo/**}`
are included in the sensitive review surface.

The remote-only `zann-client::server` capability and the decomposed
`zann-client/src/config/v2/**` modules retain the same sensitive review gates.

Server-replica cutover: `crates/zann-db/migrations/0004_server_replicas.sql`
and `crates/zann-db/tests/server_replicas_migration.rs` preserve legacy data
on refusal and retain server ciphertext and pending changes during upgrade.


Server backup restoration additionally covers `zann-core/src/item_metadata.rs`,
`zann-db/src/services/create_item.rs` and migration `0005_item_metadata.sql`.
Item attributes participate in the same sync CAS proof as ciphertext; legacy
unknown attributes are refused rather than synthesized. The backup import
session, file preflight and transactional publication remain under the existing
application/sync/SQLite owners.

## Shared interactive Connect policy

`crates/zann-flows/src/connect.rs` and its submodules own native Connect stage,
registration, trust sequencing, operation admission and cancellation/result policy.
`crates/zann-ffi/src/connect_flow.rs` and submodules project this reducer without
transport or runtime policy. COSMIC consumes it directly; Apple executes the same
typed effects through existing `RemoteSession` calls. Executors must capture
opaque prepared/trust/browser capabilities before dispatch, register auth
cancellation before awaiting, and check instance/operation/phase before installing
results. Late successful, failed or browser-start results must have no UI or OS
effect after Back, Cancel, replacement or terminal success.

Compensating tests: `crates/zann-flows/src/connect/tests.rs`,
`crates/zann-ffi/tests/connect_flow.rs`, COSMIC Connect/executor tests and Apple's
`ConnectFlowAdapterTests` / `ConnectFlowBindingTests`. The architecture guard
forbids runtime/transport/platform dependencies in `zann-flows` and the retired
shell Connect reducer shapes. Native executors do not abort canonical crash-safe
credential commits or roll back a completed trust decision.
## Chromium extension (#25)

- `apps/extension/**`: packaged MV3 permissions/CSP, toolbar, per-host grants and
  registrations, isolated DOM adapter, worker port/document binding and
  extension-origin field chooser; identity storage and transient capture/fill lifecycle.
- `crates/zann-browser/**`: WASM projection, browser entropy feature selection.
- `crates/zann-client/src/browser_ipc{.rs,/**}`: canonical shared wire/signature and
  single-flight client; no daemon-local protocol copy remains.
- `crates/zann-client-sqlite/src/local_vault/browser_save.rs`: selection-bound
  typed login creation under the native lease.
- `crates/zann-db/src/services/create_item.rs`, `local/{item_repo,item_history_repo,pending_change_repo}.rs`:
  one item/history/pending transaction used by browser and native creation.
- `crates/zann-ui-core/src/generator/`: shared bounded OS-CSPRNG password generation.

Browser pages have no window-message or external-runtime entry point. Only the
packaged isolated adapter and extension iframe use internal runtime ports. The
worker verifies the granted host, top document, stable runtime document IDs,
read-only iframe ancestor origins and active tab before release. The paired extension is trusted to
observe browser document identity and require an actual chooser gesture. Passwords,
TOTP values, page URLs and query results never enter extension storage. The
versioned client signing seed/server pin and bounded opaque successful-fill MRU
persist in trusted-context-only local profile storage; browser profile/key compromise remains
inside the existing approved-client threat limit.

An extension-origin iframe protects its contents from page reads and CSS; it
does not make an embedded chooser browser chrome or prevent page clickjacking.
Closed shadow embedding is layout encapsulation, not an authorization boundary.
This explicit tradeoff is recorded in ADR 0007's inline implementation contract.

One-time-code enrollment additionally covers `zann-crypto/src/ipc_pairing.rs`,
`zann-client/src/browser_ipc/pairing.rs`, `zann-daemon/src/engine/pairing.rs` and
the WASM pairing projection. Review the five-attempt native window, monotonic
expiry at start/commit, generation replacement, final Noise transcript/identity
binding, directional confirmation, one-use proof/code state and durable
publication before pin installation. No code or verifier may enter persistent
extension storage, native identity snapshots or diagnostics.

Successful-fill ordering adds the strict local schema/ranking owner at
`zann-client/src/browser_ipc/usage.rs`, its WASM projection and `apps/extension/src/usage.js`.
Review native-only `match_quality` production, stable complete-search sorting,
server/storage/vault isolation, DOM-acknowledgement before recording, no query /
release-only writes, identity-serialized update/reset and storage-failure outcome
reporting. Only opaque IDs are retained; no credentials, URLs or timestamps.


Virtual login lists add `zann-ui-core/src/login_list.rs`, the shared prepared
text query in `filter.rs`, `zann-browser/src/login_list.rs`, and the packaged
`apps/extension/src/login-list.{js,css}` adapter. Filtering sees only admitted
public labels, preserves rank and maps back to original IDs. Review bounded
window projection, transient query lifetime, keyboard/IME guards, revision checks
on detached rows and shared DOM rendering; no filter may grant native access.
The WASM dependency on toolkit-neutral presentation must retain the existing
no-DB/no-HTTP/no-keystore feature boundary.

## Native unlock and scoped recovery (#270)

Review `zann-core::unlock`, `zann-ui-core::password`, `zann-flows::unlock`,
`zann-client::app::{unlock,connection_removal,local::recovery}`,
`zann-client-sqlite::local_vault::recovery`, `zann-db::{sqlite_pin,local::recovery}`
and the thin FFI/Apple/COSMIC adapters together. Password feedback exposes only
translation keys, never estimator patterns or typed secret values. Existing
credentials are passed unchanged; new-password rules share one owner.

A recovery confirmation is scoped to one exact preview token, local generation,
data version and keyring value. Snapshot failure, cancellation, stale data or an
unconfirmed unsent-data warning must preserve local records. SQLite writer
reservation and source validation precede Config account-profile removal/remembered
unlock disarm; local deletion and instance UUID rotation commit atomically.
Ordinary pool TEMP triggers reject writes from stale database instances, even on
reconnected pool connections. Recovery is native-only and sends nothing remotely.
Account removal uses the existing credential journal, never a second credential
store. Device reset retains server sign-ins; neither operation claims to recover
forgotten encryption passwords.

Verify cross-account key isolation, encrypted snapshot restoration, stale preview
rejection (including same-cardinality edits), snapshot failure, post-reset stale
handles, and late unlock result rejection. Shared idle/focus policy applies while
account/recovery screens hold an unlocked root. Trusted OS authentication sheets
must not cancel their own unlock, and startup remembered-unlock must not repeat
on every lock.

## Account-scoped replicas (ADR 0011)

Review `zann-client::config::v2::{replica,profile,anchor,generation_model}`,
`repository::{connections,credential_remove,auth_intent}`, `app::connections`,
`zann-client-sqlite::{target_binding,local_vault::recovery}` and SQLite migration
0007 together. Endpoint trust has one normalized owner; replica storage and key
fingerprints belong to exact profiles. Pending `expected_account_subject` is only
a reconnect constraint. Authenticated `/me`, exact-source credential journals and
Config generation leases must precede selected-UUID cache claim release. Adding,
logging out or removing another profile must not redirect keys, data, tokens or
in-flight operations. Check old primary/backup/journal refusal before database
migrations and credential I/O, and shared Add/Reconnect effects through native/FFI
consumers. No personal plaintext or account key crosses the server boundary.

ADR 0012 adds authenticated `AccountKeyOrigin` to the existing account-envelope
AAD, shared-only enrollment and sync admission. Review
`crates/zann-client/src/app/account_keys/enrollment.rs`,
`crates/zann-client/src/session/account_identity.rs` and
`crates/zann-client/src/sync/engine/catalog.rs` with the existing keyring CAS and
sync proof boundary. A random candidate is persisted before its Config fingerprint;
local-cache purpose cannot publish personal keys. The explicit format/policy-change
procedure is in `docs/operations/shared-cache-key-cutover.md`.

## Headless passkeys (#200)

`crates/zann-passkey/**`, `zann-crypto::es256` behind the `passkey` feature,
`zann-autofill::RpId`, and `zann-core::item_policy` own credential custody,
ES256/COSE/attestation, origin admission and personal-only eligibility.
Review immutable `get_assertion`, permanent zero counters and BE/BS flags,
explicit presence and truthful verification, bounded candidate/ID/key input,
PKCS#8 validation and zeroizing temporary key material. Provider adapters must
authenticate observed origins and bind fresh confirmation to one operation;
this headless stage does not qualify a live browser/OS provider.

`zann-ui-core::{item_policy,item_detail,item_editor,categories}` and shared
schemas project only public profile-admitted passkey fields. Neither malicious
payload field kinds nor reveal/copy metadata can expose a passkey key through
the generic detail/editor APIs. FFI and COSMIC consume the same policy. Local
write encryption and server typed/history payload admission reject shared
passkeys. Vault `v1` envelopes, sync checkpoints and keyring transitions are
unchanged. Regression coverage includes standard RFC/W3C/CTAP vectors and two
independent offline credential copies; live provider and export qualification
remain #292–#294, #297 and #298.

### Plaintext export step-up (#297)

`zann-client::app::local::export`, `zann-client-sqlite::local_vault::{export,export_file}`,
`maintenance::private_output` and `zann-ffi::export` own the proof-to-publication
boundary. A fresh local factor mints one opaque 120-second permit tied to the
current root, keyring, context generation, policy and cancellable operation.
The default policy accepts the device password, an enrolled hardware key with
presence/PIN, or an available enrolled biometric key with a fresh OS prompt.
Strict policy requires password plus hardware/biometrics and explicitly refuses
last-factor removal. Missing or malformed policy metadata fails closed.

Review proof replay/expiry, cancellation during prompts and SQLite waits, lock
and key eviction, strict factor removal, redacted PIN/password errors, and atomic
0600 publication with failed-output cleanup. Shells show the plaintext warning
and local challenge before any export file or destination picker is opened.
