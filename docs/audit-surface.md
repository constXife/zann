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
