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
- server audit-log infrastructure;
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
