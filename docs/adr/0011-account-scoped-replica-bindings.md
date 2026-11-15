# ADR 0011: Account-scoped replica bindings on one server

- **Status:** Accepted
- **Proposed:** 2026-11-15
- **Accepted:** 2026-11-15
- **Scope:** `zann-client::config`, `zann-client::app`, `zann-client-sqlite`, native account selection
- **Related:** [ADR 0001](0001-shared-client-core.md) (Accepted),
  [ADR 0010](0010-device-unlock-account-keys.md) (Accepted),
  [ADR 0016](0016-account-session-and-removal-lifecycle.md) (Proposed)

This decision extends account cardinality and authorizes the direct Pre-GA Config
cutover below. ADR 0010 remains the keyring and device-unlock owner.

## Context

Measured in `main` at `d61a8a6` on 2026-11-15:

- [ConfigV2](../../crates/zann-client/src/config/v2/journal_model.rs) already stores
  `account_identities` by connection/profile. There is no global account identity to migrate again.
- [ConnectionMetadata](../../crates/zann-client/src/config/v2/schema.rs) still owns
  `storage_id` and `expected_master_key_fp`.
- [Authenticated target admission](../../crates/zann-client/src/config/v2/authenticated_target.rs)
  prohibits endpoint aliases and rejects a different storage binding on an existing connection.
- [Account-key resolution](../../crates/zann-client/src/app/kdf_identity.rs) combines
  that connection's storage with the selected profile's canonical account subject.

Inference: independent offline replicas for two subjects on one endpoint need
profile-scoped bindings. Multiple configured profiles alone do not supply that capability.

## Decision

1. Keep normalized endpoint identity, server ID and TOFU fingerprint on the existing
   `ConnectionConfig`. Two subjects on the same endpoint share its trust decision;
   a second account cannot create an alias to bypass or replace the pin.
2. Move replica storage UUID and expected account-key fingerprint from connection
   metadata to the corresponding `CredentialProfile`. Reuse `account_identities`
   for per-profile KDF identity. A remote-only profile has no replica binding;
   a native replica has exactly one explicit binding. Enforce uniqueness of the
   enrolled `(server_id, account_subject)` and of the storage UUID, using authenticated
   subjects rather than email, profile labels or whichever account is visible.
3. Update canonical target resolution, generation leases, credential anchors,
   sync, account selection and removal together. The keyring continues to bind
   device/storage/server/subject as ADR 0010 requires. No active-profile inference
   may substitute for a binding captured by an operation.

## Profile schema and provisioning

`CredentialProfile` owns optional `storage_id` and `expected_master_key_fp` alongside
`account_subject`, `auth_method`, expiry and opaque credential references. Native
storage IDs are canonical UUIDs at the SQLite boundary. The expected key fingerprint
is canonical twelve-character lowercase hexadecimal; a remote-only CLI profile may
omit both replica fields. The existing `account_identities[connection/profile]`
continues to own KDF parameters. Neither crypto envelopes nor their AAD change.

Connect distinguishes Add Account from Reconnect by an explicit storage UUID.
A new account reserves an opaque profile and storage UUID. Before authentication,
that profile has no credentials, authenticated subject, key fingerprint or KDF
identity. One unowned provisioning slot per endpoint is reused inside the Config
write transaction, so cancelled/repeated probes do not consume the profile budget.
An authenticated profile is never eligible for reuse. Competing login operations
retain their exact full-profile anchors and cannot overwrite a winning account.

A disconnected replica is looked up by UUID, never by URL or email. Its canonical
subject becomes `expected_account_subject` on that explicit pending profile. This
is a constraint, not authenticated identity or proof of a usable key. Only a matching
canonical `/me` result may replace it with `account_subject` and credentials. Repeated
reconnects reuse the same constrained profile; they cannot retarget another storage.
Native storage summaries project the matching profile's optional canonical account
name from `account_identities`; `zann-ui-core::sync_status::storage_context_label`
formats server/account labels for COSMIC and Apple/FFI. Labels never authorize or
select a profile. Metadata listing does not initialize/read credentials.

Pin replacement and reservation publish in one exact-revision Config transaction.
A changed server ID is refused. A changed fingerprint requires explicit confirmation,
including when it comes from the selected disconnected replica's cached pin.

After authentication, an exact Config lease must match the access capability's
endpoint, pin, storage, subject and auth method. Only then may the SQLite adapter
release that UUID's previous generation claim. Sync still proves the account key
and complete catalog before claiming or changing its projection. An unrelated
profile or active-selection change cannot redirect the operation. Removing one
account retires only its credentials/identity; scoped local recovery also removes
only its key envelope and replica. The shared endpoint pin remains. After a shared
pin change, other accounts retain their cache claims and receive the existing
sign-in-required sync state until explicitly reauthenticated. Confirmation for
one profile never silently releases another profile's projection. Explicit whole
endpoint removal remains a separate capability: native “Forget Server” recovers
from a changed server identity and confirms removal of every saved sign-in on
that endpoint. It leaves offline replicas and envelopes intact for explicit
reconnect; account-scoped recovery and logout must never invoke it.

## Direct Pre-GA cutover

There is no automatic mapping of an old connection-level binding to one of its
profiles. Old `metadata.storage_id` or `metadata.expected_master_key_fp` fields,
including explicit nulls, are refused with an export/fresh-root/import diagnostic.
The native startup gate checks the primary, backup, embedded restore/credential
journals, auth intent and legacy config before SQLite initialization or migrations
and before credential access. An auth intent without a readable current-format
primary requires explicit recovery before opening SQLite. Existing files are preserved. Duplicate normalized
endpoint trust owners are also refused; aliases are not an account mechanism.
Remote-only configurations with no superseded fields can keep their existing shape.

Use the [cutover procedure](../operations/account-replica-cutover.md). This costs
one explicit export/verification pass per existing account and reconnect/enrollment
in a fresh root. It avoids guesses about ownership, compatibility branches, dual
writes and an ongoing migration ledger. Server accounts and crypto formats do not
change. No migration exception is introduced.

SQLite migration `0007_account_scoped_replicas.sql` replaces the unique URL index
with an indexed URL lookup and unique remote `(server_url, account_subject)` pair.
The Config owner independently rejects duplicate native `(server_id, subject)` and
storage bindings. All catalog/item/history/pending/cursor access stays storage-scoped.

## Verification contract

- Config tests cover two subjects sharing one trust record, stable account proof
  despite another profile, duplicate storage/subject rejection before credential
  writes, pending reconnect subject checks and independent profile removal.
- Native provisioning tests cover 200 cancelled/repeated probes reusing one slot,
  no pre-authentication cache release and atomic reconnect trust confirmation.
- SQLite tests use two profiles on one endpoint with independent keys and identical
  vault/item UUIDs; resolving/pulling/resetting one leaves the other projection intact.
  Startup cutover tests preserve config, journals and database bytes without WAL creation.
- The real HTTP/Postgres integration test in
  `crates/zann-integration-tests/tests/account_replicas.rs` enrolls two subjects,
  syncs, restarts, exports, logs out one and removes its replica while the other
  account's credentials, key and data continue to work.
- COSMIC consumes the same explicit Add/Reconnect flow as Apple through FFI;
  FFI/flow tests and the macOS build/binding tests cover their changed contract.
  Config-only and remote-only CLI feature checks must remain free of SQLite.

## System alignment review

- **Reuse:** Config/profile repositories, authenticated endpoint uniqueness and
  generation leases remain the owners; `DeviceUnlock` remains the sole keyring policy.
- **Justified divergence:** replica binding changes cardinality from one per
  connection to one per account profile. This is not a second connection or keyring model.
- **Realigned:** all connection-level replica/fingerprint consumers,
  including account-scoped recovery. Superseded fields and the single-profile
  generation gate are removed. ADR 0016 remains Proposed for broader lifecycle work.
- **Aligned as-is:** ADR 0010's random device root and per-account encryption envelopes.

## Values interrogation

There is no separate repository values manifest/template. The tests below apply
the trust, custody, SSoT, crash-safety and bounded-work invariants in
[AGENTS.md](../../AGENTS.md) and the [capability map](../architecture/capabilities.md).

| Lever | Trust and custody | SSoT and consolidation | Crash safety and bounds | Cost and verification |
|---|---|---|---|---|
| Shared endpoint trust | Adding a subject cannot weaken the existing pin | Reuse the connection's single trust record | Existing authenticated target checks gate writes | No repeated trust ceremony; test alias/pin replacement rejection |
| Per-profile replica binding | Exact subject/storage/fingerprint prevents cross-account key use | Move existing fields; reuse the KDF identity map | Retain bounded config validation and exact generation leases | Consumer changes are required; test two subjects on one endpoint |
| Coordinated cutover | Never infer an account from a label or active screen | Delete connection-level binding after all consumers switch | Refuse ambiguous source before writing; no dual-write interval | Explicit one-time export/reconnect cost; refusal preserves original files |

## Consequences, debt and alternatives

This enables personal/admin accounts on one server without separate client roots.
The implementation cost is a coordinated schema/consumer change, not a new crypto
format or an extra per-unlock KDF. Independent accounts can use independent profile
records; adding one does not require rewriting a central account registry in code.

The direct cutover is intentionally breaking. Its operational cost is explicit in
the procedure; there is no compatibility or account-ownership inference debt.
Unrelated ADRs 0012–0016 remain Proposed.

Rejected: duplicate connections for the same normalized endpoint, email-based
account identity, or a parallel native-only profile store. Each would split trust
or account ownership instead of fixing its cardinality.

Also rejected: per-shell cleanup of cancelled reservations. A shared bounded,
reusable unowned slot is idempotent and avoids stale-result cleanup races in both
native executors. An authenticated profile is never recycled into that slot.
