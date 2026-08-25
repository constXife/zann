# Zann client architecture

This document describes the target architecture shared by the CLI, Tauri and
COSMIC clients. It is normative for new code. Existing deviations are migration
exceptions recorded in [`architecture/capabilities.md`](architecture/capabilities.md).

The decision to converge the clients is recorded in
[`ADR 0001`](adr/0001-shared-client-core.md). The capability map is the source
of truth for ownership and allowed extension points.

## Goals

- One implementation of every security- or consistency-sensitive capability.
- Thin clients that translate typed state into platform UI and execute effects.
- No client-specific interpretation of crypto, protocol, auth or sync policy.
- Explicit, versioned contracts for persisted state and server traffic.
- New clients are adapters over shared services, flows and presentation models.
- Dependency direction and client conformance are enforced in CI.

## Non-goals

- Sharing widgets or layout between Vue/Tauri and libcosmic.
- Forcing the server-only CLI through SQLite or an FFI boundary.
- Hiding platform integrations such as tray, biometrics or file pickers in the
  domain layer.
- Preserving internal APIs while the current client forks are consolidated.

## Layers and dependency direction

Dependencies point down. Lower layers never import a client framework or call
back into a shell.

```text
CLI / Tauri / COSMIC
  |---> zann-client
  |       |---> zann-core
  |       |---> zann-protocol (planned)
  |       `---> zann-keystore (os-credentials feature only)
  |---> zann-client-sqlite ---> zann-db
  |---> zann-flows (planned) ---> pure domain/application types
  `---> zann-ui-core -----------> zann-core

non-Rust consumer ---> zann-ffi ---> zann-client / zann-ui-core
```

zann-ffi is an edge adapter over the application and presentation APIs. It is
not an application layer and Rust clients must not use FFI types as their
internal domain model.

`zann-protocol` and `zann-flows` name the accepted target boundaries. Until
those crates are introduced, their code must remain in the canonical owner
listed in the capability map; it must not be copied into a shell.

## Boundary rules

### Shells

The CLI, Tauri backend/frontend and COSMIC app may own:

- argument parsing, terminal formatting and process exit behaviour;
- widgets, layout, navigation and framework lifecycle;
- Tauri commands/events and libcosmic tasks/subscriptions;
- platform clipboard, tray, biometrics, browser and file-dialog adapters;
- mapping a small, closed set of abstract icons to toolkit icons.

They must not own:

- HTTP routes, wire DTOs, auth headers, fingerprint or token policy;
- KDF, encryption, payload integrity or key derivation;
- sync cursors, conflict, version or deletion semantics;
- persisted shared-config schemas or credential serialization;
- category, filtering, masking or field-ordering policy.

An adapter may translate a typed shared error into presentation text. It must
not recover semantics from free-form error strings.

### Application and flows

`zann-client` owns remote access and application-session orchestration. The
crate defaults to `remote`; persisted configuration is an explicit `config`
feature and exposes only the crash-safe v2 repository. The opt-in
`session` surface composes `remote` with `auth-lock` and owns DB-free password
login plus authenticated refresh/logout orchestration without pulling SQLite, `zann-db`,
`zann-keystore` or a platform keyring. Plaintext v1 config writers and raw
bearer helpers are not part of the canonical package. The concrete
OS-store adapter is a separate `os-credentials` feature; selecting `remote`,
`config` or `session` alone never pulls a keyring implementation. That adapter
selects only the thin `zann-keystore/secret-store` surface with default
features disabled, so token storage never brings remembered-unlock, FIDO or
raw-HID dependencies with it.

The clean crate exposes one low-level discovery primitive:
`zann_client::probe::probe_system_info`. It owns its redirect-free client,
bounds the response body and returns system information only after the signed
server identity verifies.

COSMIC and FFI use the shared `AppClient`; CLI and Tauri keep their existing
paths until each can move config, trust, auth, refresh and logout together in a
tested vertical slice. No dual-write bridge is allowed during activation. The
shared boundary durably records in-flight
password-login, refresh and logout operations. Password login is intentionally
limited to an already-pinned connection and a present-or-absent profile; it
cannot create, pin, relocate, open SQLite or activate a shell. Remaining
activation work is consumer migration plus OIDC and service-token login, local
storage/sync, and deletion of each legacy writer as a tested vertical slice.

Headless flows accept typed events and return state plus declarative effects:

```text
handle(State, Event) -> (State, Vec<Effect>)
```

Flows have no UI toolkit, async runtime or global filesystem dependency.
Long-running effects carry an operation ID and cancellation handle. A late
response from an older operation cannot mutate current state.

### Domain, protocol and presentation

`zann-core` contains domain models, invariants, policies and ports. It does not
know about reqwest, Tauri, libcosmic, Clap, database rows or OS paths.

`zann-protocol` contains versioned, serde-compatible wire contracts shared by
server and client transport. It contains no HTTP client, persistence, runtime or
business orchestration.

`zann-ui-core` produces toolkit-neutral view data: categories, folder trees,
filters, ordered fields, labels, masking/copy/reveal policy and TOTP parameters.
It does not produce Vue components, libcosmic widgets or translated prose
errors.

### Infrastructure and security

`zann-crypto` is the only implementation of KDF, payload encryption,
authentication and integrity primitives. Other crates call its typed API; they
do not wrap copied algorithms.

`zann-db` implements persistence ports and owns database-specific details.
`zann-keystore` implements credential storage. Neither decides UI, auth-flow or
sync policy. Its generic secret store uses a versioned physical namespace that
cannot address the historical DWK or CLI entries. Those are reachable only
through explicit compatibility adapters; the CLI adapter is read-only.

## Single-writer invariants

State that crosses client or process boundaries has one writer abstraction:

- `ConfigRepository`: schema versioning, migrations, locking and atomic replace;
- `CredentialStore`: access/refresh/service tokens and stored secret material;
- `RemoteClient`: routes, headers, TLS/fingerprint handling and error decoding;
- `SyncEngine`: cursor, version, conflict and deletion semantics;
- `AppClient`: authenticated existing-target composition and operation-scoped
  sync-store selection;
- `zann-crypto`: KDF and encrypted-payload format.

Clients may keep private UI preferences in client-specific files. Shared
connection metadata is namespaced and versioned. Credentials are not persisted
in shared JSON configuration.

Paths are injected through a typed `ClientPaths` value. No service derives a
second implicit `$HOME/.zann` root after an application has selected its root.
Credential references are bound to that canonical root; moving a migrated
repository is an explicit migration operation, not an implicit path change.

Config v2 is published beside, not over, the legacy file:

```text
client-config.json          versioned, secret-free canonical state
client-config.lock          permanent cross-process lock target
client-config.credential.lock
                            permanent credential-lifecycle operation lock
client-auth.lock            permanent root-scoped authentication operation lock
client-config.backup.json   previous valid v2 generation
client-config.restore.json  durable, idempotent restore journal (normally absent)
client-config.credential-intent.json
                            secret-free credential transaction/cleanup intent
client-auth.intent.json     secret-free exactly-once auth-operation intent
config.json                 legacy migration source, read-only to v2 clients
```

The repository exposes locked mutations against the latest revision, not a
whole-document `save(snapshot)` operation. Migration writes and verifies
deterministic, repository- and source-bound credential references before
publishing v2. It
retains a digest of the legacy config and known-host files and reports
divergence if an older client changes them; it never silently merges or
overwrites that change. Each client claims its own legacy projection
atomically, so startup order cannot choose which shell receives the active
connection.

An existing backup blocks fresh initialization when the primary is missing.
Recovery is explicit, never falls back from a future schema, and advances the
revision beyond both the predecessor backup and the potentially lost primary
generation. A restore that swaps two valid generations is completed from a
durable journal before any later repository operation.

All three process locks use the same owner implementation. Their files remain
empty and permanent; ownership lives only in the operating-system lock held by
an open handle. Before and after acquisition the implementation verifies that
the path still identifies that handle, rejects indirect/non-regular targets
(including Windows reparse points and Unix hard-link aliases), and applies
private `0700` root / `0600` lock permissions on Unix. The only permitted
nested order is `client-auth.lock` -> `client-config.credential.lock` ->
`client-config.lock`. `AppSession` holds authentication and then credential
ownership across reconcile, trust verification, the exactly-once remote
operation and its terminal local commit or revoke. The config lock is acquired
only for bounded repository steps. Network and credential-store calls may run
under the two outer operation locks, but never under the config lock.

Credential transactions use a separate, secret-free compact intent containing
generation digests, revisions and exact credential-reference topology. It does
not duplicate full config generations or contain credential values or
secret-derived hashes.
The intent is a crash-recovery state record under the cooperative-writer model,
not a cryptographic authenticity boundary.

Login is a single authenticated-session transaction across the canonical
config generation: identity, trust binding, optional local storage reference,
credentials and active selections appear together or not at all. For local
sessions SQLite storage is created first and then treated as a
recoverable projection; remote-only sessions publish no storage reference.
The current DB-free password slice accepts only an existing pinned connection,
preserves its storage binding, and records the canonical `/me.user_id` plus the
exact `Password` auth method on the credential profile. It rechecks bounded
prelogin data on canonical `/me.email` and requires exact salt, KDF parameters
and recomputed-fingerprint coherence before candidate publication.
Logout and refresh rejection use a symmetric credential-aware revoke rather
than editing metadata directly.

Before an existing refresh secret is read or sent, `AppSession` probes the
canonical endpoint and verifies the exact stored address, server identity and
fingerprint binding. In protocol v1 the fingerprint is unsigned TOFU metadata
observed through the configured transport, not part of the signed identity
proof. A refresh is dispatched at most once. Once dispatch may have happened,
a timeout, transport loss, 5xx response, oversized/truncated body or invalid
success response is an ambiguous outcome: it is never retried automatically,
and the anchored local profile is revoked so restart cannot replay the old
refresh credential. A successful refresh rotates only access and refresh
credentials against the original profile anchor; any service account
credential id and secret in the same profile are preserved.

The live operation guards and future-drop handling do not cover process death:
`SIGKILL` releases the operating-system locks and destroys the future without a
terminal local commit or revoke. `AppSession` therefore writes
`client-auth.intent.json` before auth dispatch. Version 1 covers refresh/logout;
version 2 adds password login with fresh credential-ID reservation and an exact
source-or-absent profile anchor. Both are bounded to 64 KiB and 256 JSON nodes,
reject duplicate/unknown/future fields, are bound to the canonical repository
root, and contain no credential values or secret-derived hashes.
Its non-clone live ownership token binds transitions to the digest of the exact
journal bytes and operation id. State moves from `armed` to
`candidate_prepared` only after fresh-id validation/absence preflight and before
the normal credential journal or credential-store writes.

Restart holds authentication then credential ownership, validates the auth
intent before any credential-store call, reconciles restore/credential state,
and classifies the primary again. For refresh/logout an exact source is
journal-revoked. For password login an exact source or originally absent
profile is abandoned without deleting reserved or source credentials. An exact
committed candidate is preserved and an absent target is accepted as terminal;
any other state remains a typed recovery conflict with no auth retry. A
candidate marker without a credential journal never authorizes deletion of its
fresh ids. Public credential writers, initialization and restore fail closed
while recovery is pending, while read-only snapshots remain available.

The secret-free login intent cannot recover a refresh token returned immediately
before `SIGKILL`; that narrow remote orphan remains valid only until server TTL.
Closing it requires a protected durable `must_revoke` secret or a server
operation/idempotency handle. Live compensation failures are surfaced as an
unknown remote outcome. The pre/post prelogin comparison also narrows, but does
not cryptographically eliminate, KDF races until the server authenticates KDF
identity in the login or `/me` response.

Verified-binding construction and bearer access remain internal to the shared
transport/session boundary. Explicit trust replacement is a separate decision;
`AppSession` does not infer it from an auth response.

The filesystem protocol assumes a local filesystem and cooperative writers
running as the same OS user. The repository makes its root private and rejects
static symlink/non-regular targets, but it is not a sandbox against a hostile
same-UID process. That stronger boundary would require capability-directory,
directory-relative no-follow opens and renames on every supported platform.

Canonical v2 accepts only registered, versioned client namespace schemas; it
does not expose a raw JSON writer or flattened extension bag. Unknown
non-security legacy extensions remain in the digest-pinned legacy source and
only their paths are recorded for a future migration. Unknown KDF or credential
profile fields fail closed because silently ignoring them could change secret
derivation or token semantics. Credential references are private repository
state: a caller cannot inject one through a connection metadata update, and a
credential lifecycle transaction must store, read back and bind a secret before
publishing its reference. Its durable intent contains only validated config
generations, credential IDs and digests—never secret values or secret hashes—so
a crash between the OS-store write and config publish can be reconciled after
restart. OS credential calls run outside the config lock, and cleanup rechecks
all durable generations before deleting an ID.

Old keyring entries have no revision marker, so their later mutation cannot be
proven from the file digest alone. A consumer is not activated on v2 until its
auth and refresh paths have also stopped writing the legacy keyring and config.
Rollout is therefore vertical per consumer, not a read-path-only switch.

All JSON inputs are bounded and reject duplicate keys before typed decoding.
Migration also enforces semantic count and string limits and validates the
complete canonical candidate before invoking a credential backend. Persisted
KDF parameters are checked by the same bounded policy used immediately before
`zann-crypto` performs the computation.

An endpoint's canonical address and trust identity cannot be changed by a
generic metadata update while credentials are bound to it. Equivalent URL
spellings share one trust key, and once an endpoint has a pin, an unpinned alias
cannot downgrade it. Retargeting is an explicit credential-aware operation.

## Contracts and compatibility

- Persisted and wire formats have explicit versions and migrations.
- Writers use atomic replacement and the appropriate cross-process lock.
- Readers preserve unknown namespaced data when another client may own it.
- Crypto compatibility is protected by golden fixtures, not implementation
  duplication.
- Public application APIs return typed results and stable error kinds.
- Breaking contract changes include migration notes and conformance fixtures.

## Testing and enforcement

Shared behaviour is tested once at its owner and through each consumer adapter:

- unit and property tests for domain and crypto invariants;
- golden tests for crypto, config migrations and protocol serialization;
- DB-backed auth and sync tests for final state, not log text;
- flow tests for timeout, cancellation and stale async responses;
- conformance tests through CLI, Tauri and COSMIC adapters;
- exact-feature compile/tests plus dependency-closure checks for every thin,
  non-default client surface;
- dependency and source guards for forbidden implementations in shells.

A change to a shared contract is not mergeable unless all affected consumers
build and their conformance tests run. Full compositor/UI tests may remain
selective, but headless client-adapter checks are mandatory.

## Change process

1. Locate the capability owner in the capability map.
2. Add or change the canonical implementation and its contract tests.
3. Migrate every affected consumer using typed adapters.
4. Remove replaced code and its migration exception in the same change series.
5. Update the map or add an ADR before introducing a new layer or owner.

The exception process and Definition of Done are specified in
[`architecture/capabilities.md`](architecture/capabilities.md).
