# ADR 0001: Shared client capabilities and thin interface shells

- **Status:** Accepted
- **Decision date:** 2026-08-16
- **Originally proposed:** 2026-08-05
- **Scope:** `crates/zann-cli`, `apps/desktop`, `apps/cosmic` and their
  shared Rust crates

## Context

Zann intends to have one Rust implementation of security- and
consistency-sensitive behaviour with several native interfaces. The current
clients do not yet satisfy that intent:

- the Tauri backend contains a fork of the auth and sync implementation in
  `zann-client` (roughly 2,600 duplicated lines at the time of the audit);
- CLI, Tauri and `zann-client` read and write incompatible representations at
  the same `~/.zann/config.json` path;
- master-key derivation and encrypted-payload helpers have implementations in
  `zann-client`, Tauri services and `zann-ffi`, despite `zann-crypto` being
  their intended owner;
- the CLI implements its own HTTP/auth/token stack and wire payloads, which has
  already allowed request fields and server pagination behaviour to drift;
- COSMIC reaches local behaviour through `zann-ffi`, while parts of
  `zann-ffi` perform application orchestration and derive their own filesystem
  root;
- connect, OIDC cancellation, idle locking, category policy and item-detail
  projection are repeated across the Tauri and COSMIC interfaces.

These are not only maintenance costs. A client can erase another client's
configuration, two sync engines can interpret deletion differently, a cancelled
OIDC listener can outlive its screen, and a fix to a crypto or auth path can miss
one copy.

The repository therefore needs architectural boundaries that are enforced by
types, dependency direction, conformance tests and CI. Documentation alone is
not sufficient.

## Decision

### 1. Capabilities have a single canonical owner

Every shared capability has exactly one owner. The normative map of owners,
consumers, extension points and forbidden locations is
[`docs/architecture/capabilities.md`](../architecture/capabilities.md).

A shell can adapt an owned capability but cannot provide a second
implementation. Existing copies are temporary migration exceptions, not
precedent for new code.

### 2. Shared state and crypto are single-writer boundaries

Before moving higher-level auth and sync code, the clients will converge on:

- a versioned configuration envelope with explicit migrations;
- namespaced client-private state and preserved unknown namespaces;
- atomic writes and cross-process locking;
- an injected `ClientPaths` value, with no secondary implicit home-directory
  lookup;
- a `CredentialStore` abstraction backed by `zann-keystore`, keeping tokens
  and secret material out of shared JSON;
- the sole KDF and payload-crypto implementation in `zann-crypto`, protected by
  compatibility fixtures.

No normal architecture exception may introduce another config writer,
plaintext credential store or crypto implementation.

Config v2 is written to `client-config.json`; legacy `config.json` is retained
as a read-only migration source until old writers are retired. Repository
mutations reread the latest revision while holding a permanent sibling lock,
atomically replace the file and keep one previous valid v2 generation. The API
does not expose whole-document `save`, and it does not downgrade an unknown
future schema from backup. A missing primary with an existing backup cannot be
reinitialized as empty state: recovery is explicit and advances the revision
past the potentially lost generation. Flattened extensions cannot shadow
typed fields, and namespace updates are patches rather than lossy typed
round-trips. Canonical state uses registered namespace schemas instead of a raw
JSON writer; unknown non-security legacy extensions stay in the digest-pinned
source with only their paths recorded, while unknown KDF or credential-profile
fields fail closed. Credential references are private, repository-bound state,
and each client atomically records that it has claimed its own legacy
projection. A valid-generation rollback uses a durable journal that every
repository operation completes idempotently before proceeding.

Canonical and legacy JSON are byte- and structure-bounded and reject duplicate
keys before typed decoding. Migration validates semantic counts and the final
serialized candidate before calling a credential backend. Persisted KDF
parameters use the same bounded `zann-crypto` policy as execution. Credential-
bearing connections cannot be silently retargeted: canonical URL aliases share
one trust identity, and rebinding requires an explicit credential-aware
transaction.

Authenticated login is also one credential-aware candidate: identity, trust
metadata, optional local storage reference, credential bundle, active profile
and the calling client's active connection are published together. Local
sessions create or reuse SQLite storage first and reconcile it as a projection
after publication; remote-only sessions leave the storage binding absent.
The first DB-free password slice is narrower: it requires an existing pinned
connection, preserves any storage binding, and records canonical `/me.user_id`
plus the exact `Password` method on the credential profile.
Logout and refresh rejection use the inverse repository transaction so stale
OS credentials are never detached from their provenance by a metadata edit.

The legacy integrity digest covers config and known-host files. Old keyring
entries have no revision marker, so a consumer cannot activate the v2 read path
while its old auth or refresh path may still mutate those entries. Each
consumer therefore switches config and credential persistence together in one
vertical slice.

### 3. Remote and local application APIs share `zann-client`

`zann-client` is the application API for client use cases:

- a remote-only surface owns routes, HTTP behaviour, server probing, auth,
  fingerprint trust, token lifecycle and typed remote errors;
- a DB-free `session` surface composes the remote and authentication-lock
  capabilities and owns password login plus authenticated refresh/logout
  orchestration; its owner type and entry points remain crate-private;
- a DB-free, bidirectional `sync` surface injects its transactional local store and
  owns strict wire validation, pending-aware merge/delete policy, cursor and
  sequence progression. Each validated projection carries the fingerprint
  derived from the exact payload key; the later local adapter must CAS that
  immutable key binding together with the page, even when the page is empty.
  The active DB-free `app` facade composes password/OIDC login, trust,
  refresh/logout and sync through an injected, lazy local-store factory without
  exposing `AppSession`, `SyncEngine` or bearer access. A later application
  expansion adds the remaining local storage use cases.

The remote, session, sync and app surfaces must be feature-separated from SQLite,
`zann-db`, `zann-keystore` and platform keyrings so the CLI can remain
server-only. Sync may depend on `zann-crypto`, but its database implementation
is injected as a port. Push conflicts and initial shared snapshots use explicit
wire validation and atomic local checkpoints. Its page commit is an
owned terminal task after dispatch; cancellation before dispatch performs no
write, while runtime/process shutdown recovers from the atomic cursor/sequence
checkpoint instead of blindly retrying an ambiguous commit. Platform-specific
credential, callback-listener and filesystem implementations are injected as
ports. COSMIC and FFI have moved their complete config, trust, auth, refresh,
logout and sync path to the application facade; CLI and Tauri still require a
vertical migration. Dual activation with an old writer is forbidden. Its
exactly-once auth dispatch is now backed by the secret-free,
repository-bound `client-auth.intent.json`: v1 covers refresh/logout and v2
adds password login with a source-or-absent anchor and fresh-ID reservation.
Because live file locks and future-drop cleanup do not survive `SIGKILL`, startup
validates that intent before credential I/O, reconciles the credential journal,
then revokes a v1 exact source, abandons a v2 login source without deleting its
reserved IDs, preserves an exact committed candidate, or accepts an
already-removed target. Password login rechecks prelogin on canonical
`/me.email` after authenticated `/me` and requires exact KDF coherence before
candidate publication. OIDC and local storage/sync are active; service-token
composition remains a separate future slice.

The client-side pre/post comparison narrows KDF races, but authenticated KDF
identity remains a future server-protocol requirement. The secret-free intent
also cannot recover a refresh returned immediately before `SIGKILL`; a durable
protected `must_revoke` slot or server idempotency handle is future P2
hardening. Live compensation failure is always reported as an unknown remote
outcome rather than ordinary cancellation or protocol rejection.

The clean pull owner currently treats the catalog as complete only when an
explicit `limit=200`, `offset=0`, ascending request returns fewer than 200
entries. A full page fails before reconciliation because offset pagination has
no versioned snapshot or stable tie-break cursor. The service-account handler
now mirrors that compatibility boundary with a 200-row SQL lookahead and
returns `catalog_too_large`, never a partial body; catalogs above 199 still
require a future versioned snapshot protocol. Account binding is also
fail-closed before catalog I/O. It requires
an exact local canonical `/me.user_id` plus `AuthMethod` match and the verified
personal-vault capability; legacy profiles lacking that pair fail before the
catalog request. Local adapters persist pulled deletes as `Synced` rows
with `deleted_at`, and server-confirmed history replacement has no authority to
delete local/UI, pending, rejected or conflict history.
The SQLite adapter remains single-target while the physical schema uses global
vault/item/history UUID keys: a second storage that presents the same server
identifier must fail rather than alias another endpoint's projection. Composite
`(storage_id, id)` keys are required for a multi-endpoint rollout. Initial key
binding is permitted only for an empty projection through an exact
envelope/wrap/fingerprint transaction; an ordinary key update clears the
fingerprint and cannot silently re-authorize an existing cache.
The connection-level expected master-key fingerprint is bound separately,
before projection I/O, through a freshly resolved repository/profile anchor.
That Config v2 CAS accepts only a canonical twelve-lowercase-hex target,
allows absent-to-exact once, makes exact-to-exact a no-write idempotent result,
and rejects any other existing value without an explicit rebind/reset. The
anchor also preserves the observed fingerprint across unrelated revision
rebases. Auth-intent v1/v2 wire documents remain unchanged, and their internal
reconstructed anchors are not accepted by this local binding path.

The pre-v2 compatibility package was removed after COSMIC and `zann-ffi`
migrated to `AppClient`. Cargo feature separation still prevents remote-only
consumers from acquiring SQLite, raw bearer or platform credential capabilities.

Wire contracts move to a small, serde-only `zann-protocol` crate shared by the
server and client transport. Shells consume the typed `zann-client` API rather
than constructing URLs or wire requests.

### 4. Interactive workflows are headless state machines

Connect, startup, unlock, remembered unlock and idle-lock behaviour move to
`zann-flows`. A flow has the shape:

```text
handle(State, Event) -> (State, Vec<Effect>)
```

It has no toolkit or async-runtime dependency. Effects use typed inputs and
outputs, operation IDs and cancellation. Framework code only executes effects
and renders current state; an old response cannot mutate a newer operation.

### 5. Presentation policy belongs to `zann-ui-core`

`zann-ui-core` owns toolkit-neutral decisions about categories, filters,
folder trees, item field ordering, labels, masking/copy/reveal policy and TOTP
parameters. Canonical schemas and catalogues are data, not repeated conditionals
inside interfaces.

Vue/Tauri and libcosmic continue to own widgets, layout, navigation and the
mapping of abstract icons to toolkit icons.

### 6. FFI and interface crates are edge adapters

`zann-ffi` exposes the shared application API to non-Rust consumers. It owns
binding/runtime conversion and FFI-safe DTO conversion only. It is not the
internal application service for Rust clients, and application behaviour must
not be added to make an FFI call convenient.

The clients retain only shell-specific concerns:

- CLI: Clap, terminal input/output, exit codes and explicit filesystem/process
  actions;
- Tauri: commands/events, tray, biometrics, file dialogs and the Vue bridge;
- COSMIC: widgets, tasks/subscriptions, navigation and OS integration.

## Dependency direction

The accepted direction is:

```text
CLI / Tauri / COSMIC
  |---> zann-client
  |       |---> zann-core / zann-protocol
  |       `---> zann-keystore (adapter feature only)
  |---> zann-client-sqlite ---> zann-db
  |---> zann-flows ---> pure domain/application types
  `---> zann-ui-core ---> zann-core
```

`zann-ffi` sits beside the shells as an edge adapter. Domain, protocol,
crypto, application and presentation crates cannot depend on Tauri, libcosmic
or Clap.

## Consequences

### Positive

- Security and consistency fixes land once.
- The compiler and dependency guard expose boundary violations early.
- A new client renders shared state and supplies platform adapters rather than
  reimplementing auth, sync and presentation policy.
- Shared behaviour can be tested without a compositor or browser.
- The CLI stays lightweight because remote transport is independent of local
  storage.

### Costs

- The initial migration touches persisted state, auth, crypto and sync and must
  be split into reviewable, compatibility-tested changes.
- Typed ports and effects add some indirection at UI call sites.
- Tauri and COSMIC must run headless conformance checks when shared APIs change.
- During migration, explicit exceptions are required for existing dependency
  violations.

## Migration plan

Each phase starts with characterization fixtures and ends by deleting the
replaced implementation and its exception.

1. **Guardrails:** publish the capability map, add dependency/source guards and
   make shared-contract changes build every consumer adapter.
2. **State and crypto:** introduce config v2, `ClientPaths`,
   `ConfigRepository`, `CredentialStore`, atomic locking and migration
   fixtures; route every KDF/payload operation through `zann-crypto`.
3. **Protocol and remote client:** introduce `zann-protocol`, split the
   remote-only `zann-client` feature and migrate CLI HTTP/auth/token operations.
4. **Tauri auth and sync:** move Tauri to the canonical remote client and sync
   engine in small slices, then delete its fork.
5. **Application session and FFI:** activate the extracted and recovery-tested
   Rust `AppClient` API as complete consumer vertical slices, migrate Tauri and
   COSMIC, reduce `zann-ffi` to an edge adapter, and move SQLx row mapping from
   `zann-core` to `zann-db`.
6. **Flows and presentation:** migrate connect/unlock/idle flows and category,
   folder and detail projection to `zann-flows` and `zann-ui-core`.
7. **Large application services:** extract toolkit-neutral streaming
   import/export from file-dialog and command adapters when the previous
   boundaries are stable.

## Completion criteria

A phase is complete only when all of its consumers use the canonical owner,
legacy code is removed, compatibility and conformance tests pass, and the
associated migration exception is deleted. The complete Definition of Done is
in the [capability map](../architecture/capabilities.md#definition-of-done).

## Alternatives considered

### Copy behaviour into each client

Rejected. Existing auth, sync, config and presentation drift demonstrates that
review discipline cannot keep independent implementations equivalent.

### Share the entire UI

Rejected. A single web UI or toolkit would reduce presentation duplication but
would give up the native Vue/Tauri and libcosmic interfaces. The shared boundary
is behaviour and presentation data, not widgets.

### Put all behaviour behind `zann-ffi`

Rejected. FFI types are an interoperability constraint, not a useful internal
Rust architecture. Rust clients should call the shared application API directly
and `zann-ffi` should adapt that same API for future non-Rust consumers.

### Make the CLI use the local-vault facade

Rejected. The CLI has server-only workflows and should not pull SQLite, a GUI
runtime or FFI into those commands. It shares the remote client and wire
contracts instead.

### Keep architecture rules as review guidance only

Rejected. The current duplication passed code review. Dependency checks,
source guards and cross-client conformance tests are part of the decision.
