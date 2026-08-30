# Client capability ownership

This document is the normative ownership map for code shared by Zann clients.
It complements [the client architecture](../Architecture.md) and
[ADR 0001](../adr/0001-shared-client-core.md).

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** are requirements for
new code. Existing violations are allowed only when listed in the migration
exception ledger below.

## How to use this map

Before adding client behaviour:

1. Find the capability in the map.
2. Change its canonical owner.
3. Expose a typed API or extension point.
4. Keep the consuming shell limited to translation and platform execution.
5. Add owner tests and consumer conformance coverage.

If no row fits, update this document and, when the new boundary is material,
write an ADR before implementation. Creating a second implementation in a shell
is never the default extension mechanism.

An **owner** controls policy and invariants. A **consumer** calls the owner. An
**extension point** is an injected port or declarative data contract; it does
not transfer ownership to the adapter.

An owner written as `crate::module` is also the required target namespace. If
that module does not exist yet, its existing code is migration debt; the name
does not authorize another temporary implementation.

## Capability map

| Capability | Canonical owner | Consumers | Allowed extension points | Forbidden locations |
|---|---|---|---|---|
| Domain models and policy | `zann-core` | server, `zann-client`, presentation | domain ports, newtypes, pure policies | UI frameworks, HTTP clients, database rows and OS paths in `zann-core` |
| KDF, encryption and payload integrity | `zann-crypto` | server and application services | reviewed algorithms and versioned parameter types | implementations or algorithm wrappers in CLI, Tauri, COSMIC, `zann-client`, `zann-ffi` or `zann-db` |
| Database persistence | `zann-db` | local application/session services | repository transactions, migrations, streaming readers/writers | SQL and database rows in shells, flows, presentation or protocol |
| Credential storage implementation | `zann-keystore` | `CredentialStore` adapter | platform keystore backends | direct keyring calls in shells; credentials in config or logs |
| Credential lifecycle and port | `zann-client::credentials` | remote auth and application session | injected `CredentialStore`, clock and revocation policy | token refresh/selection/serialization in CLI, Tauri, COSMIC or FFI |
| Paths and persisted client config | `zann-client::config` | all client shells and application services | injected `ClientPaths`, storage backend, versioned migration | independent writers for shared config; implicit home lookup below the composition root |
| Server wire contracts | `zann-core::api` **(interim)**; `zann-protocol` **(planned)** | server handlers and the private `zann-client` transport | additive/versioned serde DTOs and explicit compatibility adapters | local wire DTOs, route strings or response decoding in client shells; transport or persistence in protocol types |
| Remote transport, auth and server trust | private `zann-client` transport; public bounded `zann-client::probe`, `zann-client::secrets` and `zann-client::session` capabilities | CLI and application sessions | HTTP transport, TLS policy, OIDC callback listener, clock and cancellation | `reqwest`, bearer headers, endpoint paths, fingerprint or OIDC policy in shells and FFI |
| Sync semantics | `zann-client::sync` **(active bidirectional surface)** | local application sessions | transactional repository port, private remote transport, progress/cancellation sink | cursor, merge, conflict, version and deletion policy in shells, FFI or presentation |
| SQLite sync persistence | `zann-client-sqlite` **(production adapter)** | native application composition roots | explicit `ClientPaths` plus one pre-resolved native SQLite file location, injected sync port, bounded projection proofs and atomic DB CAS | implicit active target selection, `HOME`/URI path derivation, binding replacement, multiple endpoint/profile caches or direct use from shells |
| Authenticated application session | private `zann-client::session` owner, exposed only through `zann-client::app::AppClient` | COSMIC, FFI and the Tauri sync composition root; future CLI adapter | `CredentialStore`, `ClientPaths`, clock, operation deadline and cancellation | constructing `AppSession` directly; password/OIDC login, trust, refresh, logout, token-selection and ambiguity policy in shells and FFI |
| Authenticated application composition | `zann-client::app` **(active native facade)** | COSMIC, FFI and the Tauri sync composition root | injected `AppSyncStoreFactory`, `CredentialStore`, explicit `ClientPaths`, operation-scoped master key, progress/cancellation | exposing `AppSession`/`SyncEngine`, bearer access, ambient paths, mutable target/key maps or local orchestration in shells |
| Local vault application use cases | `zann-client::app` **(planned beyond remote sync)** | Tauri, COSMIC and FFI adapters | storage/credential ports, `ClientPaths`, clock and progress sink | local application orchestration in Tauri commands, COSMIC screens or `zann-ffi` |
| Connect, startup, unlock and idle flows | `zann-flows` **(planned)** | Tauri and COSMIC adapters; future clients | typed effect executor, operation IDs and cancellation | flow reducers in components/screens; toolkit, runtime, filesystem or transport in `zann-flows` |
| Categories, folders, filters and item-detail projection | `zann-ui-core` | Tauri/Vue, COSMIC and future clients | canonical schema/catalogue data, translation and abstract-icon resolver | category, ordering, masking/copy/reveal and TOTP parsing policy in components or screens |
| Streaming backup/import/export use cases | `zann-client::app` | Tauri and future CLI commands | `Read`/`Write`, progress and cancellation ports | file dialogs in shared services; parsing/encryption policy in Tauri commands |
| FFI interoperability | `zann-ffi` | non-Rust consumers | binding generation, runtime bridge and FFI-safe DTO conversion | domain, auth, sync, config, crypto or presentation policy in `zann-ffi`; Rust clients using FFI as their internal API |
| Platform interaction and rendering | each shell | that shell | clipboard, tray, biometrics, browser, file dialogs, terminal IO, toolkit icon mapping | platform APIs in shared domain/application/presentation crates |

The planned crates identify accepted extraction boundaries. Until they exist:

- shared Zann request/response DTOs live in `zann-core::api` until the
  serde-only `zann-protocol` extraction; server handlers and
  the private `zann-client` transport MUST import those types directly, cover them with
  golden serialization fixtures and MUST NOT copy them into a shell;
- new cross-client flow policy MUST introduce `zann-flows` first; a bug fix to
  an existing duplicated flow stays within MIG-006, adds parity coverage and
  MUST NOT expand either implementation;
- `zann-app` is a frozen transitional implementation package under MIG-008. It
  may retain only its existing backup, snapshot and verification modules while
  those use cases are ported to `zann-client::app`; it MUST NOT acquire auth,
  session, sync, item, vault or storage orchestration, remote transport, config
  ownership or platform dependencies;
- a PR that introduces the planned crate updates the map from **planned** to
  **active** and adds dependency/conformance coverage.

## Allowed dependency direction

### Shells and adapters

- CLI, Tauri and COSMIC MAY depend on public `zann-client`,
  `zann-flows`, `zann-ui-core` and shared domain types.
- COSMIC and `zann-ffi` consume the canonical `zann-client::app` surface; a
  second compatibility client package MUST NOT be introduced.
- Target dependency edges are admitted by the machine baseline only when their
  required split exists. CLI -> `zann-client` is limited to explicit bounded
  capabilities with default features disabled; the current CLI selects only
  `remote`, whose dependency graph is free of `zann-db`, SQLite and local-vault
  migrations.
- Shells MUST NOT depend directly on `zann-db`, `zann-keystore`,
  `zann-crypto`, `reqwest`, `argon2` or `keyring` after their recorded
  migration exception is removed.
- `zann-ffi` MAY depend on the application, presentation and DTO crates needed
  to expose bindings. No shared Rust client MAY depend on `zann-ffi`.

### Application and presentation

- `zann-client` MAY depend on `zann-core`, `zann-crypto`, `zann-protocol` and
  `zann-keystore`; it MUST NOT declare `zann-db` or legacy-only dependencies.
- The remote-only `zann-client` feature MUST compile without `zann-db`,
  SQLite, local-vault migrations or a UI runtime.
- The `zann-client` `session` feature MUST compose `remote` and `auth-lock`
  explicitly and MUST compile and test without `zann-db`, SQLite,
  `zann-keystore` or `keyring`. The plain `config` feature exposes only config
  v2 and MUST remain free of `anyhow` and plaintext v1 config APIs.
  `os-credentials` is the boundary that may add the concrete secret-store adapter.
- The `zann-client` `sync` feature MUST compose `session` and `zann-crypto`
  explicitly while remaining free of `zann-db`, direct SQLx/SQLite persistence, `dirs`,
  `zann-keystore` and `keyring`. Its injected local port
  owns atomic persistence, but the engine owns validation, merge/delete policy
  and exact pending-aware CAS expectations. Push and pull pages are fully validated
  before local I/O; cursor and durable `last_seq` advance only in the page
  transaction. Shared plaintext is immediately encrypted for the local
  projection and receives a newly computed local checksum. Push conflicts are
  explicit, and initial shared snapshots use the same atomic checkpoint
  contract. Until MIG-007 removes it from `zann-core`,
  this graph inherits that crate's existing `sqlx-core` exception but exposes
  no database adapter or SQLite capability. Page transactions use owned
  terminal tasks so cancellation or caller-future drop after dispatch does not
  interrupt them. Runtime/process shutdown is recovered by reading the atomic
  `(cursor, last_seq)` checkpoint before any retry; an ambiguous live COMMIT
  result is surfaced as `CommitOutcomeUnknown` and is never blindly retried.
  Catalog reconciliation requests exactly the first 200 entries with explicit
  offset and ascending order, and accepts only a short page (at most 199): a
  full page is treated as potentially truncated and causes zero reconciliation.
  This is a temporary fail-closed bound, not pagination. The service-account
  endpoint now applies the same complete-snapshot boundary: it reads at most
  one 200-row lookahead and returns `catalog_too_large` rather than a partial
  catalog. Accounts with 0--199 authorized vaults are therefore bounded and
  complete; supporting larger catalogs still requires a versioned
  cursor/snapshot and a stable total-order key in the server contract.
  Pull commits persist every authoritative item with local `Synced` status;
  `deleted_at` alone marks a confirmed remote tombstone. Server-confirmed
  history reconciliation MUST preserve local/UI, pending, rejected and
  conflict history. The exact `VaultPayloadKey` derives the cache-key
  fingerprint carried by every item projection; a persistence adapter MUST
  echo that immutable value and CAS the vault's durable key binding in the
  same page transaction, including empty pages that only advance the
  checkpoint. It MUST NOT look up a possibly rotated key fingerprint after
  network validation.
  The current SQLite schema still keys vaults, items and history by globally
  unique server UUIDs rather than `(storage_id, id)`. The local adapter MUST
  fail closed when another storage already owns any of those identifiers; a
  multi-endpoint rollout is blocked until composite physical keys and foreign
  keys are migrated. A `NULL` vault key fingerprint may be bound only by a
  writer-serialized exact envelope/wrap CAS that proves the whole vault
  projection and checkpoint are empty.
  Each remote projection additionally stores one all-or-none Config v2
  generation proof: repository fingerprint, stable-target fingerprint,
  unsigned big-endian revision and exact content fingerprint. Only exact
  catalog reconciliation may claim an unbound generation, and only while all
  catalog key fingerprints and every item/history/pending/cursor and
  cross-storage reference are empty. Pull requires an existing claim. Equal
  revisions require identical content, rollback and repository/target changes
  fail closed, and a newer generation advances in the same `BEGIN IMMEDIATE`
  transaction as its catalog or pull write. The adapter holds the async
  `SyncCommit -> Config` lease across the DB transaction so no config writer
  can publish a different generation between authorization and commit. A
  synchronous process-wide single-flight permit admits at most one catalog or
  pull payload across all adapter instances; contenders return `Busy` without
  spawning or polling the rejected payload. Each admitted mutation is
  synchronously dispatched to an owned Tokio task before its outer future is
  returned; caller cancellation detaches but does not abort the permit or
  lease/COMMIT critical section. The adapter depends only on Tokio's `rt`
  feature in production. A missing runtime fails before mutation, an observed
  task failure is `CommitOutcomeUnknown`, and runtime/process shutdown is
  recovered from the durable generation and checkpoint without blind replay.
  Before a local adapter opens that projection, Config v2 binds the connection's
  `expected_master_key_fp` through a repository-bound credential-profile
  anchor. The metadata CAS accepts only the canonical 12-lowercase-hex value,
  permits `None -> exact` once, treats `exact -> exact` as a no-write/no-revision
  idempotent result, and requires an explicit rebind workflow for every other
  existing value. It rebases only while endpoint, storage, account/auth,
  credential, expiry and the previously observed master-key binding remain
  exact; legacy arbitrary values stay parseable but cannot be silently replaced.
  Sync also requires an exact protected account binding and the verified
  `personal_vaults_enabled` capability before the first catalog request. A
  credential profile either carries both a canonical `/me.user_id` subject and
  its exact `AuthMethod`, or carries neither for legacy compatibility. Missing
  or mismatched local bindings fail before catalog I/O; identity email is never
  used as an authenticated account subject. If that verified capability is
  disabled, a catalog containing any personal vault fails before local catalog
  reconciliation.
- The `zann-client` `app` feature MUST compose `sync` without adding a database,
  filesystem implementation, UI or ambient-path dependency. Its active
  `AppClient` owns verified connection preparation, password/OIDC auth,
  refresh/logout and bidirectional sync composition. It accepts an injected
  lazy `AppSyncStoreFactory`, exact
  `ClientPaths`, explicit `SessionTarget` and an owned non-Clone master
  key; it MUST NOT expose `AppSession`, `SyncEngine`, bearer access, a mutable
  target/key map, or create/migrate/reset local state. Factory opening completes
  before authorization or network I/O and is raced against the operation's
  cancellation and deadline. A process-wide synchronous admission bound allows
  at most one facade pull before factory opening. After opening, the permit is
  owned by a private local-store wrapper and survives caller Drop through every
  detached catalog/page mutation and its post-commit check. COSMIC and FFI
  consume this facade; Tauri remains a migration target. Its store
  factory is a trusted composition-root SPI because it receives the operation
  key, and pull futures require a Tokio runtime with the time driver enabled.
  Session and sync DTO/adapter ports remain public, but their orchestration
  owner types and entry methods are crate-private.
- `zann-client-sqlite` MAY depend on the clean `zann-client::app` SPI plus the
  narrow `ConfigRepository` generation-lease and binding surface,
  `zann-db` with SQLite, `zann-core`, `zann-crypto` and bounded runtime/value
  support such as `uuid`, `chrono` and `tokio`. It MUST NOT depend on
  `reqwest`, `dirs`, `keyring`, a UI crate or direct
  SQLx. Its production constructor binds one absolute `ClientPaths` root to an
  absolute, normalized, private, already-existing regular SQLite file; missing
  files are never created and injected pools remain test-only. The opener
  rejects symlink/non-regular sidecars and Unix hard links, caps the eager pool
  at one connection, and pins both filesystem identity and a migrated logical
  database UUID. SQLx cannot atomically no-follow-open a previously identified
  inode, so a malicious same-UID exact-clone swap remains outside this boundary
  and requires a private state directory. Its `AppSyncStoreFactory` owns one
  pre-resolved existing location and performs no config or network access.
  Initial personal-vault keys are generated by the adapter and published with
  a server-side initialize-once CAS. Explicit projection reset remains a
  separate unavailable recovery workflow.
- `zann-flows` MAY depend on pure domain/application data contracts. It MUST
  NOT depend on transport, persistence, an async runtime or a UI toolkit.
- `zann-ui-core` MAY depend on domain data and canonical schema assets. It
  MUST NOT depend on `zann-client`, persistence, transport or a UI toolkit.

### Domain, protocol and infrastructure

- `zann-core` MUST NOT depend on application, UI, transport, FFI or concrete
  infrastructure crates.
- `zann-protocol` MUST remain a lightweight serialization contract. It MUST
  NOT depend on reqwest, tokio, database crates, crypto implementations or
  client frameworks.
- Infrastructure crates MUST NOT select UI state, translate messages or own
  application workflows.

The dependency guard checks direct manifest entries, declared default-feature
behaviour and selected dependency features. CI then builds each resolved
consumer graph. Moving a forbidden dependency behind a feature does not satisfy
the boundary unless that feature is unavailable to the affected surface.

## Single-owner enforcement

The following markers in a shell are architectural signals and require either
removal or an exact migration exception:

- HTTP endpoint literals, bearer header construction and wire response parsing;
- direct `reqwest`, `argon2`, `keyring`, SQL or database dependencies;
- reading or writing the shared config filename outside `ConfigRepository`;
- KDF parameters, ciphertext envelope or checksum algorithms;
- sync cursor, version, conflict and deletion decisions;
- category membership, secret-field masking and field-order tables;
- branching on free-form error/status strings from a shared service.

Source guards are supporting checks, not the ownership definition. Renaming a
symbol or hiding code behind a helper does not make a second implementation
valid.

## Persisted-state rules

Shared client state MUST satisfy all of the following:

- a top-level schema version with deterministic migrations;
- one `ConfigRepository` writer using an atomic replace;
- a cross-process lock covering read/modify/write;
- mutation/patch APIs that reread the latest revision under the lock; a public
  whole-document `save` API is forbidden;
- preservation of namespaces owned by another client;
- explicit separation of shared connection metadata and client-private UI
  preferences;
- tokens and other credential material stored through `CredentialStore`, not
  in shared JSON;
- all paths resolved once at the composition root and passed as `ClientPaths`.

Config v2 uses `client-config.json`, a permanent sibling
`client-config.lock`, a single predecessor backup and a normally absent durable
restore journal. Legacy `config.json` remains a read-only migration source
until every old writer is retired. The v2 migration stores and verifies
deterministic repository- and source-bound credential references before its
atomic publish, records a digest of the legacy config and known-host files, and
fails explicitly if an older client later changes those files. The repository
binding uses the canonical config root so two concurrently used copies cannot
address the same global OS credential. Relocating a migrated root therefore
requires an explicit repository migration; clients MUST NOT silently
reinterpret its credential references at a new path. A future schema version
is not treated as corruption and MUST NOT be replaced from an older backup.

If the primary is absent while the predecessor backup exists, initialization
MUST stop for explicit recovery; it MUST NOT create defaults or remigrate
legacy state. A recovered revision must be newer than the potentially lost
primary generation. Credential references produced by migration are bound to
the source digest so a rejected attempt can leave only an unreachable orphan,
not poison a retry. Every client claims its own legacy projection atomically.
Canonical writers accept only registered, versioned namespace schemas; raw
JSON namespace/extension writers are forbidden. Unknown non-security legacy
extensions stay in the digest-pinned source and only their paths may be
recorded in canonical state. Unknown KDF and credential-profile fields MUST
fail migration rather than be ignored. Credential references are published
only by a repository transaction that stores and verifies the secret first. A
two-valid-generation restore MUST be recoverable idempotently from its durable
journal after every crash point.

These locking and atomicity guarantees cover cooperative writers on local
filesystems. The root MUST be private and static symlink/non-regular targets
MUST be rejected. Isolation from a hostile process with the same OS identity is
out of scope unless all filesystem operations move behind a platform-specific
capability-directory boundary.

Config mutation, credential lifecycle and authentication operations share one
file-lock implementation and three fixed, permanent targets:
`client-config.lock`, `client-config.credential.lock` and `client-auth.lock`.
Lock files MUST remain empty; callers cannot select an alternate filename.
Acquisition verifies that the current path and opened handle identify the same
regular file, rejects Windows reparse points and Unix hard-link aliases, and
uses private Unix root/file modes. The global nesting order is authentication
operation -> credential operation -> config. Code holding the config lock MUST
NOT call the network or a credential backend; code already holding a credential
or config lock MUST NOT acquire the authentication lock.

Every JSON source MUST be byte- and structure-bounded and reject duplicate
keys before typed decoding. Semantic migration limits MUST be checked and the
complete canonical candidate MUST serialize within its bound before any
credential backend call. KDF parameters MUST satisfy the shared
`zann-crypto` resource policy both when persisted state is accepted and when
the computation is executed.

The concrete OS adapter is the opt-in `zann-client` `os-credentials` surface;
the plain `remote`, `config` and `session` surfaces MUST remain free of
`zann-keystore` and platform keyring dependencies. It MUST select only
`zann-keystore/secret-store` with default features disabled; remembered-unlock,
FIDO and raw-HID dependencies are forbidden from that closure. Canonical
credentials use the logical service `zann` and account
`credential:v2:<CredentialId>`. `zann-keystore` maps that tuple into a
versioned, injective physical namespace which is disjoint from every legacy
`zann` / `dwk` entry. On Windows the physical TargetName is canonical
lowercase-hex with explicit UTF-8 byte lengths and is selected through
`Entry::new_with_target`, so Credential Manager's case-insensitive lookup
cannot alias two logical tuples. Linux and macOS use separate versioned,
injectively encoded service and account components, so backend-specific
matching rules cannot collapse two logical tuples there either.

Legacy CLI migration uses a separate read-only compatibility port; generic
`SecretStore` cannot select, rewrite or delete a legacy entry. That port reads,
but never rewrites or normalizes, service `zann-cli` accounts named
`access::<context>::<profile>` and `service::<context>::<profile>`.
Because that historical delimiter is non-injective, an external lookup MUST
fail closed when either component itself contains `::`; an inline legacy value
may still be migrated without consulting that ambiguous account. On Windows,
potential external accounts MUST be ASCII, all case-fold-equivalent logical
accounts MUST be rejected before the first OS read, and the compatibility
reader MUST verify the exact stored TargetName and account metadata before
returning a value. An inline value does not consult the case-insensitive legacy
reader.
Backend namespace and value limits MUST be preflighted for the complete bundle
before its first write.

Credential replacement uses the secret-free
`client-config.credential-intent.json`. The durable intent is written before
the first secret mutation and records bounded source/candidate generation
digests, revisions, exact credential topologies and proven credential-ID
ownership; it never contains full config generations, credential values or
credential hashes. Digests identify repository state under the documented
cooperative-writer boundary; they are not an authenticity claim. Recovery MUST
preserve every ID referenced by the primary, backup or restore target, and may
delete only IDs whose provenance is proven by the intent. No config lock may be
held while an OS credential port can block or prompt. An in-flight credential
intent blocks unrelated mutations and restore; a committed, bounded cleanup
intent may survive metadata rotations until its candidates are durably
unreferenced and deleted. If that bounded cleanup queue cannot make progress,
new credential writes fail before touching the credential backend.

A network refresh resolves a short-lived, repository-bound
`CredentialProfileAnchor` for an explicit connection/profile pair before it
reads the old refresh credential. The anchor contains no secret and binds the
canonical endpoint trust/storage tuple plus the exact profile credential ids
and expiry state. Commit compares those fields against the latest config under
the lock instead of using the global revision as a profile lock, so unrelated
client namespaces, metadata names, other profiles and active-profile selection
may advance while the network request is in flight. `Preserve` retains the
latest active selection; it does not restore the selection observed before the
request. A same-revision byte rewrite is still an ABA/content conflict, and an
anchor from another canonical root is never reusable.

`AppSession` MUST hold the root-scoped authentication operation lock and then
the credential operation lock from reconcile and anchor resolution through
trust verification, the remote operation and its terminal commit or revoke.
The config lock remains an inner, short-lived repository detail and MUST NOT be
held over a credential-store or network call. Endpoint trust is verified
against the anchor before reading or transmitting a refresh secret. Protocol
v1 fingerprints are unsigned TOFU metadata observed through the configured
transport; they MUST NOT be described or consumed as part of the signed server
identity proof.

Refresh dispatch is exactly once. Any result after possible dispatch that
cannot prove acceptance or rejection—including transport loss, timeout, 5xx,
oversized/truncated content or an invalid success document—is ambiguous and
MUST NOT be retried automatically. The anchored profile is revoked before the
operation completes so restart cannot replay the old refresh credential. On a
valid response, the anchored transaction rotates only access and refresh
credentials; service-account credential ids and values in a mixed profile MUST
be preserved.

Authentication and credential locks serialize live cooperative processes; they
do not make an in-flight remote dispatch durable across process death. Future
drop handling is necessary but is not sufficient for `SIGKILL`. The shared
owner now writes bounded, secret-free `client-auth.intent.json` before an
exactly-once auth request can be dispatched. Version 1 covers refresh/logout;
version 2 adds DB-free password login on an existing pinned connection. Both
are limited to 64 KiB and 256 JSON nodes, reject duplicate keys, unknown fields
and future versions, and bind operation id, endpoint, exact source topology and
config digest to the canonical repository root. They contain no credential
value or secret-derived hash.

The durable state is `armed` or `candidate_prepared`. Startup MUST validate the
intent before any credential-store operation, reconcile the normal credential
journal, reread the unchanged auth intent and then classify the primary. An
exact source is revoked through the credential journal, an exact committed
candidate is preserved, and an absent target is accepted as revoked. Any other
state remains `RecoveryRequired`; it does not retry auth or claim local revoke.
Only terminal commit/revoke proof may clear the intent and fsync its parent.

Password-login v2 reserves and absence-preflights a fresh access/refresh pair
before arming. Restart abandons an exact source or originally absent profile
without deleting reserved/source ids, preserves an exact committed candidate,
accepts an absent target, and retains every conflict. After a successful POST,
canonical bounded `/me` must prove `Internal`/`Password` and supplies the stable
UUID account subject. A second prelogin on `/me.email` must exactly match the
pre-dispatch salt, KDF parameters and recomputed fingerprint before candidate
preparation; the canonical email is published only with that proof.
This closes observable account-creation/password-rotation races but is not a
cryptographic server binding: a future protocol version SHOULD include KDF
identity in an authenticated login or `/me` response. Likewise, because the
secret-free intent cannot retain a returned refresh token, `SIGKILL` after a
valid login response but before candidate publication can leave a remote
session until server TTL. Durable compensation requires either a protected
`must_revoke` secret slot or a server operation/idempotency handle and is
accepted P2 hardening; live compensation failure is reported as
`SessionLostRemoteUnknown`, never as an ordinary cancellation or protocol error.

Fresh ids for the rotated bundle are validated and checked for absence outside
the config lock. The repository then reloads the latest generation, repeats the
anchor comparison and rebuilds the candidate with those exact preflighted ids.
Under the same final config lock it first durably records the candidate marker
in the auth intent and then installs the normal credential intent; credential
store writes happen only afterward. A crash in the marker/journal gap sees the
exact source and revokes it. Auth intent alone never authorizes deletion of
candidate ids; only the credential journal proves ownership. Fresh ids MUST NOT
be recorded before absence preflight.

Destructive live auth transitions additionally require a non-`Clone` opaque
ownership token bound to the exact auth-intent byte digest. The broader
crate-private credential APIs still express caller-held operation locks by
their `_with_operation_lock` boundary rather than a typed lock guard. Converting
that naming-only capability into one guard type is accepted P2 hardening; it
does not permit shell access and does not weaken the auth-intent ownership token
or source/candidate recovery checks.

Connections that hold credentials MUST NOT be retargeted through a generic
metadata mutation. Canonically equivalent endpoint URLs share one trust
identity; a pinned endpoint cannot coexist with an unpinned or differently
pinned alias. Rebinding is a separate credential-aware transaction.

An authenticated-session bind is one credential-aware repository candidate,
not a sequence of shell writes. It atomically publishes the validated identity,
connection and trust metadata, optional local `storage_id`, credential bundle,
active profile and the calling client's active connection. Remote-only clients
publish no storage binding. A local session MUST create or idempotently reuse
its storage before supplying `Some(storage_id)`; `None` preserves any existing
binding and cannot clear it. `Some` may fill a missing binding or exact-match
the existing value, but cannot replace it or reuse another connection's value.
A fingerprint replacement requires an explicit compare-and-replace trust
decision. A crash may leave an unreferenced local storage, but canonical config
must never reference a missing one. SQLite storage metadata is a recoverable
projection of Config v2 and is reconciled after publication.

Profile removal, logout and refresh rejection use the same credential journal:
they first remove durable references and active selections, then delete proven
unreferenced OS credentials. A generic metadata mutation or empty credential
replacement MUST NOT stand in for revocation.

Legacy keyring values are not versioned by old clients and therefore cannot be
covered by the file digest. No consumer may activate v2 until its credential
write and refresh paths move in the same vertical slice.

The shared `session` surface is active for COSMIC and FFI; CLI and Tauri MUST
still migrate as vertical slices rather than combine it with an old config or
keyring writer. Crash-recovery auth intents, password registration/login, OIDC
PKCE login, refresh/logout and cancellation are recovery-tested. Service-token
composition remains a separate future activation. Dual-writing v1 config is forbidden:
after the first v2 token rotation rollback is forward-fix only unless a separate
secret-safe reverse migration is designed.

Recovery evidence covers strict parser/root bounds, malformed/future/cross-root
intent before credential cleanup, source-only and candidate-marker crash cuts,
exact committed-candidate preservation, already-removed target acceptance,
restore blocking while stale credential backups remain, and real Tokio runtime
drop after dispatch with no second refresh/login. Password evidence additionally
covers present/absent sources, ABA/rebase, KDF coherence, canonical account/auth
binding, cancellation before candidate publication, compensation failure,
single-shot transport classification and secret redaction.

A migration MUST include fixtures for every supported input version, an
idempotence test, a cross-client round-trip test and recovery behaviour for an
interrupted write.

## Async-effect rules

Any user-replaceable operation (probe, login, OIDC, unlock, detail load, sync)
MUST have:

- a stable operation ID carried by request and completion events;
- cancellation propagated to the underlying listener/request where possible;
- a timeout represented as a typed outcome;
- reducer logic that ignores late completions for inactive operation IDs;
- tests for cancel-then-retry and A-then-B/out-of-order completion.

Dropping a UI receiver without cancelling its producer does not count as
cancellation.

## Architecture exceptions

### Policy

Architecture checks fail closed. A new exception is allowed only when all of the
following are present:

- the smallest exact path, dependency or feature scope;
- a named responsible owner;
- a linked tracking issue and an explicit expiry date;
- the reason the canonical extension point cannot yet be used;
- risk and compensating tests;
- a measurable removal condition.

An exception MUST NOT authorize plaintext credential persistence, a new crypto
implementation, loss of unknown config namespaces, or omission of compatibility
tests. Those require redesign and security review, not an allowlist entry.

Exceptions expire automatically and MUST NOT be broadened to accommodate new
uses. When the removal condition is met, the exception is removed in the same
PR. Permanent changes to ownership require this map and an ADR to be updated
instead.

### Migration exception ledger

These entries record debt that existed when ADR 0001 was accepted. They freeze
the current scope; they do not permit additional call sites or dependencies.

| ID | Owner | Frozen legacy scope | Risk | Compensating control | Removal condition |
|---|---|---|---|---|---|
| MIG-001 | `@constXife` | `apps/desktop/src-tauri/src/infra/{auth,http,identity,remote}.rs`, `services/{auth,auth_oidc,auth_password,sync,sync_helpers}.rs` and their current command/state glue | remote/auth/sync drift | characterization plus DB-backed parity tests before each slice moves | Tauri uses `zann-client` remote/auth/sync and the fork is deleted (ADR phase 4) |
| MIG-002 | `@constXife` | `crates/zann-cli/src/modules/auth/{http,types}.rs`, `system/{config,http,types}.rs`, `shared/{fetch,http,types}.rs` and current `reqwest`/`keyring` manifest entries | protocol fields, pagination and config drift | wire fixtures and CLI integration tests | CLI uses remote-only `zann-client`, `CredentialStore` and config v2 (ADR phases 2–3) |
| MIG-003 | `@constXife` | COSMIC and FFI direct database/crypto/keystore dependencies plus Tauri's current database integration | split roots and application-policy drift | explicit-root tests and canonical facade conformance | remaining shell-local application policy and direct infrastructure edges are removed (ADR phase 5) |
| MIG-004 | `@constXife` | `crates/zann-ffi/src/lib.rs`, `apps/desktop/src-tauri/src/crypto.rs` and `services/session.rs` | incompatible or unaudited crypto behaviour | golden compatibility fixtures before replacement | every call routes through `zann-crypto` and copies are deleted (ADR phase 2) |
| MIG-005 | `@constXife` | legacy config types/writers in `crates/zann-cli/src/modules/system/{config,types}.rs` and `apps/desktop/src-tauri/src/{infra/config,state}.rs` | cross-client data loss and plaintext tokens | backup/round-trip fixtures during migration; no new fields in legacy shape | config v2, locking, atomic replace, namespaces and credential separation are used by all clients (ADR phase 2) |
| MIG-006 | `@constXife` | `apps/cosmic/src/screens/{connect,detail,vault}.rs`, `apps/desktop/src/composables/app/actions/{useAppAuthFlow,useAppWatchers}.ts`, `apps/desktop/src/composables/app/state/useAppItemFilters.ts`, `apps/desktop/src/composables/{useItemDetails,useFolders}.ts` and `apps/desktop/src/utils/itemCategories.ts` | divergent UI behaviour and stale async results | existing flow/UI tests plus new operation-ID tests | clients consume `zann-flows` and `zann-ui-core`; duplicate policy is deleted (ADR phase 6) |
| MIG-007 | `@constXife` | SQLx dependencies/features in `crates/zann-core/Cargo.toml` and row mapping in `crates/zann-core/src/models/{from_row,structs}.rs` | domain types remain coupled to concrete persistence | dependency guard freezes the current edges; DB integration tests protect mappings | SQLx row mapping and features move to `zann-db` (ADR phase 5) |

Because these entries predate the exception policy, `@constXife` is their
responsible owner and the stated ADR removal phase temporarily replaces the
calendar removal expiry. The accepted ADR serves as their tracking reference.
Every grandfathered entry still has a fail-closed `review_on` date; review may
narrow or remove its scope, but cannot silently extend it. Each entry MUST gain
an issue and calendar expiry when work on its phase starts. Any scope increase
requires a normal, issue-linked, time-bounded exception immediately.

## Definition of Done

A new or changed shared capability is done only when:

### Ownership and API

- its canonical owner and consumers match this map;
- business rules are represented by typed inputs, outputs and error kinds;
- platform variation is behind a documented port or declarative data contract;
- no consumer reconstructs policy from strings, JSON shapes or database rows.

### State and security

- secrets cross a boundary only when explicitly requested and are never logged;
- persisted/wire formats are versioned and have backward-compatibility tests;
- config writes are atomic, locked and preserve other namespaces;
- crypto changes use the `zann-crypto` API and pass golden/property tests;
- cancellation, timeout and stale-response behaviour is defined for async work.

### Consumers and tests

- owner unit/contract tests cover success and failure paths;
- every thin, non-default client feature compiles and tests in isolation, and
  its resolved normal-dependency closure is checked against its contract;
- each affected CLI, Tauri and COSMIC adapter builds and passes conformance
  tests;
- DB-backed tests cover final sync/auth state when persistence semantics change;
- fixtures cover migrations and serialization when a durable contract changes.

### Cleanup and enforcement

- every affected consumer uses the canonical implementation;
- replaced code, dependencies and compatibility shims are deleted;
- the dependency/source guard is updated to enforce the resulting boundary;
- no exception is added merely to make CI green;
- the associated migration exception is removed or narrowed;
- architecture docs and migration/release notes are updated when the public
  contract or owner changes.

A migration that adds the shared implementation but leaves independently
callable legacy policy is not complete.
