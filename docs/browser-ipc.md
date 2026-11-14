# Local browser session and native messaging (#199)

The service implements phases 2–3 of [ADR 0007](adr/0007-browser-integration.md).
The Chromium UI is implemented by [#25](chromium-extension.md); Firefox packaging remains separate.

## Composition and custody

`Daemon::start(ClientPaths, Arc<dyn LocalVaultService>)` accepts an existing
session. COSMIC `Session` and the macOS production composition embed the service over
their one local vault. FFI `create_core` opens storage only; the production
composition explicitly calls `start_browser_service()` on that same facade.
Native unlock/lock/selection and browser requests
observe the same key and context. Activation is idempotent; management before
activation reports typed `NotRunning`. An overlong socket path reports typed
`PathTooLong` without making storage unusable. The independent `zann-daemon` binary is an
explicit alternative composition for a terminal; it does not run alongside
an embedded owner for the same root. A second owner fails rather than opening
a replacement socket or silently selecting another session.

The returned `DaemonControl` is an in-process, non-serializable capability.
Only it can list/revoke pairings and generate a one-time pairing code. COSMIC Security settings and
macOS Browser connections settings project it. The terminal composition offers
the same controls through stdin. Unlock and vault/storage selection remain
native operations and are absent from the socket API. Password prompts disable
terminal echo; password values never enter argv.

## Files and operating-system peer identity

The resolved client root must already be absolute, owned and private.
`ipc/` is `0700`; `ipc/browser.sock`, `owner.lock` and `identity.json` are `0600`.
Regular files reject symlinks, hardlinks and another owner. An exclusive
process lock covers listener and identity/pairing writes. Only a proven stale
owned socket is removed; shutdown removes only the inode the service bound.
Unix socket path-length limits are enforced by the OS; no alternate directory
is selected for an overlong client root.

The kernel peer UID must match the effective UID before any hello is sent:
Linux uses `SO_PEERCRED`, Darwin uses `getpeereid`/`LOCAL_PEERCRED` identity.
This check alone grants no vault access.

One strict, bounded v1 `identity.json` snapshot holds independent signing and
Noise identity seeds plus approved public keys/names. It is not a vault-key
file. Updates use a private temporary file, file fsync, atomic rename and
directory fsync. A malformed/future/unsafe snapshot never becomes an empty
pairing list. Approval publishes memory only after durable installation.
Revocation removes live authority first; if persistence fails, the service
closes authorization and reports failure. A successful revoke survives restart.

## Wire and authentication

Every packet is UTF-8 JSON with a native-endian unsigned 32-bit byte length.
Both directions reject empty frames and frames above 1 MiB before allocation.
Partial headers/bodies are errors; EOF before a header is a normal disconnect.
Framing is owned by `zann-client::native_messaging`. Shared wire DTOs, transcripts
and the single-flight browser client are owned by `zann-client::browser_ipc`,
consumed by both the daemon and the WASM edge.

1. The daemon sends `Hello`: version, Ed25519 server key, fresh 32-byte nonce,
   X25519 transport public key, and an Ed25519 signature binding those values.
   The client verifies its pinned server key. First pairing uses a provisional self-verified key only within the
   dedicated code-exchange client; PAKE must authenticate it before pin publication.
2. Establish `Noise_NK_25519_ChaChaPoly_BLAKE2s` through `snow`, pinned to the
   signed transport key. The exact hello bytes are the Noise prologue. No
   application data is sent until the two-message handshake finishes.
3. Each signed application envelope then travels inside Noise. A client
   envelope contains its public key, an exact increasing sequence number,
   hexadecimal UTF-8 JSON body and signature. The signed transcript is
   `zann-local-ipc-v1\0 || direction:u8 || server_key:32 || nonce:32 ||
   sequence:u64be || body_length:u64be || body`. Direction is 0 for hello,
   1 for requests and 2 for replies. Hello's transcript body is its transport
   public key. Replies bind the same nonce/sequence and are signed too.

Noise packets contain hexadecimal encrypted chunks. The crypto owner prefixes
the whole plaintext length inside encryption, chunks at 32 KiB, and validates
the authenticated assembled length. Dropping/reordering/replaying chunks or
altering ciphertext fails closed. The framing bridge sees ciphertext, not
passwords, client names, origins or query results. There is no unencrypted
application mode or automatic handshake downgrade.

Ed25519 primitives and the optional Noise feature belong only to `zann-crypto`.
The Noise resolver selects pure Rust X25519, ChaChaPoly, BLAKE2s and OS entropy;
it does not select ring, OpenSSL, AES or desktop-only C dependencies. The vault
v1 envelope/KDF/AAD and golden fixtures do not change.

## Pairing and browser operations

Native **Connect browser** opens one 120-second window with a uniformly random
six-digit code and five attempts shared across every connection. Only the native
control handle can issue/replace it. Codes are displayed only in native UI,
never logged, persisted or sent through IPC. The signing seed and authenticated
server pin remain the only durable browser identity fields. A separate
profile-local MRU stores only bounded opaque successful-fill identifiers.

`pair_start { name, message }` proves possession of the browser signing key and
runs RustCrypto `spake2` 0.4 (Ed25519 group), with browser/client and daemon/server
roles. Its identity binding includes the protocol domain, both signing public
keys, fresh connection nonce, final Noise handshake hash and length-delimited
browser name. Even malformed/repeated starts consume a guess. There is no code
verifier on the wire and no application access before enrollment. The server
returns its SPAKE2 message plus a directional key-confirmation MAC. Both sides
use the PAKE output through BLAKE3's derive-key mode and distinct client/server
keyed-hash confirmation labels, all owned by `zann-crypto`.

`pair_finish { confirmation }` consumes connection-local confirmation state
before verification. It rechecks expiry and native window generation, verifies
the client MAC, consumes the entire code window and atomically persists the
exact signed browser key/name before returning `paired`. Replacement, expiry,
restart or another successful enrollment invalidates incomplete attempts. No
fallback/manual approval command exists. The dedicated bootstrap client cannot
query/fill/save and exposes a server pin only after native enrollment succeeds.
A lost final response leaves the outcome unknown: issue a new native code and
repeat pairing with the retained browser identity; existing enrollment converges
without duplicate keys or a special recovery command.

`pair_status` only checks durable authorization on an already pinned connection.
Approved keys survive reconnect/update/restart; losing the client private key
requires a new pairing. Native Settings lists exact keys/names for revocation.
Revocation also applies to existing connections, cancels any active code window
(including in-flight confirmations), and survives restart. Browser
profile compromise remains compromise of that pairing; a changed daemon key is
never silently substituted. Forgetting a browser connection explicitly removes
its identity/pin; the old key can be revoked in native Settings.

The only approved-client methods are:

- `query { context, cursor }`: up to 32 candidate logins per indexed SQLite
  page; only matching item IDs, native match-quality labels, titles and public
  text-kind usernames (up to
  256 bytes) leave
  the service, alongside the selected native scope/generation required to confirm
  a save destination. Missing websites are ineligible; malformed rules/URLs fail
  closed. No vault scan or per-result database round trip occurs in one call.
- `fill { context, item_id, gesture, include_totp }`: one explicit signed
  user action releases that login's typed password and optionally its current
  TOTP code. No arbitrary field name, master key, TOTP seed, history, attachment,
  passkey private key, raw payload or SQLite handle is a wire operation.
- `save { context, scope, login, gesture }`: after explicit masked review, create
  one typed login (title/username/password) in the exact query-observed native
  selection. Secure same-origin context is required; only its canonical origin
  is saved. Duplicate paths refuse rather than overwrite. The canonical native
  create owner commits item/history/pending together. There is no automatic
  replay after ambiguous save dispatch.

The context contains the browser-observed top and frame URLs. Matching and fill
admission use `zann-autofill`; cross-origin frames are refused and fill requires
HTTPS. A signed gesture flag is an assertion by the paired extension, not an
OS attestation. The Chromium adapter derives URLs from privileged browser APIs and dispatches
fill only from the trusted browser surface's user action, never a page claim.
Compromise of an approved extension/key is compromise of that pairing.

Pagination tokens are random, single-use, expire after 30 seconds and bind
client key, connection nonce, exact browser context and native selection
generation. Unmatched item IDs are not exposed as cursors. Lock/unlock or
selection changes refuse a stale continuation. Restart/reconnect starts a new
query. The store is bounded to 128 tokens overall and four per connection.
The Chromium popup consumes continuations automatically through the shared
`LoginSearch` flow, serially on this connection. Its aggregate is published only
when the terminal page arrives; selection changes, navigation, transport errors,
repeated cursors and its 30-second/resource bounds discard the partial search.
Native page/cardinality limits and explicit fill/save gestures remain unchanged.

Approval/revocation is serialized with complete response delivery. The native
context read lease likewise covers the bounded response callback: lock or
selection cannot complete while a secret from the preceding context is still
being written. Once those operations complete, no later release retains an
old authorization snapshot. Each DB await has a two-second deadline; every
whole frame read/write has a five-second deadline, including partial I/O.
Idle connections expire too; the Chromium adapter reconnects on a new explicit
action before dispatch, redoing the encrypted handshake without replaying an
ambiguous fill or save. There are at most 16
connections, one code window, at most one exchange per connection, and 64 approved pairings.

## Install and run

Build the stateless bridge and optional terminal composition:

```sh
cargo build -p zann-native-host -p zann-daemon --features zann-daemon/standalone
target/debug/zann-daemon --database /absolute/client/root/local.sqlite
```

Use an already server-initialized replica. The terminal starts locked; `unlock`
prompts locally. `settings`, `pair` (displays a fresh code locally), `revoke PUBLIC_KEY`,
`storage ID`, `vault ID`, `lock` and `quit` are native commands. COSMIC/macOS
already host this service while open; use that app's Settings instead of
starting a second owner on its root.

Install a manifest into an explicit browser directory with the actual extension
ID; nothing is written to a discovered HOME directory automatically:

```sh
target/debug/zann-native-host install /absolute/client/root /absolute/browser/NativeMessagingHosts chromium abcdefghijklmnopabcdefghijklmnop
target/debug/zann-native-host install /absolute/client/root /absolute/firefox/native-messaging-hosts firefox zann@example.test
```

The installer emits a private launcher bound to that root and a `0600` manifest
named `com.rlyeh.zann.json`. Chromium gets one `allowed_origins` entry; Firefox
gets one `allowed_extensions` entry. Wildcards and empty IDs are rejected.
Repeating the same installation is idempotent; differing existing files are
preserved and reported. Refer to the official
[Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
and [Firefox](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_manifests)
documentation for the directory appropriate to the browser/OS.

The remaining trust limit is local custody: same-UID code that can replace
the daemon's identity store or steal an approved browser's private key is not
made harmless by a socket permission or pairing. Root and a compromised native
owner are outside this boundary. Noise protects the transport from a relaying
process without endpoint keys; pairing prevents an arbitrary unpaired socket
caller from asking the legitimate owner for data.

## Verification

```sh
cargo test -p zann-daemon -p zann-native-host -p zann-crypto --all-features
cargo test -p zann-client --no-default-features --features native-messaging --test native_messaging
cargo test -p zann-client-sqlite --features local-vault
cargo test -p zann-ffi -p zann-ui-core
./scripts/check-client-architecture.sh
./scripts/check-audit-surface-deps.sh
```

Tests cover real Unix peers, unpaired/locked/refused release, signatures and
replay across connections, restart/revocation durability, scoped pagination,
lock/delivery ordering, Noise secrecy/tampering/truncation, filesystem attacks,
native message bounds, manifest scope and idempotent installation.

The SPAKE2 dependency is optional (`zann-crypto/ipc-pairing`), pure Rust, and
absent from the default crypto feature closure; it adds no desktop-only
dependencies. The [upstream crate](https://docs.rs/spake2/0.4.0/spake2/) explicitly
reports no independent third-party audit; this implementation does not claim an
audited pairing protocol. Short-code authentication has a bounded online-guess
risk (at most five guesses per issued code); native code display and browser
profile custody remain trusted endpoints. Rust-owned code/confirmation buffers
are zeroized, while shell/upstream-library memory copies have no forensic-erasure
guarantee. See [ADR 0007](adr/0007-browser-integration.md) for tradeoffs.
