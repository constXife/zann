---
title: Passkey account-key grants
description: PRF wrapping, account custody proofs and explicit passkey modes.
---

# Passkey account-key grants v1

Normative companion to [ADR 0018](../adr/0018-passkey-account-access.md) and
[server recovery](passkey-recovery.md). This is a new typed grant contract;
it does not version or rewrite existing item/vault/device envelopes.

## Canonical encoding and crypto owner

`T(label, f1, ..., fn)` is ASCII `label`, one zero byte, then each field as
`u32be(byte_length) || bytes` in the exact declared order. Fixed labels below
are literal and immutable. UUIDs use 16 raw RFC-order bytes, integers use eight
big-endian bytes, booleans one byte (`0`/`1`); byte fields are raw, not hex/base64.
Text is UTF-8: canonical `RpId` ASCII comes from the existing RP owner, subject is
the server user UUID, never email. Optional values have a one-byte presence field
followed by their value only when present. Wire binary fields use base64url
without padding. Reject duplicate/unknown JSON members, wrong lengths/algorithms,
noncanonical encodings and over-budget data before cryptographic work.

SHA-256, BLAKE3 derivation, ChaCha20-Poly1305 verified wrapping and Ed25519 are
owned by `zann-crypto`. Extract a purpose-neutral Ed25519 primitive from the
existing IPC implementation, keeping distinct typed keys/namespaces: an account
key is never an IPC identity. Use strict verification and pure Ed25519 over the
transcript, not Ed25519ph or a home-grown signature algorithm; see
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html). Key material and temporary
transcripts containing it are zeroizing and have no secret-bearing Debug output.

[BLAKE3 derive_key](https://docs.rs/blake3/latest/blake3/fn.derive_key.html) is used
only on existing cryptographic key material, never directly on a password. The
Account Encryption Password still uses canonical NFC/Argon2id and authenticated
KDF identity; the server receives neither password nor its account-derived key.

## Account-key descriptor and custody proof

The descriptor is `{format=1, server_id, user_id, key_epoch, proof_public_key}`.
`key_epoch` starts at 1; its change is ADR 0013 rotation, never a failed-unwrap
repair. The client derives a 32-byte Ed25519 seed with:

```
BLAKE3-DERIVE-KEY("zann account custody seed v1",
  T("zann account custody material v1",
    account_key, server_id, user_id, key_epoch))
```

Only the derived public key is stored by the server. The client compares it
against the descriptor after proving the account key against the published
personal vault keys; a mismatch is explicit corruption/epoch/trust failure.
It never binds whichever public key the server returns to a local key blindly.
This public key is an additional offline password-check oracle for password-derived
accounts; the existing wrapped personal vault key already provides one. It does
not remove the password-strength requirement or add server decryption authority.

For a new personal account, initialize descriptor and the first personal-vault
key envelope atomically under the existing initialize-once account CAS. The
trusted client proves its text-root setup and candidate wrap before dispatch.
For an existing account without a descriptor, bootstrap requires both local
personal-vault decryption and **fresh interactive server authentication bound to
the proposed descriptor digest**. A refresh/bearer session alone is insufficient:
use a dedicated one-use server-password reauthentication or verified UV WebAuthn
assertion whose stored challenge binds the digest. OIDC uses a fresh nonce-bound
system auth session, not a reused bearer JWT. Bootstrap is a single compare-and-set;
concurrent losers read/prove the winner, never overwrite it.

The server cannot independently prove that a newly proposed public key derives
from an opaque pre-existing vault key. Fresh factor authorization plus native
vault proof is the explicit bootstrap trust boundary. A holder of only a stolen
bearer token cannot claim it. A stolen interactive factor or malicious server can
still deny service; no zero-knowledge proof of legacy ciphertext decryption is
claimed. Complete descriptor bootstrap **before** offering full grants or removing
the last server password. Recovery with an established descriptor cannot replace
it: the code restores server authority, not E2EE custody.

Shared-only accounts have no personal descriptor/grant. Enabling personal vaults
must follow explicit enrollment policy; a random shared-cache key cannot act as
an account key. Do not change serialized `AccountKeyOrigin::AccountPassword` or
its device-envelope AAD merely because login used WebAuthn.

Custody-authorized mutation uses a 32-byte server nonce valid for 120 seconds and
bound to a verified ordinary session or recovery operation, account, purpose,
security revision and the digest of the exact typed mutation body. The signature is:

```
Ed25519(account_proof_seed,
  T("zann account mutation v1", server_id, user_id,
authority_kind, authority_id, security_revision, nonce, purpose, body_digest))
```

`authority_kind` is ASCII `session` or `recovery`; enum values use their exact
ASCII spelling. `body_digest = SHA256(T(endpoint_label, declared_public_body_fields...))`.
For grant add/replace the endpoint label is `zann account grant body v1` and
fields are `C...`, blob bytes and the grant signature in the order below. For
removal use `zann account grant remove v1` with credential ID and grant ID. For
code rotation use `zann recovery code activate v1` with candidate UUID,
`SHA256(T("zann recovery code commitment v1", candidate_code))` and the one-byte
server-password-disable flag. Only the outer mutation proof is excluded.
Credential operations use `zann account credential add v1` with credential ID,
registration-response digest, ASCII mode and tested-candidate receipt UUID;
`zann account credential revoke v1` with credential ID and explicit revoke-sessions
boolean; or `zann account credential mode v1` with credential ID, ASCII mode and
optional grant-body digest. Purpose is a closed enum (`grant_add`, `grant_replace`,
`grant_remove`, `code_rotate`, `credential_add`, `credential_revoke`,
`credential_mode`); no sign-arbitrary-bytes API. The server verifies
against the established descriptor and atomically consumes the nonce with the
mutation/receipt under account/revision locks. Server-only recovery consumption,
revocation and local admin reset are explicit exceptions that can remove grants
but cannot forge new ones or change the descriptor. Grant signing does not make
session theft harmless to every ordinary server-authorized endpoint.

The registration-response digest is SHA-256 of
`T("zann account registration response v1", credential_id, clientDataJSON_bytes,
attestationObject_bytes)`, using the exact public response persisted by both
ends. The tested-candidate receipt refers immutably to that response and its
verified test assertion. This binds the account signature without a second
client-side COSE canonicalizer or RP verifier; only the selected server verifier
interprets the public key.

## PRF input, wrapping key and authenticated grant

One discoverable login must not depend on an unknown user's salt or credential
ID. Derive this public 32-byte input before the ceremony:

```
I = SHA256(T("zann account prf input v1", server_id, rp_id))
```

Request `extensions.prf.eval.first = I` through the trusted native/browser adapter.
WebAuthn performs its own salt normalization. A raw CTAP adapter instead supplies
`SHA256(UTF8("WebAuthn PRF") || 0x00 || I)` to hmac-secret exactly once, under UV;
its UV-dependent secret behavior must match the browser/provider. This is the
[standard PRF mapping](https://www.w3.org/TR/webauthn-3/#prf-extension), not a
second custom hardware KDF. Only qualified adapters may advertise cross-path
interoperability. Credentials without PRF remain Auth-only.

After authentication identifies the account/credential, obtain the associated
grant. Its public context fields, in order, are `format` (u64 value 1),
`server_id`, `user_id`, `rp_id`, `credential_id`, `grant_id` (UUIDv4), `key_epoch`,
`proof_public_key`, `algorithm` (ASCII `chacha20poly1305`). Let `C` denote those
fields in precisely that order. Derive and wrap:

```
KEK = BLAKE3-DERIVE-KEY("zann account grant wrapping v1",
        T("zann account grant material v1", PRF_first_32_bytes, C...))
AAD = T("zann account grant aad v1", C...)
blob = encrypt_blob_verified(KEK, account_key_32_bytes, AAD)
signature = Ed25519(account_proof_seed,
              T("zann account grant signature v1", AAD, blob_bytes))
```

Use the existing verified blob encoder/random nonce; no new BLOB_VERSION branch.
A grant carries context, opaque blob and the 64-byte signature. The complete
record is at most 4 KiB; credential IDs at most 1,024 bytes. Fresh grant IDs
prevent confusing replacement with replay. Before persistence/publication, unwrap
and compare the exact original account key, verify signature and recompute its
proof public key; do not accept only a matching short cache fingerprint.

The server checks context/current epoch, registered credential/mode/UV, grant
signature and fresh mutation custody proof before admitting a full grant. It
cannot verify a PRF result or a client's trial-decrypt directly and never receives
them. The grant signature proves account-key custody, not independent PRF support;
trusted native code and real-provider tests enforce that usability property.

At login the client checks endpoint/pin, verified subject/credential, RP, epoch,
descriptor and grant signature, unwraps locally, recomputes the descriptor public
key and runs existing personal-vault proof before keyring enrollment/sync. The
server may deliver public grant context with the normal auth response; it never
receives raw client extension results. A stale/corrupt grant is not a rotation
signal or permission to overwrite the keyring.

A grant set is the current descriptor plus independently signed grant records,
with an account-scoped `security_revision` for CAS. It is **not** a globally signed
complete roster: the server can revoke/delete grants without knowing a personal
key, and a deletion cannot be undone by replaying a grant signature without a
fresh active credential, current revision and mutation challenge. This deliberately
allows server recovery to remove all grants. It does not promise detection of
all omissions or malicious-server rollback on a clean device; an existing local
key/epoch binding remains a stronger independent checkpoint.

### Public input-normalization vector

This vector contains only public inputs, not a real credential or secret. For
`server_id = 11111111-1111-4111-8111-111111111111` and `rp_id = zann.example`:

```
T hex:
7a616e6e206163636f756e742070726620696e7075742076310000000010111111111111411181111111111111110000000c7a616e6e2e6578616d706c65
I hex (WebAuthn eval.first):
33baf108a779edaf96534176bf8faea5545f688e8160d8703925da09df3759b0
raw CTAP hmac-secret salt hex:
0515e4cc99d789edd9e60619caac890514652fa2612fcc4441351d51a01ce301
```

Use this as an implementation tripwire for UUID order, field lengths and single
PRF normalization. It does not prove provider interoperability or PRF support.

## RP policy, enrollment and mode changes

Select `webauthn-rs`/its core verifier for RP validation, with server-owned
serialized challenge state and discoverable support. Use the library's registration
builder to require resident/discoverable keys, UV and `none` attestation; the
initial COSE algorithm allowlist is ES256 (-7) for both modes. Inspect
returned user handle and COSE algorithm, not only client options. Do not weaken
verification or implement signatures in shells to fit a library convenience API.
The [library's discoverable APIs](https://docs.rs/webauthn-rs/latest/webauthn_rs/struct.Webauthn.html)
use `conditional-ui`; Zann's explicit-button mediation remains explicit, and the
library feature name does not authorize silent assertions. Pin the compatible
crate/features in Cargo.lock during implementation. If public API adaptation is
needed, keep it in the server auth owner using the same core verifier.

Both modes require UV at registration and assertion. Auth-only means no PRF grant,
not presence-only server login; UP-only old-key MFA is outside #30. Offer full
mode only after an actual PRF assertion/round-trip proof. Missing PRF is an explicit
Auth-only choice with local password unlock; missing UV cannot select a weaker
mode. Registration can require a second ceremony when creation returned no PRF.
Login after enrollment targets one discoverable assertion with `eval.first`.

Never serialize `PublicKeyCredential.toJSON()` wholesale to the server, because
it can include PRF outputs. Public RP DTOs allow only raw credential ID, response
clientData/authenticatorData/signature or attestation, user handle and a bounded
allowlist of non-secret extension metadata. Keep output separate from zeroizing
PRF result types. Provider strings/claimed booleans are not authority for origin,
UV, usability or vault-key custody.

Full -> Auth-only atomically removes that credential's grant and changes its
mode under fresh local custody proof plus authorized server session. Auth-only ->
full requires a fresh UV assertion, PRF proof and newly signed verified wrap. A
missing/corrupt enrolled grant retains its source diagnostic and offers explicit
Account Encryption Password unlock; cancellation never silently changes mode.
Factor revoke is server-authorized and idempotent, removes its grant, and by
default revokes interactive sessions issued by that credential. Other credentials'
sessions survive. Store issuing credential ID on passkey sessions for this query;
recovery/admin reset invalidates **all** interactive sessions by epoch instead.

Normal factor add/revoke/mode changes require an authorized session plus either
fresh account-custody proof or a fresh UV assertion by an **already enrolled**
credential bound to that same mutation digest/revision. Candidate registration
and its test assertion are not that management authorization. Full-grant creation
always additionally requires account-key custody. A surviving unlocked personal
client can therefore manage factors without the lost key; a stolen refresh token
alone cannot add the attacker's new Auth-only credential. Shared-only accounts
use an existing enrolled UV factor or the explicit code/OIDC recovery authority;
refresh plus the attacker's candidate UV is insufficient.

## Trusted adapter admission

COSMIC starts bootstrap in native Connect with an operation ID, exact pinned
server/RP context and cancellable generation. The daemon admits a ceremony result
only for that live native operation over the existing paired Noise channel.
Pairing while locked uses native management/code confirmation; it cannot be
issued by a browser/page. No root-unlock or generic key-return capability is added.

A private packaged extension page invokes the real browser credential API, not
Zann's injected website provider shim. Check the runtime sender's exact packaged
extension origin and page path; no web-accessible resource, externally-connectable
web sender or embedded frame can dispatch account-bootstrap messages. The page
has `frame-ancestors 'none'`; use operation/channel binding and existing one-flight
admission, never a page-supplied gesture/origin boolean. Require the browser's
effective permission on the configured RP host and the server's exact extension
origin allowlist. No auto-grant or wildcard RP/origin expansion.

Native transport performs every RP HTTP request through existing trust policy;
the extension only executes the ceremony and returns strict public RP response
fields plus separately typed PRF bytes through Noise to the live native operation.
It never sends PRF to a website or ordinary RP JSON, persists it in extension
storage, or asks a page to relay it. Controlled JS buffers are overwritten after
copy into zeroizing WASM/native buffers; do not claim erasure of every browser GC
copy. Cancellation/lock/changed generation discards results without enrolling keys.
Browser/OS adapters expose typed error causes, not secret-bearing exception dumps.

Apple/Android use their installed OS ceremony adapters over the same client flow
and crypto transcripts. Associated-domain and cross-device PRF behavior must be
qualified per platform; a browser server page remains login-only on every platform.

## Recovery-code issuance and last-factor protection

Initial code issuance, rotation and server-password disable share one staged auth
mutation owner. Candidate code issuance alone does not invalidate the active code.
The client stores a candidate in CredentialStore and confirms independent storage
before the commit that replaces the verifier or disables the last server password.
Lost candidate issuance can be retried to obtain a new candidate while active
credentials remain valid; only the acknowledged candidate revision can activate.
Clients can also stage a locally generated replacement through the same generator
and service, avoiding a secret-bearing response to replay. No server encrypted
reply cache or second recovery-key authority is added.
The first release's trusted UI uses that client-generated path. Change all
existing issuance callers to staged activation together; retain no old endpoint
behavior that overwrites an active code before acknowledgment. A server-generated
candidate whose reply was lost is replaced only while still pending; a possibly
committed activation first resolves by candidate/revision status, never reissuance.

For personal accounts, normal code rotation/password-disable requires fresh local
custody proof and server authorization; shared-only uses fresh interactive UV.
A usable refresh session plus fresh local account unlock supports surviving-device
replacement even when the lost passkey cannot perform step-up. Passkey-only mode
requires one active UV credential, an acknowledged Server Recovery Key and, for
personal accounts, an established descriptor/text-root policy. Last-credential
removal without a tested replacement is refused; explicit restricted recovery
and local admin reset are the named exceptions, never an automatic fallback.
No server recovery endpoint removes the Account Encryption Password text root.

## Implementation gates and remaining limits

Crypto primitive/test-vector, wrong-context and cross-account tests must cover
all encodings above; deliberate existing blob/KDF/AAD changes invoke ADR 0009.
The selected format introduces new records, not retroactive acceptance of a
password-derived key in a shared-cache slot. Epoch/password changes and renewal
of unavailable PRF factors remain ADR 0013 work, outside initial grant enrollment.

Real OS/browser/provider qualification is a release gate, not an unspecified
protocol decision: installed adapter owns PRF handling, exact RP/origin config,
paired Noise and cancellation, with no server page handling E2EE. Test stable
cross-device output, native/browser normalization, full/Auth-only, UV, registration
without PRF output and grant proof. No platform is advertised as full-unlock
supported until it passes. Generic Auth-only remains available through qualified
UV authentication. Server compromise, copied offline keys, same-provider recovery
and malicious rollback retain the explicit limits in ADR 0018.
