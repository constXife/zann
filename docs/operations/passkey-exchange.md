# Passkey backups and exchange

In native Settings → Backups, **Import or export passkeys** transfers credentials
using one Rust implementation on COSMIC and Apple. Choose the intended personal
vault in the current account explicitly. Shared/server-encrypted vaults cannot
receive passkeys. Imported associated login passwords, URLs and notes stay inside
the encrypted passkey payload and remain hidden from generic copy/reveal tools.

Choose the input format before selecting a file:

- FIDO CXF 1.0 Proposed Standard with March 2026 errata, JSON.
- Bitwarden unencrypted JSON, `login.fido2Credentials`.
- KeePassXC `.passkey`, or a **plaintext XML export** with canonical
  `KPEX_PASSKEY_*` entry attributes. KDBX files and encrypted/protected XML values
  are not plaintext XML exports. Revoked entries in XML history are ignored.

The preview counts passkeys and ignored unrelated records. This is a passkey
transfer, so unrelated credential types are not imported. Every key and the
complete selected file must validate before any new item is committed. A repeat
import skips matching RP/credential identities; conflicting public keys or user
handles fail the whole import. Existing credentials are never overwritten.
Repeated titles use separate import paths and preserve their original metadata.

Export produces plaintext CXF. It requires fresh offline confirmation using the
configured export policy before choosing/writing the destination. Canceling,
locking, expiry and reusing the same confirmation cannot publish an export.
Files are written to fresh 0600 siblings, synced and atomically renamed.
These files contain private keys and associated login passwords: keep them
private and delete them after transfer. Native file-picker staging is removed
when the picker completes, is dismissed, or the app locks.

## Offline file conversion

The server-oriented CLI can convert an **already-plaintext file** to CXF without
opening a vault, reading a token/configuration, or contacting a server:

```sh
zann passkey --format bitwarden \
  --input /private/bitwarden.json --output /private/passkeys.cxf.json \
  --accept-plaintext \
  --account-id 00112233-4455-6677-8899-aabbccddeeff \
  --username alice --email alice@example.test
```

`--format` accepts `cxf`, `bitwarden`, `keepass-xc-passkey` and `keepass-xml`.
The account ID/username/email describe the public CXF account header; they are
explicit arguments. Secret key material is read from files, never argv or stdin,
and is never printed. Both input and output remain plaintext. This converter
cannot bypass native export confirmation because it has no unlocked-vault API.

## Validation and recovery scope

Only discoverable, syncable ES256/P-256 credentials with zero counters are
supported. Manager formats use PKCS#8 DER or its PEM representation; the pure
Rust library also exposes a separate strict COSE EC2 private-key decoder. Input
format is never guessed after a parse failure. Invalid RP IDs, oversized IDs or
handles, unsupported algorithms/FIDO2 cryptographic extensions, ambiguous or
duplicate fields, invalid points and malformed metadata fail closed.

External files are limited to 16 MiB and 4096 credentials. Native item path/name
limits still apply; an invalid late entry rolls back the entire local import.
Formats without creation time preserve an unknown time. Zann's namespaced CXF
extension preserves RP display names and exact optional timestamps; it never
changes credential IDs, RP IDs, user handles or keys.

Canonical Zann plain and encrypted backups retain the full passkey payload.
The regression corpus restores both through the server and pulls to an
independent device before verifying assertions against an independent public
key. `VACUUM INTO` snapshots restore encrypted state and require unlocking
again; unlocked `verify` checks passkey semantics in addition to ciphertext.
No vault `v1` envelope, KDF or AAD format changes are involved.

Live browser/OS provider registration remains tracked separately by #293/#294.
