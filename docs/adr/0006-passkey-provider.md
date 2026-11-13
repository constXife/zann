# ADR 0006: Zann as a passkey provider

- **Status:** Proposed
- **Proposed:** 2026-09-01
- **Scope:** `zann-core` item model, `zann-crypto`, a new `zann-passkey` crate,
  the native-messaging host and browser extension of
  [ADR 0002](0002-client-strategy.md), Decision §5
- **Related:** [ADR 0007](0007-browser-integration.md) owns the channel, the
  pairing model and origin derivation this ADR rides on
- **Out of scope:** signing *into Zann* with a passkey (Zann as a relying party)

This is a proposal, not an implementation contract. Platform admission details
below are proposal-time assumptions; they need verification against platform
documentation before implementation. Shared-vault eligibility and user
verification remain unresolved in the consequences below.

## Context

Three unrelated things in this repository say "FIDO", and conflating them is the
first way this decision goes wrong.

1. **What exists today.** `crates/zann-keystore/src/fido.rs` uses a hardware
   token's `hmac-secret` extension to derive a device wrapping key. Zann is the
   *client* of an authenticator; the credential is non-discoverable, scoped to
   `RP_ID = "zann.local"` (`fido.rs:23`), and deliberately requires user presence
   but not verification. Nothing about it is a passkey.
2. **Zann as a relying party** — a passkey that unlocks a Zann account. Small,
   server-side, `webauthn-rs`, and independent of everything below.
3. **Zann as a provider** — websites' passkeys stored in a Zann vault, with Zann
   playing the authenticator. That is this ADR.

### How the ceremony actually works

Two protocols with a hard boundary. **WebAuthn** is what the page calls:
`navigator.credentials.create()` / `.get()`. The browser, not the page,
determines the origin and writes it into `clientDataJSON`. **CTAP2** is what the
authenticator answers: exactly `makeCredential` and `getAssertion`.

A passkey is therefore data, not hardware: `rp_id`, `credential_id`,
`user_handle`, a private key, a counter, flags. Registration generates a key pair
and returns an attestation object; authentication signs
`authenticatorData || SHA256(clientDataJSON)`. **Phishing resistance comes from
the `rp_id` binding plus the fact that the origin is supplied by the browser** —
not from the key living in a chip. Apple, Google and every password manager that
ships passkeys store syncable software credentials, and the specification
accommodates them explicitly.

### The constraint is admission, not cryptography

Implementing CTAP2 is a bounded, testable problem. Being *allowed to answer* a
ceremony is not:

| Platform | Official path | Cost |
|---|---|---|
| Android 14+ | `CredentialProviderService` (Credential Manager) | needs an Android client |
| iOS 17 / macOS 14+ | `ASCredentialProviderExtension`, passkey support | platform entitlements and extension packaging |
| Windows 11, recent builds | plugin authenticator API | native app registration |
| Chromium | `chrome.webAuthenticationProxy` — designed for remote desktop, **exclusive: one attached extension per profile** | MV3 extension |
| Firefox | none | — |
| **Linux / COSMIC** | **none** | — |

Where no API exists, shipping managers override `navigator.credentials` from a
content script. It works, and the price is precise: the page-level shim breaks on
sites that capture the API early, collides with the browser's own provider UI,
is awkward inside iframes, and **moves origin validation out of the browser and
into our code**.

COSMIC is the pacesetting client (ADR 0002, Decision §2) and runs on the platform with no
provider API at all. For Zann, "become a passkey provider" therefore means
"ship a browser extension" before it means anything else.

### What the repository already gives us, and what it does not

`Item` carries `type_id: String` and an opaque `payload_enc`
(`crates/zann-core/src/models/structs.rs:147-166`). A passkey is a new
`type_id` and **no schema change**: sync, history, tombstones, sharing and
export all apply unchanged. `schemas/security_profiles.yaml` is keyed by
`type_id`, so masking and never-log rules are declarative.

Three gaps:

- **No P-256.** `crates/zann-crypto/Cargo.toml` carries Argon2, ChaCha20-Poly1305,
  blake3 and sha2. ES256 (COSE `-7`) is the one algorithm every relying party
  accepts and we cannot produce it today.
- **No monotonic counter is possible.** Two devices holding the same synced
  credential cannot maintain an increasing signature counter. The specification's
  answer is a permanent `0`, which is what all syncing providers do.
- **No session to sign with.** An assertion requires an unlocked vault. The
  daemon that ADR 0002, Decision §5 made load-bearing for the extension is equally
  load-bearing here, and it must also own the per-assertion presence prompt.

## Decision

**1. A passkey is a first-class item, `type_id = "passkey"`.** Not a field on
`login`. A site maps to many credentials, the join key is `rp_id` rather than a
URL, and there is no username to autofill. The payload is:

```
rp_id, rp_name, credential_id, user_handle, user_name, user_display_name,
alg (COSE), private_key, created_at, last_used_at, discoverable: true
```

`security_profiles.yaml` gains the strictest profile in the file:
`private_key` is never copyable, never revealable and in `never_log_fields`;
`credential_id` and `user_handle` are not public attributes. A `passkey`
category is added to `schemas/ui_categories.json`.

**2. Ceremony logic lives in a new headless `zann-passkey` crate.** Pure
functions from a payload plus a request to a response: CBOR, COSE, attestation
objects, `authenticatorData` assembly, `getAssertion` credential selection. No
HID, no browser, no `$HOME`, no toolkit — the layering rule of
[ADR 0001](0001-shared-client-core.md)
applies from the first commit. `passkey-rs` supplies types and CTAP2 structures
where they fit; the credential store is ours. Correctness is proved against
WebAuthn test vectors before any client exists.

**3. ES256 only, at first.** Add `p256`/`ecdsa` to `zann-crypto` behind a
feature so `scripts/check-audit-surface-deps.sh` keeps meaning something. Ed25519
(`-8`) is added when relying-party support justifies a second code path, not
before.

**4. The signature counter is permanently `0`, and we never lie about flags.**
`uv` is set if and only if a user verification actually happened for this
request — vault unlock by password or biometric within the presence window, not
"the session happens to be unlocked". `up` requires an explicit per-assertion
confirmation. **There are no silent assertions**, including for a vault that is
already open.

**5. In the extension path, origin validation is our obligation.** The `rp_id`
is derived from the browser-supplied top-level origin and nothing else; page
content is never trusted for it; cross-origin iframe requests are refused unless
the relying party has permitted them. This is the single highest-risk rule in
the ADR and belongs in Rust with adversarial tests, not in extension JavaScript.
Registrable-domain derivation itself comes from `zann-autofill`
([ADR 0007](0007-browser-integration.md) §5), which owns origins for the whole
workspace; `zann-passkey` enforces the rule, it does not re-derive the domain.

**6. Attestation is `none`.** We do not claim hardware backing, and an AAGUID is
registered in the community provider list only so the icon renders. Enterprise
relying parties that demand verified attestation will refuse our credentials;
that is the correct outcome, not a bug to work around.

**7. Delivery follows ADR 0002's order.** Extension first, because it is the only
Linux path and because the host and daemon are accepted target work in ADR 0002. Native
providers are added per platform only where an official API exists *and* a Zann
client already ships there.

**8. Zann as a relying party is a separate decision.** Different crate,
different threat model, no shared code beyond COSE parsing.

## Consequences

**Good.** The expensive half is platform-independent: item type, crypto,
ceremonies and origin rules are one headless crate that every future provider
reuses, and it is exercisable from the CLI long before a browser is involved.
Sync, sharing, history and export come free from the existing item model. The
work also finishes the daemon, which three other clients need anyway.

**Bad.** We take on origin validation, which the browser does for hardware keys —
a mistake there is a phishing vulnerability, not a bug. The shim collides with
Chrome's and GNOME's own passkey UI, and `webAuthenticationProxy` is exclusive,
so a user cannot run Zann alongside another provider extension. Passkeys are also
the first item type where **losing the vault means losing the account outright**:
many relying parties have no password to fall back on. Export and snapshots
(ADR 0002, Decision §3) stop being prudence and become a precondition for shipping this
at all. And `p256` in `zann-crypto` widens the audit surface that
`CONTRIBUTING.md` asks us to keep narrow.

**Unresolved.** Whether passkeys may live in *shared* vaults. A shared password is
a delegated secret; a shared passkey is a shared identity, and several relying
parties treat re-registration from a second device as account compromise. The
conservative default — personal vaults only — is easy to relax later and
impossible to tighten. Also unresolved: what counts as user verification on
Linux, where there is no uniform biometric prompt, and how the daemon raises a
presence prompt when COSMIC is not running.

## Plan

| | Phase | Risk |
|---|---|---|
| 0 | `zann-passkey`: types, CBOR/COSE, ES256 in `zann-crypto`, both ceremonies, WebAuthn test vectors. No client changes. | low |
| 1 | `passkey` item type: security profile, UI category, create/read/delete through the facade; COSMIC lists them | low |
| 2 | `zann passkey list \| get \| create \| delete` in the CLI — the core becomes exercisable without a browser | low |
| 3 | Native-messaging host gains the two ceremony calls; daemon owns the session and the presence prompt | medium |
| 4 | Browser extension: WebAuthn shim on Chromium and Firefox, origin rules enforced in Rust | **high** |
| 5 | Re-evaluate `webAuthenticationProxy` against the shim with a working extension in hand | low |
| 6 | Native providers, per platform, only behind an existing client | medium |

Phases 0–2 are worth doing on their own merits: they make passkeys importable and
exportable, which matters even before Zann can answer a ceremony.

Platform API details in the table above move quickly and are stated as of
2026-09; re-verify before phase 6 is planned.

## Alternatives considered

**Store the passkey as a field on the `login` item.** Fewer moving parts, and the
autofill UI could stay one list. Rejected: the relationship is one-to-many, the
lookup key is `rp_id` rather than a URL, and a private key needs a strictly
tighter profile than the one `login` grants `password`.

**A virtual CTAP2 authenticator over `uhid` on Linux.** Genuinely attractive:
every browser sees an ordinary USB key, no extension is needed, and — decisively
— **origin validation goes back to the browser**, deleting decision §5 and its
whole risk class. Deferred rather than rejected: it needs `uinput`/udev
privileges, presents a device to every process on the machine, and no shipping
manager does it, so we would be alone on the failure modes. Reconsider if the
page-level shim proves unworkable in phase 4.

**Global autotype instead of an extension, in the style of KeePassXC** — a
portal global shortcut plus synthetic input, reaching the browser from outside
it. Rejected *for this decision*, on a categorical ground rather than a
weighing: **a passkey cannot be typed.** The ceremony runs between the page and
the browser, and no sequence of keystrokes enters it. Autotype is a real and
independent feature — it is one more daemon client, it needs no store review and
no MV3 lifecycle, and phase 3 below is exactly the groundwork it wants — but it
is not a Linux route to passkeys and must not be read as a reason to defer
phase 4. Its own costs belong wherever it is decided, not here: matching by
window title rather than browser-supplied origin is spoofable by any
application, so it carries no anti-phishing property; on Wayland synthetic input
means holding a RemoteDesktop portal session, which is a very broad capability
for the process that holds the vault; and identifying the focused window at all
requires a compositor-specific protocol (`cosmic-toplevel-info`), without which
it degrades to pasting into whatever has focus.

**caBLE / hybrid transport — behave like a phone over BLE and QR.** Rejected: the
tunnel infrastructure is operated by Google and Apple and is not open to third
parties.

**Ed25519 instead of ES256.** Smaller, faster, already closer to our crypto
stack. Rejected: relying-party support is uneven, and a credential a site refuses
is worse than no credential.

**Do nothing; point users at hardware keys.** A defensible position — hardware
keys are stronger, and `zann-keystore` already speaks to them. Rejected on
product grounds: passkeys are becoming the default sign-in for consumer accounts,
and a password manager that cannot hold them is excluded from the case it exists
to serve.
