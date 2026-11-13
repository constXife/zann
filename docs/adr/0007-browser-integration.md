# ADR 0007: Browser integration — trust boundary, matching, and what lives in JavaScript

- **Status:** Proposed
- **Proposed:** 2026-09-02
- **Scope:** the native-messaging host and browser extension of
  [ADR 0002](0002-client-strategy.md), Decision §5, a new
  `zann-autofill` crate, and the `login` payload
- **Related:** [ADR 0006](0006-passkey-provider.md) rides the same channel
- **Out of scope:** global autotype (see ADR 0006, *Alternatives considered*)

This proposal defines future owners and trust boundaries. It does not claim
that the daemon, native host, extension or pairing protocol already exist;
platform API and store requirements must be verified before implementation.

## Context

ADR 0002, Decision §5 decided two things about the extension and stopped: it reaches
the core through a native-messaging host, and a daemon owns the unlocked session
because the host cannot share COSMIC's. Neither exists yet — there is no host, no
daemon and no extension in the tree. Everything below is still open, and three of
the open questions are security decisions rather than engineering taste.

It helps to see the integration as four layers that fail in unrelated ways.

**Transport is the easy layer.** A stdio binary, a manifest under
`~/.mozilla/native-messaging-hosts/` and `~/.config/google-chrome/NativeMessagingHosts/`,
`allowed_extensions` / `allowed_origins` bounding who may launch it. The
message-size ceiling (about 1 MB toward the browser) settles one design question
by itself: attachments do not travel this way.

**Peer trust is not.** The host is not a privileged intermediary; it is an
ordinary client of a socket under `~/.zann`, and *any process running as the user
can open that socket*. Filesystem permissions separate users, not processes.
Without an explicit answer here, a shell script in the user's session asks the
daemon for passwords and gets them. The daemon is also the wrong place to be
casual about this, because ADR 0006 puts passkey assertions on the same channel.

**Matching is where a naive implementation is a vulnerability, not a bug.**
Today a `login` carries a single `url` — `schemas/security_profiles.yaml` lists
it under `exposable_public_attrs` — and there is no notion of a matching rule.
The only URL handling in the shared code is
`zann_ui_core::server_url::normalize_server_url`
(`crates/zann-ui-core/src/server_url.rs:5`), which prefixes `https://` onto what
the user typed into the connect field. That is the right function for its job and
useless for this one. Comparing hostnames without a public-suffix list collapses
`foo.co.uk` and `bar.co.uk`; comparing them too loosely offers the
`admin.example.com` credential on `blog.example.com`; comparing them too strictly
breaks every site whose login lives on a different subdomain than its content.
`zann-ui-core` deliberately carries five small dependencies
(`crates/zann-ui-core/Cargo.toml`) and is the wrong home for a vendored list of
every public suffix on the internet.

**Autofill is where the page is the adversary.** Field detection has to survive
shadow DOM and SPA re-renders; an in-page picker rendered into a hostile document
is clickjackable; filling on page load hands credentials to anything that
navigated the user there.

Two facts constrain all of it. `zann_ui_core::totp::generate_totp`
(`crates/zann-ui-core/src/totp.rs:55`) is already shared, so TOTP is nearly free
once the channel exists. And a new crate is not free: `config/architecture-boundaries.json`
enumerates `internal_packages`, `allowed_internal_dependencies` and
`forbidden_direct_dependencies`, and CI enforces all three.

## Decision

**1. The extension is a view. Nothing security-relevant lives in JavaScript.**
No matching, no policy, no origin derivation, no crypto. The JS does DOM work —
find fields, insert values, render the browser-provided surface — and shuttles
messages. Everything else is Rust, behind tests. Two reasons: the reviewed
artifact in the store stays small enough to audit, and the rules that decide
whether a secret is released are exercisable in `cargo test` without a browser.

**2. The host is a shim; the daemon holds everything.** The native-messaging
binary does no crypto, keeps no state and makes no decisions: it frames stdio
messages onto the daemon socket. It is a thin client on the facade exactly as
ADR 0002, Decision §5 anticipated. It transiently forwards released secret values
as transport, but must not persist them or gain independent authority to request
them. Authorization and secret lifetime remain owned by the daemon.

**3. Peer trust is explicit: `SO_PEERCRED` plus pairing.** The socket checks peer
credentials, and beyond that every client pairs. On first connection the
extension generates a key pair, the daemon shows the request in a UI the page
cannot reach, the user approves once, and subsequent requests are signed.
Unpaired clients get no data — not even item metadata. Pairings are listed and
revocable next to devices in settings. Peer credentials alone are explicitly
insufficient: they distinguish users, and the threat is a second process of the
same user.

**4. The browser never receives the master key and never decrypts.** Queries
return metadata — which items match this origin, their names and usernames. A
secret value crosses the channel only on an explicit user gesture, one value per
gesture, and the extension does not cache it. This extends ADR 0002's rejection
of a server-talking extension to its logical end: the browser is the most
attacked process on the machine and is treated as such.

**5. Matching moves into a new headless `zann-autofill` crate, and it owns
origins for the whole workspace.** It holds the public-suffix logic,
registrable-domain derivation, per-item match rules, the equivalent-domain list
and the fill policy. `zann-passkey` (ADR 0006 §5) depends on it for `rp_id`
derivation rather than deriving its own: two implementations of "what is a
registrable domain" is precisely the drift class
[ADR 0001](0001-shared-client-core.md) guards against,
and here the two copies would disagree about a phishing boundary. The crate is
registered in `config/architecture-boundaries.json` with `zann-core` as its only
internal dependency.

**6. The public-suffix list is vendored and digest-pinned.** Fetching it at
runtime is a supply-chain hole; letting it rot is a correctness bug. It is
updated by an ordinary PR, the same idiom `docs/Architecture.md` already uses for
digest-pinned sources.

**7. `login` gains explicit match rules.** A `match_rules` field with modes
`registrable-domain` (default), `host`, `exact`, `regex` and `never`, plus an
equivalent-domain list shipped as data. `never` matters as much as the rest: it
is how a user says "this credential is not for autofill".

**8. Fill policy, stated as rules the crate enforces.** No filling on page load —
a user gesture is required. No in-page picker; the browser's own popup or side
panel is the surface, at the cost of some UX. Iframes are matched on the frame's
own origin, and cross-origin frames are refused by default. The picker never
shows an item the origin did not match, so an incorrect match cannot be repaired
by the user clicking through.

**9. Chromium and Firefox first; Safari is a macOS app target, not a build
flag.** Safari integration is a separate Apple target after the shared channel
and policy are proven. The existing macOS app does not itself provide a browser
extension.

**10. Minimal permissions, no remote code, reproducible builds.** The extension
is the only artifact users obtain through a distribution channel we do not
control, so its build must be reproducible from the tag and its permission list
must be defensible line by line.

## Consequences

**Good.** The security-critical surface ends up in two testable Rust crates
rather than in content scripts, and `zann-autofill` serves the extension,
passkeys and any future client at once. TOTP arrives almost free. The pairing
model gives the daemon a general answer for every local client, not an
extension-specific patch.

**Bad.** The daemon becomes a hard dependency of the browsing experience: not
running means the extension is dead, and "the daemon isn't running" is the new
failure mode ADR 0002 already warned about, now on the user's critical path. The
no-in-page-picker rule costs real convenience against every competitor. Vendored
public-suffix and equivalent-domain lists are maintenance we have to actually
perform. And pairing adds an onboarding step at the exact moment a user is least
patient.

**Unresolved.** The MV3 service-worker lifetime against a long-lived port: an
active port extends the worker's life, but relying on it is fragile, so the
extension needs state that survives a restart and a reconnect path — the details
belong in the phase that builds it. Whether a pairing survives extension updates
and cleared extension storage, or whether users re-pair. What the daemon does
when the vault is locked and a fill is requested: prompt, or fail quietly. And
the equivalent-domain list has no obvious owner yet.

## Plan

| | Phase | Risk |
|---|---|---|
| 0 | `zann-autofill`: origins, public-suffix list, match rules, fill policy — pure functions, adversarial tests, no client | low |
| 1 | `match_rules` on the `login` payload, security profile and UI in COSMIC; migration defaults to `registrable-domain` | low |
| 2 | Daemon: socket, `SO_PEERCRED`, pairing, revocation UI, session ownership | **high** |
| 3 | Native-messaging host: stdio framing, manifests for both browsers, nothing else | low |
| 4 | Extension: password and TOTP autofill, save prompt, generator | **high** |
| 5 | ADR 0006 phases 3–4 ride the same channel | **high** |
| 6 | Reproducible build and store publication | medium |

Phase 2 is the one to be careful with: it is where a mistake is a local privilege
boundary, and it is a prerequisite for both this ADR and ADR 0006.

## Alternatives considered

**Matching in JavaScript, in the extension.** Every shipping manager does it, it
is where the DOM already is, and it avoids a crate. Rejected: the phishing
boundary would then live in the least testable, most exposed, store-distributed
part of the system, and `zann-passkey` could not reuse it.

**A localhost WebSocket or TCP port instead of native messaging.** Simpler to
develop against and browser-agnostic. Rejected: a web page can attempt a
WebSocket connection to localhost, so the port needs its own origin
authentication, and we would have built a second, weaker copy of the pairing
problem while also being reachable from the network stack. A unix socket plus a
browser-launched host is strictly narrower.

**Naive hostname comparison now, public-suffix list later.** Ships phase 0 in a
day. Rejected: the failure mode is offering the right credential on the wrong
site, which is the one outcome a password manager exists to prevent.

**The master key in the browser, decrypting locally, daemon optional.** Removes
the daemon from the critical path and makes the extension usable standalone.
Rejected on the same grounds as ADR 0002's rejection of a server-talking
extension, only more so: extension storage is readable by anything that achieves
code execution in the browser profile.

**An in-page autofill overlay.** Materially better UX, and what users expect.
Rejected for now: it means rendering a trusted picker inside an untrusted
document, where clickjacking against a one-click "fill" is a known and repeatedly
exploited pattern. Revisit if the browser surfaces prove unusable in practice.

**One matcher shared with global autotype.** Tempting symmetry. Rejected: the
inputs are not the same kind of thing. An origin is supplied by the browser and
is trustworthy; a window title is supplied by the application and is not. Sharing
the code would invite sharing the trust assumption.
