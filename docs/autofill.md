# Autofill matching (#198)

`zann-autofill` implements phases 0–1 of the direction proposed in
[ADR 0007](adr/0007-browser-integration.md). The daemon, pairing protocol,
and native host are implemented by [the local IPC service](browser-ipc.md) (#199);
the Chromium extension is implemented by [#25](chromium-extension.md). Matching
does not grant authority to release any secret.

The existing encrypted login payload keeps its typed `url` field. An optional
text-kind `match_rules` field contains one strict JSON object:

| Mode | Object | Meaning |
|---|---|---|
| Domain | `{"mode":"registrable-domain"}` | Same registrable domain, including PRIVATE PSL boundaries; reviewed equivalent groups also apply |
| Host | `{"mode":"host"}` | Same canonical scheme, host and effective port |
| Exact | `{"mode":"exact"}` | Same canonical URL including path/query, excluding fragment |
| Regex | `{"mode":"regex","pattern":"https://example\\.com/login"}` | Full canonical URL must match the bounded Rust regex |
| Never | `{"mode":"never"}` | Never a matching autofill candidate |

All modes retain scheme and effective-port equality with the saved URL. The
domain mode does not collapse `alice.github.io` with `bob.github.io`, or
`alice.co.uk` with `bob.co.uk`. IPs and `localhost` match only their own
origin; bare public suffixes never match in domain mode. IDNA/punycode is
canonicalized by the URL parser; visually similar different domains remain
different. Ambiguous separators, credentials, control characters, trailing
DNS dots and non-HTTP(S) URLs are rejected. HTTP URLs may be compared, but
fill admission requires HTTPS. No insecure-fill exception is implemented.

Only absence of `match_rules` means domain mode, as explicitly specified by
#198. Present empty, malformed, oversized, duplicate-key or unknown rules fail
closed. No payload/envelope version, crypto fixture or database migration is
needed: this is a normal encrypted field. COSMIC offers a mode selector and
regex input; FFI projects typed mode/pattern operations over the same shared
draft. Existing editors that preserve fields preserve these rules.

`LoginMatcher` is compiled once per candidate. Input URLs are limited to 8192
bytes; rules to 4096 bytes; regex source to 2048 bytes; regex compilation and
DFA cache each to 256 KiB. Matching is a bounded per-item operation, not a
vault scan API. The daemon separately bounds each indexed query to 32 candidates.

`authorize_fill` requires an explicit user gesture, HTTPS, same-origin top
and frame URLs, and a matching item. The adapter must obtain those URLs from
browser/OS APIs. The daemon authenticates the paired caller and binds each signed
sequence to its context/item. The gesture assertion comes from the privileged
browser popup; an enum value or a page message is not proof of user action. Cross-origin frames are denied
even when both frames match the same registrable domain.

The PSL source, license, update process and intentionally empty initial
equivalence dataset are documented [next to the data](../crates/zann-autofill/data/README.md).
Favicon retrieval/cache is a separate presentation capability, outside #198;
icons do not participate in matching or trust decisions.
