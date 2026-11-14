# Autofill matching data

Owner: `@constXife`, reviewed as part of the security audit surface.

`public_suffix_list.dat` is the complete UTF-8 ICANN + PRIVATE list downloaded
from <https://publicsuffix.org/list/public_suffix_list.dat> on 2026-11-13.
Its upstream version/commit and MPL-2.0 notice are retained in the file.
`publicsuffix` interprets its wildcard and exception rules, including IDNA.

`equivalent_domains.json` is a list of groups of canonical ASCII registrable
domains. Its initial content is deliberately empty: no cross-domain credential
sharing is enabled without a reviewed provider ownership/authentication claim.
Do not import a third-party password manager's equivalence list wholesale.
Only domain-mode matching consults this file; host/exact rules never widen.

Both files have adjacent SHA-256 pins checked at build time. Updates are an
explicit PR: replace the data from the authoritative source, inspect changes,
regenerate the adjacent pin with `shasum -a 256`, and run `cargo test -p
zann-autofill`. Equivalence additions require a source proving shared login
ownership and a regression test for the group and unrelated lookalike domains.
There is no runtime download or disk lookup.
