# Audit-surface status

The audit surface is the small set of security-sensitive modules that receive
security labeling, explicit ownership and stricter CI checks. The list is
source-based: moving policy behind a new adapter does not remove it from the
surface.

## Current status

No release is designated as fully audited or “blessed” yet. Until that changes,
the automated gates provide regression protection but are not a substitute for
a focused security review.

The current surface covers:

- cryptographic primitives and their compatibility fixtures in `zann-crypto`;
- core and server authentication and access-control policy;
- OS secret storage in `zann-keystore`;
- Config v2, credential lifecycle and their crash/recovery tests in
  `zann-client`;
- signed server-identity verification and its opaque trust proof in
  `zann-client`;
- the sync owner, secret-bearing payload-key models and persistence ports under
  `crates/zann-client/src/sync/**`;
- the DB-free authenticated application facade and operation-scoped sync-store
  factory port in `crates/zann-client/src/app.rs`;
- the production bidirectional SQLite sync adapter in `zann-client-sqlite`,
  including its pinned existing-file opener, exact Config v2 generation lease,
  bounded projection readers, initial personal-key publication and atomic
  storage/catalog/item/checkpoint CAS seams in `zann-db`;
- server audit-log infrastructure.

`CODEOWNERS`, the `t: security` labeler and the `audit-surface` CI job must be
updated in the same change whenever this list grows or moves. Client ownership
and dependency direction are additionally enforced by
`scripts/check-client-architecture.sh`.

## Release record

There are currently no blessed releases. A future entry must name the exact Git
revision, reviewed paths, review date, known limitations and the checks that
were run; a version number alone is not sufficient.
