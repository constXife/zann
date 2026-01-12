# Audit Surface

## Status

This document tracks the current audit-surface boundaries and "blessed" releases.
Until a release is blessed, assume the audit status is "in progress".

## Scope

Current audit-surface paths:

- `crates/zann-crypto/**`
- `crates/zann-core/src/auth.rs`
- `crates/zann-server/src/domains/auth/core/**`
- `crates/zann-server/src/domains/access_control/**`
- `crates/zann-server/src/infra/audit.rs`
- `crates/zann-keystore/**`

## Guardrails

- Dependency guard: `scripts/check-audit-surface-deps.sh` (direct deps for `zann-crypto`).
- CI gate: audit-surface clippy + crypto property tests on audit-surface changes.
- Auto-labeler: `t: security` for audit-surface path changes.
- CODEOWNERS: audit-surface paths require review by owners.

## Blessed Releases

Add a new row when a release is blessed.

| Version | Date (UTC) | Commit | Notes |
| --- | --- | --- | --- |
| Unblessed | - | - | No blessed releases yet. |
