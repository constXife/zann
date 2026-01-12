# Contributing Guide

Thanks for contributing! This guide explains how to work in this repo and what we expect from PRs.

## Quickstart

1. Create a branch from `main`.
2. Make changes in the relevant crate/app.
3. Run formatting/tests (see below).
4. Open a PR on GitHub and use Conventional Commits for the PR title.

We use **squash merge**, so the PR title becomes the commit message in `main`.

## Repository layout

- `crates/` — Rust crates (`zann-cli`, `zann-server`, `zann-core`, `zann-db`, `zann-keystore`)
- `apps/desktop` — desktop app (Tauri + Bun)
- `config/` — configs (CI, dev, policies)
- `schemas/` — schemas/specs
- `compose.yaml` — local integration/demo

## Development environment

Requirements:
- Rust toolchain per `rust-toolchain.toml`
- Bun for `apps/desktop`
- `just` (optional)

Workspace (Rust):
- Build: `cargo build`
- Tests: `cargo test`
- Format: `cargo fmt`
- Lint: `cargo clippy --all-targets --all-features`

Desktop (Tauri) from `apps/desktop`:
- Install deps: `bun install`
- Dev: `bun run tauri dev`
- Build: `bun run tauri build`

## PR process

- One PR = one logical change.
- Include a short summary and verification steps.
- Add screenshots/video for desktop changes when applicable.

## PR naming: Conventional Commits

Format:
`<type>(<scope>): <subject>`

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `build`, `ci`, `chore`.

Scopes: pick the primary area (`desktop`, `cli`, `server`, `core`, `db`, `keystore`, `ci`, `repo`).

## Issues naming and labels

Use the same Conventional Commits format for issue titles:
`<type>(<scope>): <subject>`.

Types map to `t:` labels (feature, bug, refactor, discussion, security, chore, docs).
Scopes map to `s:` labels (desktop, cli, server, core, db, keystore, ci, repo).

Issue templates add the type label automatically and the issue-labeler workflow
applies the scope label based on the selected Area. If you change label names or
colors, run the "Sync labels" workflow.

## Breaking changes

Use one of:
- PR title: `feat(server)!: change auth token format`
- PR body: `BREAKING CHANGE: describe what breaks and how to migrate`

## AI-assisted contributions (LLM/Copilot/etc.)

Allowed.
- PR author is responsible for correctness, security, and maintainability.

## Dependencies and security

- Explain dependency changes.
- CI enforces Rust license policy via `deny.toml`.
- Do not commit secrets (use `config.example.yaml`).

## Audit-surface plan (draft)

Goal: isolate security-critical code (audit-surface) so we can trust the core
without constant re-audits, prevent architectural drift, and track "blessed"
versions at release time.

Principles:
- "Hard core, flexible shell" — isolate audit-surface from the rest.
- High value / low cost — keep the surface minimal.
- Low bureaucracy — automate, keep manual steps few.

High-value components:
- Dependency guard to keep the audit-surface isolated.
- Auto-labeler to highlight security-impacting changes.
- Strict clippy on audit-surface paths.
- Property tests for crypto invariants.
- Repository rulesets (no direct pushes to `main`).

Overkill for this repo (for now):
- SHA pinning for actions.
- Hash manifests in CI (Git already gives integrity).
- Formal break-glass process.
- Required approvals / CODEOWNERS validation in solo mode.

Audit-surface (current targets):
- `crates/zann-core/src/crypto.rs`
- `crates/zann-core/src/vault_crypto.rs`
- `crates/zann-core/src/auth.rs`
- `crates/zann-core/src/secrets.rs`
- `crates/zann-server/src/domains/auth/core/**`
- `crates/zann-server/src/domains/access_control/**`
- `crates/zann-keystore/**`
- `crates/zann-server/src/infra/audit.rs`

Architectural option: extract `zann-crypto` crate
- Rationale: tighter boundaries, smaller audit scope, minimal deps, reuse.
- Proposed modules: `blob`, `keys`, `vault`, `password`, `token`, `payload`.
- `zann-core` re-exports crypto types; `zann-server` uses `zann-crypto` directly.
- Move `EncryptedPayload` into `zann-crypto` (pure serialized structure).

Implementation phases (high level):
1. Create `zann-crypto` and migrate crypto/password/token/payload code.
2. Add dependency guard for `zann-crypto` isolation.
3. Add `CODEOWNERS`, audit-surface labels, and auto-labeler.
4. Add CI gate for audit-surface (strict clippy + property tests).
5. Add audit status doc and "blessed" release notes.

## Reporting vulnerabilities

Do **not** open a public issue. Report privately via the security contact (TBD).

## License

By contributing, you agree your contributions are licensed under `LICENSE`.
