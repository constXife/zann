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

Types map to `t:` labels (feature, bug, refactor, discussion, chore, docs).
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

## Reporting vulnerabilities

Do **not** open a public issue. Report privately via the security contact (TBD).

## License

By contributing, you agree your contributions are licensed under `LICENSE`.
