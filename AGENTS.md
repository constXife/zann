# Repository Guidelines

Full contribution rules live in `CONTRIBUTING.md`; this file is a brief, practical summary.

## Project Structure & Module Organization
- `crates/` contains the Rust workspace crates: `zann-server`, `zann-cli`, `zann-core`, `zann-db`, `zann-keystore`.
- `apps/desktop/` holds the Tauri desktop app (frontend + `src-tauri/` backend).
- `config/` stores environment and policy configs (use `config/config.example.yaml` as a template).
- `schemas/` includes specs and schema artifacts; `docs/` contains documentation and screenshots.
- `loadtest/` and `grafana/` hold performance tooling; `scripts/` has helper scripts and hooks.

## Build, Test, and Development Commands
- `cargo build` builds the Rust workspace.
- `cargo test` runs the fast, no-DB test suite.
- `cargo fmt` / `cargo clippy --all-targets --all-features` format and lint Rust code.
- Run `cargo fmt` before committing changes; CI enforces formatting.
- `just fast-test`, `just full-test`, `just test` are convenience wrappers (see `Justfile`).
- `just server-run` or `just server-run-dev` runs the API server with local migrations.
- `bun install` then `bun run tauri dev` starts the desktop app; `bun run tauri build` builds it.
- DB integration tests need Podman and `compose.test.yaml` (run via `just server-test-db`).

## Coding Style & Naming Conventions
- Rust code is formatted with `rustfmt`; keep Clippy clean (warnings are treated as errors in CI).
- Follow existing module boundaries (e.g., `crates/zann-server/src/domains/...`).
- Prefer descriptive, domain-scoped module names (`auth`, `vaults`, `sync`).
- For desktop code, follow the existing TypeScript/Vue style in `apps/desktop`.

## Testing Guidelines
- Rust tests live in `crates/*/tests/` and `src/**/tests.rs`.
- Fast tests are expected on every change; DB-backed tests require the Postgres container.
- For desktop changes, run `just desktop-test` and add/update e2e tests under `apps/desktop/e2e/`.

## Commit & Pull Request Guidelines
- Use Conventional Commits for PR titles and issue titles: `<type>(<scope>): <subject>`.
  Example: `feat(server): add audit log export`.
- Common scopes: `desktop`, `cli`, `server`, `core`, `db`, `keystore`, `ci`, `repo`.
- One PR per logical change; include a short summary and verification steps.
- Add screenshots or video for desktop UI changes.
- Breaking changes: use `!` in the title or add `BREAKING CHANGE:` in the PR body.

## GitHub Issues & Branch Naming
- Issues use the same Conventional Commits format and map to labels (`t:`, `p:`, `s:`); keep titles short and scoped.
- Branch names should reflect the same scope and intent, e.g. `feat/server-audit-log` or `fix/desktop-login`.
- Keep issue updates in the PR description and reference the issue number when applicable.
- Use GitHub CLI for issue/PR workflows when possible (e.g., `gh issue view 17`, `gh pr create`).

## Security & Configuration Tips
- Do not commit secrets; use `config/config.example.yaml`.
- Server threat model lives at `crates/zann-server/SECURITY.md`.
- When touching crypto/auth paths, read the audit-surface notes in `CONTRIBUTING.md`.
