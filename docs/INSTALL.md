---
title: Install Guide
description: Practical setup steps for desktop, CLI, and server.
---

## Linux (COSMIC)

Build the native Linux package with Nix from the repository root:

```bash
nix build .#zann-cosmic
./result/bin/zann-cosmic
```

For development and local installation, see the
[COSMIC guide](https://github.com/constXife/zann/tree/main/apps/cosmic).

## macOS (SwiftUI)

Build the Rust framework and generated Swift bindings, then the native app:

```bash
apps/apple/ZannCoreKit/build-xcframework.sh debug
cd apps/apple
xcodegen --spec project.yml
xcodebuild -project Zann.xcodeproj -scheme Zann -destination 'platform=macOS,arch=arm64' build
```

Requires Xcode and XcodeGen. See the
[Apple guide](https://github.com/constXife/zann/tree/main/apps/apple)
for signing, Touch ID and tests. iOS/iPadOS app targets and Windows GUI support
are planned; the Tauri application has been retired.

## CLI

Release binaries are on GitHub Releases. To build locally:

```bash
cargo build -p zann-cli
```

The binary is at `target/debug/zann` (or `target/release/zann` with `--release`).

## Server (Docker Compose, local dev)

```bash
git clone https://github.com/constXife/zann
cd zann
./scripts/dev-up.sh
# Or: just dev-up
```

Requires Docker Engine / Docker Desktop with Compose, Bash and OpenSSL. With
Podman and a Compose provider, run `./scripts/dev-up.sh podman` or
`just dev-up podman` instead. The bootstrap creates `.env` from `.env.example`
with independent random peppers and `0600` permissions. Existing `.env` contents
are preserved; blank required values must be filled explicitly. Keep the file
for subsequent starts. Once it exists, `docker compose up -d` also works directly.

This uses `config/dev.yaml` and PostgreSQL. The `zann_data` named volume holds
`/data/smk` (generated on first start in `auto_generate` mode) and
`/data/identity-key`. The `zann_pgdata` named volume holds the database. Compose
prefixes these volume names with the project name. No secret values ship in the
repo. Existing `./data` bind-mount keys must be copied into `zann_data` before
starting an upgraded checkout; they are not moved automatically.

### Local dev backups

Keep `.env`, a database dump, and both key files together in private backup
storage. Losing the SMK makes shared vaults unreadable; losing the identity key
changes the server identity pinned by clients. For Docker, from the repository
root with the stack running:

```bash
umask 077
backup_dir="$(mktemp -d)"
docker compose exec -T db pg_dump -U zann -d zann > "$backup_dir/database.sql"
docker compose cp server:/data/smk "$backup_dir/smk"
docker compose cp server:/data/identity-key "$backup_dir/identity-key"
cp .env "$backup_dir/.env"
chmod 600 "$backup_dir/"*
```

Move this directory to private backup storage outside the checkout. Use
`docker compose down` to stop while retaining volumes; `docker compose down -v`
(or `just db-reset`) deletes the database and keys. For Podman, replace
`docker compose` with `podman compose`.

## Server (prebuilt image)

```bash
docker pull constxife/zann-server:latest
```

## Server config (self-hosted)

Start from `config/config.example.yaml` and supply required secrets via env:

- `ZANN_PASSWORD_PEPPER`
- `ZANN_TOKEN_PEPPER`
- `ZANN_SMK` or `ZANN_SMK_FILE` / `server.master_key_file` (shared vault master key; the server rejects the historically committed public dev key)
- `ZANN_IDENTITY_KEY_FILE` / `server.identity_key_file` (Ed25519 server identity; generated on first start if the file is missing, and must live on persistent storage)
- `ZANN_CONFIG_PATH` (path to your config file)

The config file controls auth mode, OIDC settings, policies, and metrics.

## First user access

For local dev, `config/dev.yaml` sets `auth.internal.registration: open`.
For production, consider `invite_only` and create invites from an admin account.
