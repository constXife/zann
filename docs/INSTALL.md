---
title: Install Guide
description: Practical setup steps for desktop, CLI, and server.
---

## Desktop (Tauri)

If your platform is not listed in Releases, build from source:

```bash
cd apps/desktop
bun install
bun run tauri build
```

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
docker compose up -d
```

This uses `config/dev.yaml` and dev-only pepper values from `compose.yaml`.

## Server (prebuilt image)

```bash
docker pull constxife/zann-server:latest
```

## Server config (self-hosted)

Start from `config/config.example.yaml` and supply required secrets via env:

- `ZANN_PASSWORD_PEPPER`
- `ZANN_TOKEN_PEPPER`
- `ZANN_SMK_FILE` or `server.master_key` (shared vault master key)
- `ZANN_CONFIG_PATH` (path to your config file)

The config file controls auth mode, OIDC settings, policies, and metrics.

## First user access

For local dev, `config/dev.yaml` sets `auth.internal.registration: open`.
For production, consider `invite_only` and create invites from an admin account.
