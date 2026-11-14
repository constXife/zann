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
cp .env.example .env
# edit .env: set ZANN_PASSWORD_PEPPER and ZANN_TOKEN_PEPPER
# (openssl rand -base64 32)
docker compose up -d
```

This uses `config/dev.yaml`. The shared-vault master key is generated into
`./data/smk` on first start (mode `auto_generate`); back that file up. No secret
values ship in the repo.

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
