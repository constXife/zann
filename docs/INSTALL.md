---
title: Install Guide
description: Practical setup steps for desktop, CLI, and server.
---

Zann is currently evaluated from source or the local Compose stack. There is
no automated CLI binary release workflow or published native GUI installer.
Clone the repository before following the build commands:

```bash
git clone https://github.com/constXife/zann
cd zann
```

For normal native-client setup, [start the development server](#server-docker-compose-local-dev)
first, or use an existing Zann server. After building a client, connect to
`http://localhost:8080`, sign in or register, and create/unlock your personal
vault with its master password. Complete the first sync to use cached content
offline.

## Linux (COSMIC)

Build the native Linux package with Nix from the repository root:

```bash
nix build .#zann-cosmic
./result/bin/zann-cosmic
```

For a server-free UI preview, follow the
[offline demo fixture](https://github.com/constXife/zann/tree/main/apps/cosmic#offline-ui-preview-no-server)
using a throwaway database and a password you choose. It is a development/test
fixture without an authenticated server session, not standalone vault creation.

Without Nix, install rustup with current stable Rust, a C toolchain, Git,
pkg-config, OpenSSL, Wayland, xkbcommon, libudev, D-Bus, Expat, Fontconfig,
FreeType and OpenGL development packages, plus a Vulkan loader and your GPU's
Vulkan driver. Run in a Wayland desktop session with D-Bus available.
The [COSMIC prerequisites](https://github.com/constXife/zann/tree/main/apps/cosmic#without-nix)
list exact Ubuntu/Debian, Fedora and Arch package commands. Then build from the
app directory so its own stable toolchain is selected:

```bash
cd apps/cosmic
rustup update stable
cargo run --locked
```

See the [COSMIC guide](https://github.com/constXife/zann/tree/main/apps/cosmic)
for development and local desktop installation.

## macOS (SwiftUI)

On Apple silicon, install full Xcode (Command Line Tools alone are insufficient)
and Rust through rustup. Select Xcode with
`sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer` and open
it once to accept the license and finish setup. From the repository root:

```bash
brew install jq xcodegen
rustup target add aarch64-apple-darwin
```

Build the macOS Rust framework and Swift bindings, then the native app. No iOS
Rust targets or SDKs are needed for this local build:

```bash
apps/apple/ZannCoreKit/build-xcframework.sh debug
cd apps/apple
xcodegen --spec project.yml
xcodebuild -project Zann.xcodeproj -scheme Zann -destination 'platform=macOS,arch=arm64' build
```

Open `Zann.xcodeproj` and run the Zann scheme. See the
[Apple guide](https://github.com/constXife/zann/tree/main/apps/apple)
for signing, Touch ID, tests and optional `--all-platforms` packaging (which
requires the iOS and simulator Rust targets and SDKs). iOS/iPadOS app targets
and Windows GUI support are planned; the Tauri application has been retired.

## CLI

Build the CLI from the repository root with the pinned Rust toolchain:

```bash
cargo build -p zann-cli
```

The binary is at `target/debug/zann` (or `target/release/zann` with `--release`).

## Server (Docker Compose, local dev)

```bash
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
