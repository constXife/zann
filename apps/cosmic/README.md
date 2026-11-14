# Zann for Linux (COSMIC)

Native Linux password manager built on [libcosmic](https://github.com/pop-os/libcosmic).
Connect to a server, unlock its encrypted offline replica, and browse, search,
create or edit items. Secret fields stay masked until revealed; one-time codes,
clipboard copy and item history are available in the detail view.

## Quick run

For normal setup, first [start a development server](../../README.md#1-start-a-server)
or use an existing Zann server. With Nix, from the repository root:

```bash
nix build .#zann-cosmic
./result/bin/zann-cosmic
```

Connect to `http://localhost:8080`, sign in or register, then create/unlock your
personal vault with its master password. After the first sync, cached vaults
work offline; edits wait for the server to confirm them.

## Offline UI preview (no server)

Use the existing `seed_demo_vault` development fixture to explore the UI before
setting up a server. From the repository root, enter the development shell:

```bash
nix develop .#cosmic --command bash
cd apps/cosmic
```

Or install the [non-Nix prerequisites](#without-nix) below, open Bash with `bash`
and run `cd apps/cosmic`. Then, in that same terminal:

```bash
umask 077
demo_dir="$(mktemp -d)"
export ZANN_DB_URL="sqlite://$demo_dir/local.sqlite"
read -r -s -p 'Choose a demo master password: ' ZANN_DEMO_PASSWORD
printf '\n'
export ZANN_DEMO_PASSWORD
cargo run --locked --example seed_demo_vault
unset ZANN_DEMO_PASSWORD
cargo run --locked
```

Unlock with the password you chose. The fixture writes a few synthetic key/value
items and a login with a masked password and a one-time code. Both environment
variables are required for seeding; keep `ZANN_DB_URL` set when launching the app
so it opens that same database. The identity config is written beside it.

This fixture has no authenticated server session or sync and is available only
in development/test builds. It does not add serverless vault creation to the
normal client. Each run above uses a fresh private directory.

## Build prerequisites

### With Nix

libcosmic needs a newer Rust toolchain than the root workspace pin. The app has
its own development shell, selected from the repository root:

```bash
nix develop .#cosmic
cd apps/cosmic
cargo run --locked
```

### Without Nix

Install [rustup](https://rustup.rs/) and an up-to-date stable Rust toolchain.
`apps/cosmic/rust-toolchain.toml` selects stable when Cargo runs from that
folder; the root workspace toolchain is not used for this app.

The build needs a C toolchain, Git, pkg-config, OpenSSL, Wayland, xkbcommon,
libudev, Expat, Fontconfig and FreeType development files. At runtime it needs
a Wayland desktop session, D-Bus, the Vulkan loader and a Vulkan driver for your
GPU. The package commands below include the build dependencies and loader;
install your distribution's GPU driver separately.

Ubuntu / Debian:

```bash
sudo apt-get update
sudo apt-get install -y build-essential git pkg-config libssl-dev \
  libwayland-dev wayland-protocols libxkbcommon-dev libudev-dev \
  libdbus-1-dev dbus libexpat1-dev libfontconfig1-dev libfreetype6-dev \
  libgl1-mesa-dev libvulkan1
```

Fedora:

```bash
sudo dnf install gcc gcc-c++ make git pkgconf-pkg-config openssl-devel \
  wayland-devel wayland-protocols-devel libxkbcommon-devel systemd-devel \
  dbus-devel dbus expat-devel fontconfig-devel freetype-devel \
  mesa-libGL-devel vulkan-loader
```

Arch Linux:

```bash
sudo pacman -S --needed base-devel git pkgconf openssl wayland wayland-protocols \
  libxkbcommon systemd-libs dbus expat fontconfig freetype2 libglvnd vulkan-icd-loader
```

Then, from the repository root:

```bash
cd apps/cosmic
rustup update stable
cargo run --locked
```

`ZANN_DB_URL` can point development builds at a separate database; otherwise the
client uses `sqlite://$HOME/.zann/local.sqlite`.

## Install it as a desktop app

The packaged way, which is what you want unless you are iterating on the code:

```bash
nix build .#zann-cosmic          # or: nix profile install .#zann-cosmic
```

The derivation installs the binary, the desktop entry and the icons into the
same output, so a `nix profile install` puts all three in the profile and the
launcher picks the app up on its own. Nothing is left in `~/.local`, and the
library paths are baked in by `wrapProgram` from the derivation's own inputs, so
it survives `nix-collect-garbage`.

For a quick loop while changing code, the same thing straight into `~/.local`:

```bash
just cosmic-install     # ~/.local/bin + ~/.local/share/{applications,icons}
just cosmic-uninstall
```

That one builds the release binary, installs the desktop entry from `data/` with
`Exec` rewritten to the absolute path, and uses the shared product icons from `assets/icons` — one owner for every client. The
binary lands in `~/.local/libexec` and `~/.local/bin/zann-cosmic` is a wrapper,
because winit `dlopen`s libwayland at startup and a launcher starts `Exec=` with
none of the dev shell's environment — the bare binary dies with `NoWaylandLib`.
That wrapper carries the `LD_LIBRARY_PATH` of the shell that built it, so it
points at store paths: rerun `just cosmic-install` after a
`nix-collect-garbage`. The Nix package has no such problem.

Two more things worth knowing:

- The entry's `StartupWMClass` has to equal the app's `APP_ID`
  (`com.rlyeh.zann.Cosmic`). If they drift apart the window appears without the
  launcher's name and icon.
- Launched this way it gets no `ZANN_DB_URL`, so it opens the same
  `~/.zann/local.sqlite` database — including running the local
  migrations against it. That is fine while this is built from the same commit
  as the client you rely on; it stops being fine the moment you install a build
  from a branch that is ahead on schema. Point it elsewhere while testing:
  `ZANN_DB_URL=sqlite:///tmp/zann-demo/local.sqlite zann-cosmic`.

## Layout

`main.rs` is the shell and nothing else: the window, the [`Session`] and the
routing between screens. Everything else lives in the library next to it, which
is what lets `tests/flows.rs` drive the flows without a compositor.

```
src/backend/local.rs    the vault on this machine (zann-client-sqlite)
src/backend/remote.rs   logging in against a server (zann-client)
src/session.rs          the open database and the core's auto-sync schedule,
                        owned for the app's lifetime
src/screens/*.rs        one module per screen
```

Each screen owns its own state and its own `Message`, and reports back through
its own `Outcome` — it knows nothing about `Screen` or about its siblings, so
every transition is decided in one place. A screen never reaches for the
clipboard, the browser or the window: those come back as `Outcome` variants the
shell acts on. Two rules keep this from eroding:

- no state in the shell that belongs to a screen — if two screens need the same
  field, it belongs to neither;
- no `Option` for something that always exists once the app is running, which is
  why `Session` is not optional and a missing database is a separate shell state.

While a vault is open it syncs on the core's `AutoSyncSchedule`: at once on
unlock (unless the first sync after a login just ran), a couple of seconds after
each save, and every minute otherwise. The vault screen keeps one timer armed
for it; Settings → Sync now takes the same one-sync-at-a-time admission, and a
lock forgets what was due and cancels a sync in flight.

## Connecting without a server

`tools/mock-server` answers the endpoints a password login needs
(`/v1/system/info`, `/v1/auth/prelogin`, `/v1/auth/register`, `/v1/auth/login`,
`/v1/vaults/personal/status`), which is enough to walk the connect screen end to
end. It does not implement sync, so the pull after unlocking and every
automatic sync after it fail — the vault still opens and reports it.

```bash
cargo run --manifest-path ../../tools/mock-server/Cargo.toml   # 127.0.0.1:18081
```

## Renderer

The app renders through `wgpu`, the same way the system COSMIC apps do, so it
needs a working Vulkan stack (`vulkan-loader` and the GPU driver are in the dev
shell's `LD_LIBRARY_PATH`).

It maps `libvulkan`, `libGLX_nvidia` and `libdrm` at startup. Dropping the
`wgpu` feature falls back to iced's software renderer (tiny-skia) and saves
roughly 60 MB of RSS — cheaper, but not what the rest of the desktop runs on.

## Memory

Release build, x86_64 + NVIDIA, vault of 1000 items (200 paged in):

| | RSS | PSS | anonymous (PSS) |
|---|---|---|---|
| locked | 111 MB | 72 MB | 22 MB |
| vault open | 118 MB | 79 MB | 28 MB |

RSS counts the whole mapped GPU driver, which is shared with every other
accelerated app on the desktop; PSS is the fairer number for what this process
actually costs, and the anonymous column is what it allocates on its own.
Opening a vault of a thousand items adds ~6 MB.

Reproduce from another terminal while the app runs:

```bash
grep -E '^(Rss|Pss|Pss_Anon):' /proc/$(pgrep -x zann-cosmic)/smaps_rollup
```
