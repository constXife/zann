# COSMIC PoC

Minimal COSMIC-native PoC built on [libcosmic](https://github.com/pop-os/libcosmic)
(iced), next to the Qt/Kirigami PoC in `apps/kde`.

Scope: connect to a server (password or SSO, including confirming a changed
server key) or set up a local vault, unlock it with the master password, browse
the items (nav categories, search, paging) and read a secret — masked fields
with a reveal toggle, one-time codes and copy-to-clipboard.

Not covered: creating or editing items, folders, attachments, and anything the
other clients do beyond reading.

Like `apps/kde`, this crate is excluded from the root workspace: libcosmic is a
git dependency and the root `Cargo.lock` must stay free of git sources (the Nix
package derives its vendoring from it).

## Layout

`main.rs` is the shell and nothing else: the window, the [`Session`] and the
routing between screens. Everything else lives in the library next to it, which
is what lets `tests/flows.rs` drive the flows without a compositor.

```
src/backend/local.rs    the vault on this machine (zann-ffi)
src/backend/remote.rs   logging in against a server (zann-client)
src/session.rs          the open database, owned for the app's lifetime
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

## Prereqs

libcosmic's `rust-version` is ahead of the workspace pin in
`rust-toolchain.toml`, so this app has its own dev shell:

```bash
nix develop .#cosmic
```

## Build & Run

```bash
cd apps/cosmic && cargo run
```

Or from the repo root:

```bash
just cosmic-run
```

Optional:
- `ZANN_DB_URL` overrides the default `sqlite://$HOME/.zann/local.sqlite`.

## Demo vault

To try the PoC without touching a real vault, seed a throwaway one (the
identity config is written next to the database, so give it its own directory):

```bash
mkdir -p /tmp/zann-demo
export ZANN_DB_URL=sqlite:///tmp/zann-demo/local.sqlite
cargo run --example seed_demo_vault   # master password: demo-password
cargo run
```

The seed writes a few key/value items plus one login with a masked password and
a one-time code, so the detail drawer has something to hide and to count down.

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
