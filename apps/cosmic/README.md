# COSMIC PoC

Minimal COSMIC-native PoC built on [libcosmic](https://github.com/pop-os/libcosmic)
(iced).

Scope: connect to a server (password or SSO, including confirming a changed
server key) or set up a local vault, unlock it with the master password, browse
the items (nav categories, search, paging) and read a secret — masked fields
with a reveal toggle, one-time codes and copy-to-clipboard.

Not covered: creating or editing items, folders, attachments, and anything the
other clients do beyond reading.

The crate is excluded from the root workspace: libcosmic is a git dependency and
the root `Cargo.lock` must stay free of git sources (the Nix package derives its
vendoring from it).

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

## The three columns

The open vault is the same shape as the Tauri app: nav categories, the item
list, the item detail. Only the first is libcosmic's — it is the standard nav
bar, drawn by the shell from `vault::State::nav_model`, and the header bar's
toggle collapses it the way the desktop sidebar collapses.

The other two are the vault screen's own `row`, not libcosmic's context drawer.
The drawer would have done it — setting `core.window.context_is_overlay = false`
turns it into a real third column — but its width is computed, and the desktop
app lets the reader drag the boundary. So the split is ours: a `mouse_area` over
a divider starts the drag, and a window-wide subscription follows the pointer
until the button comes back up, because it leaves those few pixels immediately.

The widths in `screens::vault::layout` are the ones from the desktop app's
`useAppLayout.ts`, so the split lands in the same place in both clients, and the
window's minimum is the width at which both columns still fit their minimums.
Only the list carries a width; the detail takes what is left, and stays in place
with nothing selected so that selecting an item never reflows the list.

The shell is the one that knows how much of the window the nav bar left, so it
tells the screen through `set_content_width` rather than the screen guessing.

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
`Exec` rewritten to the absolute path, and takes the icons from the Tauri app —
one logo for the whole product rather than a second copy of the same PNGs. The
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
  `~/.zann/local.sqlite` as the other clients — including running the local
  migrations against it. That is fine while this is built from the same commit
  as the client you rely on; it stops being fine the moment you install a build
  from a branch that is ahead on schema. Point it elsewhere while testing:
  `ZANN_DB_URL=sqlite:///tmp/zann-demo/local.sqlite zann-cosmic`.

## Demo vault

To try the PoC without touching a real vault, seed a throwaway one (the
identity config is written next to the database, so give it its own directory):

```bash
mkdir -p /tmp/zann-demo
export ZANN_DB_URL=sqlite:///tmp/zann-demo/local.sqlite
export ZANN_DEMO_PASSWORD=pick-your-own
cargo run --example seed_demo_vault
cargo run
```

Both variables are required. The seed creates a real vault, so its master
password is yours to choose rather than a constant published here.

It writes a few key/value items plus one login with a masked password and a
one-time code, so the detail column has something to hide and to count down.

## Connecting without a server

`tools/mock-server` answers the endpoints a password login needs
(`/v1/system/info`, `/v1/auth/prelogin`, `/v1/auth/register`, `/v1/auth/login`,
`/v1/vaults/personal/status`), which is enough to walk the connect screen end to
end. It does not implement sync, so the pull after unlocking fails — the vault
still opens and reports it.

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
