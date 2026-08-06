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

## The header bar's menu

COSMIC has no global menu bar — its apps keep theirs in their own header, beside
the nav-bar toggle, and `header_start` is where this one goes. Lock, Settings
and Quit live there because they act on the app rather than on whatever screen
is showing; locking sat in the item list's toolbar first, where it read as an
action on the list.

The menu prints the shortcut beside each item but does not listen for it, so the
`subscription` matches `menu::KeyBind` itself. `KeyBind::matches` falls back to
the physical key, which is what keeps Ctrl+L working on a layout where that key
does not produce an `l`.

Lock stays in the menu while the vault is shut, disabled rather than hidden, so
the menu does not change shape between screens.

## The sidebar

The desktop app stacks three things in that column: which vault, the categories,
the folders. libcosmic's nav bar covers only the middle one, and the folders
cannot simply join the categories in its model — a nav bar has one selection,
while a folder *narrows* whatever category is showing rather than replacing it,
the way it does in `useAppItemFilters.ts`.

So `nav_bar` is overridden and the categories keep the stock widget inside it,
with the vault picker above and the folder tree below. The tree comes from
`zann_ui_core::build_folder_tree`, which the desktop app already used; the two
selections stay independent and `ItemFilter` composes them, along with the
search. The stock widget paints its own background through `into_container`,
which building it into a column bypasses, so `nav_bar_style` is applied again
around the whole column.

The vault picker only appears when there is a choice — one vault needs no
dropdown. Switching is the shell's: it owns the session, so the screen reports
`Outcome::SwitchVault` rather than reaching for the facade.

## Where the reader left off

`cosmic.json` also keeps the splitter's width, the selected category and the
selected folder, so the app opens where it was left. Restoring a folder unfolds
the path down to it, or the selected row would be hidden inside a closed parent.

Two of the desktop's are deliberately not kept: the search query and the
selected item. Both record what someone went looking for, and neither is worth
writing to disk to save a click. A place is only written when it actually
changes, because dragging a splitter reports on every pixel.

## Shortcuts and the palette

The header menu's three keys are joined by four more that need an item to act
on — copy the primary secret, reveal every field, focus the search, open the
palette — so they live in `key_binds` without a menu entry. The palette is where
they are named instead, because it only offers them when there is something to
act on.

The palette is a `dialog`, which libcosmic draws above everything including the
settings. It holds only a query and where the highlight sits: the commands are
carried out by the shell, and the items are rebuilt from the vault on every
draw, so it can never offer a row the list no longer has. It narrows the same
set the list is showing rather than reaching past the category and folder.

While it is up it takes the arrows and Escape, which the key binds must not, or
`/` would fight with typing a query.

## Copying, and what a copy leaves out

A single field copies as it is. The three bulk copies — `.env`, JSON, raw —
follow the desktop app: the first two name every field but write `<protected>`
where a masked one would go, and say how many they held back; raw is the payload
as the vault stores it, secrets and all, which is what the button says. That
distinction is the point, so `Detail` keeps the raw payload alongside the fields
it parsed out of it.

Every copy now says so. Toasts go through `widget::toaster`; before them a copy
was silent and an error was small text at the bottom of a column.

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

## The tray

COSMIC has no tray of its own. The panel's status area is a StatusNotifierItem
host, so `src/tray.rs` puts an SNI on the session bus with `ksni` and the panel
picks it up — the icon resolves by name, which is why it is the app id the
hicolor icons are installed under. Add the "Status area" applet to the panel or
there is nowhere for it to appear.

The close button then hides instead of closing. Wayland has no way to unmap a
window and map it back — winit's `set_visible` is a no-op there — so hiding
destroys the window and showing builds a new one. Nothing is lost with it: all
the state, including the unlocked `Session`, lives in `App` rather than in the
window. The process survives with none because libcosmic runs as an iced daemon
and `Settings::exit_on_close(false)` stops it exiting when the main window goes.

Two paths lead into the same message. The header bar's close button arrives
through `Application::on_app_exit`, whose returning `Some` is what stops
libcosmic closing the window itself; a close from the compositor arrives as an
ordinary `window::Event::CloseRequested` once the window is no longer allowed to
act on one by itself.

If nothing on the bus will take the icon, `tray::start` says so and the close
button is left alone — a window with nowhere to go and no way back would leave
a process the user cannot reach.

Whether it hides or quits is a setting, so neither the header button nor the
compositor decides it — both come back as one message and the shell reads the
preference then.

## Settings

`src/settings.rs` carries the desktop app's `DesktopSettings` names and its
defaults, so "auto-lock after 10 minutes" means the same thing in both clients.
The file is not shared: `desktop.json` holds a wrapped master key and a biometry
backup this app cannot produce, and a round trip through a struct without those
fields would drop them, so this one writes `cosmic.json` beside it.

The screen is `screens/settings.rs`, reached from the gear in the header bar and
from the tray. It is drawn with `widget::settings::section`, the same rows
cosmic-settings uses, and it lays over whatever is underneath instead of
replacing it — opening it must not throw away the vault's list and its scroll.

Three of the desktop's five tabs are here, and the two that are missing are
missing for a reason rather than for now:

- **Backups** sits on `backup_export_file` / `backup_import_file`, which
  `zann-ffi` answers with `Unimplemented`. The desktop does that work on its own
  side, so there is nothing for this client to call.
- **The keystore block** under Security — remember, auto-unlock, Touch ID — is
  inert on Linux for *both* clients: `zann-keystore` implements macOS and
  answers `supported: false` everywhere else, which is what greys the whole
  block out in the desktop app too.

Accounts is here but thinner than the desktop's: listing storages and syncing
one go through the facade, while sign-out, clear-data and factory-reset are
Tauri-side commands with no `zann-ffi` behind them.

Language is one of them. The strings come from `i18n/` at the repo root, which
the desktop app loads into `vue-i18n` and this one reads through
`zann_ui_core::i18n` — one catalogue rather than two that drift. `screens/*.rs`
ask for them by the dotted keys the JSON nests, so a string added for one client
is one the other can already ask for by the same name, and the nav categories
finally use their `schemas/ui_categories.json` label keys as the catalogue keys
they always were. Unset means whatever `LC_ALL`/`LC_MESSAGES`/`LANG` asks for.

Nothing checks those keys at compile time, so `every_key_the_app_asks_for_is_in_the_catalogue`
does it instead: it reads the sources, picks out anything key-shaped, and fails
on one the catalogue has never heard of.

Everything that is here is wired, not just drawn. Idle is measured from discrete
input — keys, clicks, the wheel — rather than from the pointer crossing the
window, because a mouse nudged by a cat is not someone reading their vault and
believing otherwise would cost a redraw per motion event.

The clipboard and the reveal both hand a timer to the runtime, and a task once
handed over cannot be called back. Both therefore carry a count: a timer that
fires for a copy or a reveal that has since been replaced recognises itself and
does nothing.

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
