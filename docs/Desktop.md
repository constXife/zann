---
title: Desktop Guide
description: Desktop app usage and local/offline workflow.
---

## Overview

The desktop app is the primary client for people. It supports offline-first
personal vaults and can optionally connect to a server for shared vaults.

## Install

Download the desktop app from GitHub Releases.
If you need to build locally:

```bash
cd apps/desktop
bun install
bun run tauri build
```

## Local usage (no server)

- Create a personal vault and store secrets locally.
- The app works offline-first.

## Shared vaults (with server)

- Connect to a server to access shared vaults.
- Use the server for multi-user access and policy enforcement.

## Linux notes

On Linux the app renders through the **system WebKitGTK** (`libwebkit2gtk-4.1`),
not a bundled engine and not your default browser. Your default browser only
matters when the app opens an external link.

**Wayland viewport workaround.** Under native Wayland the GTK3 webview surface
can be allocated incorrectly (`window.innerWidth/innerHeight` come back negative,
the page becomes unusable). This is independent of the WebKitGTK version and is
tracked upstream in [wry#1727](https://github.com/tauri-apps/wry/issues/1727).
To avoid it, on a Wayland session the app forces XWayland by setting
`GDK_BACKEND=x11` before GTK initializes.

- If native Wayland works for you, opt back in by exporting `GDK_BACKEND=wayland`
  before launching — the app respects an explicit value.
- This workaround is removed once tao's GTK4 port
  ([tao#1104](https://github.com/tauri-apps/tao/pull/1104)) ships in a release.

## Upgrading

### "Remember unlock" key moved into the OS keystore — action required

Builds before this change stored the key that unwraps your master key (the DWK)
in cleartext inside `~/.zann/desktop.json`, right next to the master key it
unwraps. Anyone who could read that one file could recover the master key without
your password and without biometrics.

The DWK now lives in the platform credential store (Keychain on macOS, Credential
Manager on Windows, Secret Service on Linux). On first launch the app migrates any
existing key automatically and rewrites `desktop.json` without it. If the keystore
is unavailable, "remember unlock" is reset and you unlock with your master password
instead.

**Updating is not sufficient on its own.** The migration cleans the file on this
machine; it cannot reach copies that already left it. `desktop.json` sits in
`~/.zann` next to `local.sqlite`, so any backup, filesystem snapshot or synced
folder (Dropbox, iCloud Drive, Syncthing, …) that captured the directory while
"remember unlock" was on contains both the key and the data it opens.

If that describes you, assume the vault contents in those copies are readable and
**rotate the secrets themselves** — change the stored passwords at the services
they belong to. There is currently no master-password re-key flow in the app, and
even if there were it would not help: the leaked copy is a self-contained snapshot,
so nothing you change now retroactively protects it. Deleting the affected backups
is worth doing too, but rotation is what actually closes the exposure.

Turning "remember unlock" off and on again after upgrading generates a fresh DWK,
which is worth doing so the old one is no longer live — but do that in addition to
rotation, not instead of it.

If "remember unlock" was never enabled, no DWK was ever written and there is
nothing to do.

## Tips

- Keep the desktop app updated for security fixes.
- Use a strong device unlock password and OS keychain protections.
