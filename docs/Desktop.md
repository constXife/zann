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

## Remembered unlock

"Remember unlock on this device" stores the master key encrypted with a random
device key. That device key is kept in the OS credential store — Keychain on
macOS, Credential Manager on Windows, Secret Service (gnome-keyring, KWallet) on
Linux — and never in the app's own files.

- Without a working credential store the option cannot be enabled: there is no
  file fallback, so the master password stays the only way in.
- On Linux this means a Secret Service provider must be running in the session.
- "Require OS authentication" adds a biometric prompt where the platform offers
  one. It gates the app, not the stored key: no backend currently binds the
  device key to a biometric ACL.
- Upgrades from earlier versions move the device key out of `desktop.json` on
  first launch. If it cannot be moved, the remembered unlock is dropped and you
  are asked for the master password again.

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

## Tips

- Keep the desktop app updated for security fixes.
- Use a strong device unlock password and OS keychain protections.
