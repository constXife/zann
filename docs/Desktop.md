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

## Tips

- Keep the desktop app updated for security fixes.
- Use a strong device unlock password and OS keychain protections.
