# KDE PoC

Minimal KDE-native PoC to estimate memory footprint using Qt/Kirigami.

## Prereqs

- Qt6 + Kirigami dev packages available in the dev shell.
- From repo root, enter nix dev shell:
  - `nix develop`

## Build & Run

```bash
cd apps/kde
cargo run
```

Optional:
- `ZANN_DB_URL` to override the default `sqlite://$HOME/.zann/local.sqlite`.

## E2E (Mock)

```bash
cd apps/kde
bun run e2e
```

## Memory Check

From another terminal:

```bash
ps -eo pid,comm,rss,etime --sort=-rss | head -n 15
```

Look for the `zann` process.
