# Zann Desktop Architecture (Core + Native UI)

## Scope
- Desktop-first PoC with a shared Rust core.
- Future targets: iOS, Android, and possibly web.
- UI layer is native; business logic lives in Rust core.

## Goals
- Single source of truth for vault, secrets, crypto, and sync logic.
- Memory- and CPU-efficient core with streaming IO for large inputs.
- Strong security boundaries and minimal secret exposure in UI.
- Responsive UX with lazy data loading and predictable latency.

## Non-Goals (PoC)
- Full sync engine or multi-device conflict resolution.
- Web UI implementation.
- Enterprise-grade sandboxed daemon.

## Core Principles
- **In-process core via FFI** for desktop/mobile (lowest overhead).
- **Strict separation** of domain logic from storage/UI.
- **Streaming by default** for import/export and large datasets.
- **Explicit data contracts** between UI and core (stable DTOs).

## Architecture Overview

### Crate Layout (proposed)
- `crates/zann-core`:
  - Use-cases and policies (unlock/lock, list/search, update, import/export).
  - DTOs for UI/API boundaries.
- `crates/zann-crypto`:
  - KDF, encryption, key management, zeroization.
- `crates/zann-db`:
  - SQLite storage and migrations.
- `crates/zann-import`:
  - Streaming backup import/export (JSON).
- `crates/zann-sync` (later):
  - Sync engine and transport abstractions.
- `crates/zann-ffi`:
  - FFI surface (UniFFI or cxx).

### UI Layer
- Desktop native (Qt/Kirigami for KDE PoC).
- UI holds no business logic; it only calls core APIs.
- UI receives typed DTOs (no raw DB rows).

## FFI Boundary
- **Primary path**: FFI (in-process).
- **Optional**: IPC adapter for isolation mode later.

### DTOs (examples)
- `VaultStatus`, `ItemSummary`, `ItemDetail`, `FolderTree`, `ItemCounts`.
- Use only FFI-friendly types (String, Vec, Map, primitives).

### Command-style API
- `vault_unlock(passphrase) -> VaultStatus`
- `vault_lock()`
- `items_list(filter, page) -> ItemPage`
- `items_search(query, page) -> ItemPage`
- `item_get(id) -> ItemDetail`
- `item_update(id, payload) -> ItemDetail`
- `folder_tree() -> FolderTree`
- `counts_by_type() -> ItemCounts`
- `backup_import_stream(reader, options) -> Progress`
- `backup_export_stream(writer, options) -> Progress`

## Security Model
- Secrets never leave the core unless explicitly requested.
- Short-lived sensitive buffers with `zeroize`.
- All input validated in core (size limits, schema checks).
- Encryption/keys isolated in `zann-crypto` API.

## Performance Model
- Lazy fetch of item details and attachments.
- Pagination everywhere; counts served separately.
- Streaming import/export to avoid large in-memory buffers.
- Measured latency budgets:
  - List: < 50ms for first page.
  - Search: < 150ms for typical vault sizes.

## UX Guidelines (Desktop)
- Avoid blocking UI thread; all core calls async.
- Use optimistic updates with clear error recovery.
- Show progress for long operations and allow cancel.
- On low-memory, degrade gracefully (smaller page sizes).

## Testing Strategy
- Unit tests in core (use-case logic).
- Integration tests for DB + crypto.
- FFI contract tests (round-trip DTO validation).
- Perf smoke tests (import 100k items; memory cap).

## Rollout (PoC)
1) Core API facade covering unlock/list/detail/edit/import/export.
2) KDE UI with list/search/detail.
3) Streaming import/export validated on large files.
4) Perf and memory baselines.

