# Items API Unification (Decision + Plan)

## Decision (MVP)
Proceed with a unified `/v1/vaults/:vault_id/items` API driven by `vault.encryption_type`.

Rationale:
- Single API surface reduces client branching and avoids duplicated handlers.
- `vault.encryption_type` already exists and is the correct source of truth.
- Server-encrypted vaults currently require `/shared` + `/secrets` semantics; unifying on `/items` keeps payload semantics consistent per vault.

## Contract (per vault.encryption_type)

### Common
- `/v1/vaults/:vault_id/items` list returns item summaries only (no payload). No change.
- `/v1/vaults/:vault_id/items/:item_id` returns full item. Payload shape depends on `vault.encryption_type`.
- `/v1/vaults/:vault_id/items/:item_id/history` follows the same payload rule as item detail.

### encryption_type=server
- Request: `payload` is required for create/update; `payload_enc` must be absent.
- Response: `payload` is returned; `payload_enc` is omitted.
- Error: if `payload_enc` is present -> `400 payload_enc_forbidden`.
- Error: if `payload` is missing or invalid -> `400 payload_required` / `400 invalid_payload`.

### encryption_type=client
- Request: `payload_enc` (and `checksum`) are required for create/update; `payload` must be absent.
- Response: `payload_enc` is returned; `payload` is omitted.
- Error: if `payload` is present -> `400 payload_forbidden`.
- Error: if `payload_enc` or `checksum` missing -> `400 payload_enc_required` / `400 checksum_required`.

### Files
- File upload/download behavior remains unchanged, but representation checks still depend on `vault.encryption_type`.

## Migration / Deprecation Plan

Phase 0 (now):
- Document and implement conditional payload behavior on `/items`.
- Keep `/v1/vaults/:vault_id/secrets/*` and `/v1/shared/*` as compatibility endpoints.

Phase 1 (after clients adopt unified items API):
- Mark `/v1/vaults/:vault_id/secrets/*` and `/v1/shared/*` as deprecated in docs and OpenAPI.
- Add server logs/metrics for usage of legacy endpoints.

Phase 2 (later release):
- Remove legacy routes and client modules once usage is near-zero.
- Provide migration guidance and timeline in release notes.

## Client Impact

### CLI
- Replace `/v1/shared/items` reads with `/v1/vaults/:vault_id/items` (server-encrypted vaults).
- Replace `/v1/vaults/:vault_id/secrets/*` usage with `/items` for server-encrypted vaults.
- Continue to use encrypted payload flow for client-encrypted vaults.

### Desktop
- Use `vault.encryption_type` to choose payload vs payload_enc for items CRUD and history.
- Remove or gate shared/secrets-specific flows once `/items` supports plaintext for server vaults.

## Server Impact
- Items HTTP models: make `payload` optional and conditional in responses.
- Items handlers: validate payload fields by `vault.encryption_type`.
- Items history handlers: return `payload` for server-encrypted vaults.
- Shared + Secrets routes: remain in place until deprecation.

## Tests / Docs / OpenAPI
- Add tests for payload rules per encryption type.
- Update OpenAPI to document conditional payload behavior and new error codes.
- Update docs with deprecation plan for `/shared` and `/secrets`.
