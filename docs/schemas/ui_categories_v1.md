# UI Categories Schema (V1)

Below is the compact, approval-ready summary of the `schemas/ui_categories.json` contract.

## V1: Top-Level

```json
{
  "schema_version": 1,
  "min_client_version": "0.8.0",
  "updated_at": "2026-01-26T00:00:00Z",
  "fallback_category_id": "other",
  "categories": []
}
```

## Semantics

- `schema_version` defines the schema version (not data). Clients MUST ignore unknown fields.
- `min_client_version` guards against incompatible changes.
- `updated_at` is for debugging and caching.
- `fallback_category_id` is the "unknown/other" bucket (optional but recommended).

## V1: Category Structure

```json
{
  "id": "login",
  "labels": [
    { "key": "nav.logins" },
    { "when": { "scope": "shared" }, "key": "nav.loginsShared" }
  ],
  "icon": "key",
  "view": "items_list",
  "scope": "both",
  "group": "items",
  "order": 20,

  "when": {
    "platforms": ["desktop"],
    "feature_flags": ["audit_enabled"],
    "min_tier": "team"
  },
  "requires": ["can_view_logins"],

  "filter": {},

  "badge": { "counter": "alerts_count", "style": "danger", "max_display": 99 },

  "shortcut": { "default": "Ctrl+2", "macos": "Cmd+2" },

  "empty_state": {
    "title_key": "empty.logins.title",
    "description_key": "empty.logins.description",
    "primary_action": { "route": "create_item", "params": { "type_id": "login" } }
  }
}
```

## Required Fields (MUST)

- `id` (unique, stable)
- `labels[].key` (i18n key)
- `icon` (enum from the icon allowlist)
- `view` (enum)
- `scope` (`personal|shared|both`)
- `group` (string/enum)
- `order` (number; sorting)

## Optional (SHOULD)

- `when` visibility conditions (platforms/feature_flags/tier)
- `requires` permissions/capabilities (category hidden if unmet)
- `filter` only when `view: "items_list"`
- `badge`, `shortcut`, `empty_state`

## V1: `view` Allowlist (Minimal for zann)

- `items_list` (list of items with `filter`)
- `trash` (recommended distinct view for clarity)
- `alerts`
- `audit`
- `settings`
- Optional later: `sync_status`, `shared_vaults`

Rule: if `view` is not `items_list`, `filter` MUST be absent (preferred) or MUST be ignored.

## V1: `FilterExpr` (Restricted Bool DSL)

Supported operators:

- `$and`: `FilterExpr[]`
- `$or`: `FilterExpr[]`
- `$not`: `FilterExpr`

Supported leaf predicates (allowlist):

- `type_ids`: `["login", "card", "*"]`
- `is_deleted`: `true|false`
- `is_favorite`: `true|false`

Example:

```json
{
  "$and": [
    { "is_deleted": false },
    {
      "$or": [
        { "type_ids": ["login"] },
        { "is_favorite": true }
      ]
    }
  ]
}
```

## Deterministic Render Rules (V1)

- Sort order: `group` (by fixed `group_order` on the client) -> `order` -> `id`.
- Unknown `icon`/`view`/`filter` fields are ignored unless the client chooses to drop the category.
- Category is shown if:
  - `when` passes (if present),
  - `requires` passes (if present),
  - and it matches the current `scope`.
