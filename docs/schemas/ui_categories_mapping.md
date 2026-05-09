# UI Categories Mapping (V1)

Goal: ensure all clients (Tauri, KDE, Swift, Windows) render the same navigation categories from `schemas/ui_categories.json`.

## Client Responsibilities

- Load the schema file at build time (preferred) or runtime.
- Apply visibility rules: `when`, `requires`, and `scope`.
- Resolve labels via i18n keys (ru/en).
- Sort categories by `group` (client-defined order) -> `order` -> `id`.
- Apply the `filter` only when `view` is `items_list`.
- Use `fallback_category_id` for unknown/unsupported types.

## i18n Rules

- `labels[].key` is the default i18n key.
- If a `labels[].when` matches the current context (e.g., `scope: "shared"`), use that label.
- Missing keys fall back to the default label for the category.

## Filter Handling

- Supported fields in V1: `type_ids`, `is_deleted`, `is_favorite` with `$and/$or/$not`.
- Items list views should filter client-side unless a server index is available.
- For `view != "items_list"`, ignore `filter` and use the view behavior.

## Category Counts

- Counts are derived by applying the category filter to the current item set.
- `trash` uses deleted items only.
- `infra` aggregates multiple type IDs.

## Platform Mapping (Recommended)

- **Tauri (Vue):** map schema to the existing categories list; replace hardcoded categories with schema parsing.
- **KDE (QML):** load JSON, map to a model; bind labels through i18n layer.
- **Swift (iOS/macOS):** parse JSON into structs; map `labels` to Localizable strings.
- **Windows:** parse JSON into DTOs; bind `labels` to resource strings.

## Current V1 Categories (zann)

- `all`, `login`, `note`, `card`, `identity`, `api`, `kv`, `infra`, `trash`
