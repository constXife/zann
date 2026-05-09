# Layout and Responsive Behavior Spec - zann

## Goals and Invariants

- MUST: Preserve the information architecture (vaults/shared vaults, list, details, status) at any width.
- MUST: Keep primary actions reachable: search, create, sync status, lock/unlock.
- MUST: Status clarity (sync/lock/conflict) is always visible without deep navigation.
- SHOULD: Keep "where am I" context (selected vault/item) across layout changes.

## Primary Surfaces

- Phone portrait
- Phone landscape
- Tablet (compact/regular)
- Desktop narrow
- Desktop medium
- Desktop wide

## Panels and Roles

- Navigation: vaults, shared vaults, alerts, audit.
- Items list: item rows, filters, selection, conflict badges.
- Detail view: item fields, reveal/copy actions, TOTP, attachments (if/when enabled).
- Inspector / right rail: metadata, history, audit, participants, sync status.
- Global toolbar: search, create, sync status, lock/unlock.

## Breakpoint Rules (Layout Table)

| Surface | Navigation | Items list | Detail view | Inspector/right rail | Global toolbar |
| --- | --- | --- | --- | --- | --- |
| Phone portrait | Collapsed to top-level menu | Full-screen list | Full-screen detail (push) | Hidden or modal | Sticky top |
| Phone landscape | Drawer/overlay | Full-screen list | Full-screen detail (push) | Hidden or modal | Sticky top |
| Tablet compact | Collapsible sidebar | List + detail (stacked) | Primary area | Hidden or modal | Top |
| Tablet regular | Sidebar visible | List + detail (split) | Primary area | Optional rail | Top |
| Desktop narrow | Sidebar collapsible | List + detail (split) | Primary area | Hidden or modal | Top |
| Desktop medium | Sidebar visible | List + detail (split) | Primary area | Right rail visible | Top |
| Desktop wide | Sidebar visible | List + detail (split) | Primary area | Right rail persistent | Top |

## Transitions and Context Preservation

- MUST: Keep selected vault and item when resizing/rotating.
- MUST: Preserve list scroll position on layout change.
- SHOULD: Keep detail scroll position when the detail view remains visible.
- MUST: Open modals remain open and centered across resize.
- SHOULD: If a panel collapses, preserve its state for when it reopens.

## Density, Typography, and Truncation

- MUST: Minimum hit target size applies in all layouts.
- SHOULD: Prefer truncation with tooltips in dense views; allow wrapping in detail view.
- MUST: Define minimum column widths for list/table layouts; avoid zero-width columns.
- SHOULD: Use compact/comfortable density presets on desktop if supported.

## Security Constraints

- MUST: Secrets remain masked by default in all layouts.
- MUST: No auto-reveal on resize, rotate, or layout switch.
- SHOULD: Avoid showing sensitive columns (e.g., password/TOTP) in narrow list modes.
- MUST: Clipboard/reveal actions require explicit user action in all layouts.
