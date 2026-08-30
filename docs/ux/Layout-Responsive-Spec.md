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

## Desktop Vault Home Contract

This section is normative for every desktop client. Toolkits may render native
controls, but they MUST preserve the same information architecture and region
ownership.

- MUST: Use the semantic order `navigation sidebar -> items list -> item detail`.
- MUST: Put storage and vault selectors in the navigation sidebar, before
  categories and folders. They are context, not list filters.
- MUST: Keep search and list pagination in the items workspace, not the
  navigation sidebar.
- MUST: Keep reveal, copy, TOTP and item actions in the detail workspace.
- SHOULD: Hide the vault selector when the current storage has only one vault;
  hiding it MUST NOT move controls between semantic regions.
- MUST: A vault switch clears stale item detail, loads the selected vault's
  first page and updates category/folder counts as one visible transition.
- MUST: Transient input state (held modifiers, hover, focus, loading hints,
  copy/reveal feedback) MUST NOT insert or remove layout rows or resize columns.
  Use an overlay, reserved slot or style-only change if feedback is necessary.
- MUST: The whole value surface is the copy target. Hover and successful-copy
  feedback SHOULD style that same surface without changing its text or geometry.
- MUST: Holding `Option`/`Alt` on macOS or `Shift` on Linux and Windows may
  reveal masked values only while held. Releasing it or losing window focus
  hides them without changing persistent reveal state. Linux and Windows MUST
  NOT bind this behavior to `Alt`, because it participates in app switching.

Tauri is the current reference implementation for region placement. It is not
the reference for widget styling: COSMIC, SwiftUI and other clients SHOULD use
their platform-native controls inside the same semantic regions.

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

## Cross-client Conformance

- A layout-affecting change MUST update this specification before or together
  with client code.
- The change MUST be checked against every shipping GUI client. Implement it in
  the same change, or record a time-bounded waiver with owner and rationale.
- Each client MUST have state-level tests for context preservation and secret
  visibility. Release UI checks SHOULD capture Vault Home at narrow, medium and
  wide desktop widths.
- Reviewers MUST verify semantic region ownership, not pixel identity. Shared
  geometry belongs in `zann-ui-core`; native widget appearance remains local.
