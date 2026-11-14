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
- Global toolbar: search, create, lock/unlock; sync status may sit here or beside the sidebar vault context.

## Desktop Vault Home Contract

This section is normative for every desktop client. Toolkits may render native
controls, but they MUST preserve the same information architecture and region
ownership.

- MUST: Use the semantic order `navigation sidebar -> items list -> item detail`.
- MUST: Put storage and vault selectors in the navigation sidebar, before
  categories and folders. They are context, not list filters.
- MUST: Keep search and list pagination in the items workspace, not the
  navigation sidebar.
- Native shells MAY place the storage sync indicator beside the sidebar's
  server/account selector. macOS uses two rows: server/account with sync above,
  vault below. Details and sync actions open in a popover; a single vault
  shows its name instead of a selector.
- macOS opens cached content before network synchronization finishes. Sync
  progress stays in the server indicator; errors and recovery actions belong
  to its popover, without blocking the workspace or inserting a status banner.
  Server/vault selectors remain usable during network sync. Progress belongs
  to the storage being synced; completion must preserve explicit navigation,
  including when the user leaves a context and returns before an old read ends.
- On a new device, macOS shows an explicit first-sync explanation before the
  first cache exists. Committed catalog metadata exposes server/vault navigation
  immediately; committed pull pages progressively populate the current list.
  An unfinished first pull must not be presented as an empty vault. Subsequent
  background sync keeps the compact sidebar indicator and usable cached content.
- macOS keeps the detail layout stable while replacing an item. Retained
  content is masked and inactive until the requested item is ready; reveal and
  copy feedback never carry across selections.
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

COSMIC is the reference client for region placement. SwiftUI and other native
clients SHOULD use platform-native controls inside the same semantic regions.

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
- SHOULD: An item list row shows a caption under its title: the item's
  subtitle (who or where it is for, e.g. a login's username or host), then
  its folder, as `zann-ui-core::item_caption` joins them; never the full path
  that repeats the title, and never a secret field. The core takes the
  subtitle from non-secret payload fields (`zann-core::item_subtitle`).
- SHOULD: When the detail column is too narrow for a label beside its value,
  every field row puts its label above the value; rows never mix the two.

## Security Constraints

- MUST: Secrets remain masked by default in all layouts.
- MUST: A masked value shows `zann-ui-core`'s fixed-width `MASKED_VALUE`,
  never a mask whose length follows the secret.
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

## Item editing and history in native desktop clients

- Create/edit and history occupy the detail workspace while preserving the
  navigation and list columns. COSMIC and Apple render native forms and
  history controls in the same semantic region.
- Field templates come from `schemas/item_fields.json`. Draft validation and
  payload construction for Rust clients belong to `zann-ui-core::item_editor`.
- Duplicate or invalid field keys prevent submission. Editing preserves typed
  field metadata and payload extras. Unmasked multiline fields use a text area.
- Editor reveals use the configured auto-hide timer and hide on window focus
  loss. Locking destroys the draft; stale asynchronous completions cannot put
  a previous screen's secrets into the new screen.
- Restoring a history version requires explicit confirmation. Selecting another
  version discards its previous preview before loading the new one.
- Closing a desktop window to tray follows its configured preference. If the
  tray becomes unavailable, a hidden COSMIC window is reopened; the configured
  lock-on-hidden policy applies before closing the window.
- macOS keeps running when its window closes and provides Open, Lock and Quit
  through its menu-bar icon. Opening restores the single main window; idle
  lock and clear-on-exit remain active while no window is visible.
