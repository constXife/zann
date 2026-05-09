# UX Documentation Set

Goal: define the mandatory, recommended, and governance documents so the unified experience and quality are reproducible.

## 1) Mandatory Documents

### A. Unified Experience Specification (UX "North Star")

Goal: establish the unified experience and platform adaptation rules so teams can decide without constant alignment.

Document requirements

- Normative language: MUST/SHOULD/MAY with clear boundaries between required and allowed.
- Cross-platform: describes the product as a behavior system, not a single-platform screen set.
- Testable: every rule can be verified (checklist/acceptance criteria).
- Conflict resolution: explicit priorities (e.g., security/data integrity > accessibility > platform conventions > visual consistency).
- Versioning: version, date, owner, changelog, and change process.
- Adaptation matrix: explicit decisions "unified / adaptable / platform-specific" for key UX areas.
- Backlog linkage: rules connect to epics/components/patterns so changes are not "in a vacuum".

Artifacts inside

- UX principles (5-10).
- Unified product model (IA, entities, navigation, states).
- Behavior spec: errors/loading/empty/offline/undo/search/selection/hotkeys.
- Content style (tone of voice, glossary).
- Minimum A11y requirements.

### B. Design System Spec (Tokens + Components + Patterns)

Goal: a unified visual language and predictable UI assembly across technologies.

Document requirements

- Single source of truth for tokens: semantic tokens (roles), not "just colors".
- State coverage: normal/hover/pressed/disabled/focus/error/success/loading.
- Component contracts: purpose, behavior API, constraints, variations.
- A11y per component: focus, keyboard, screen reader, contrast.
- Platform mappings: how tokens/components map to SwiftUI/AppKit, WinUI, Qt/KDE.
- Usage enforcement: rules for when a component can be bypassed and how it is documented.

Artifacts inside

- Token taxonomy (color/typography/spacing/radius/elevation/motion).
- Component library + patterns (forms, dialogs, notifications, tables/lists, settings).

## 2) Recommended Documents

### C. Platform Appendices (one per platform)

Goal: preserve native expectations without diluting the unified experience.

Requirements

- Focus on differences: only where the platform mandates a different pattern.
- Windowing and navigation rules: especially for macOS/Windows/Linux.
- Hotkeys and interactions: standard shortcuts, context menus, drag and drop.
- System integrations: share sheet, file pickers, permissions, tray/menu bar.

### D. Content and Localization Guidelines

Goal: a consistent product voice and predictable copy across platforms.

Requirements

- Term glossary: "how we name the same thing" in UI.
- Message templates: errors, confirmations, empty states.
- Localization constraints: string length, line breaks, numbers, date/time formats.

## 3) Governance Documents (to prevent sprawl)

### E. Quality Gates (UX/A11y Acceptance Criteria)

Goal: turn "intentions" into release criteria.

Requirements

- Checklists by area: navigation, forms, errors, loading, keyboard, SR, themes, densities.
- UX Definition of Done: without it, the feature is not done.
- Regression criteria: what must not get worse with changes.

### F. Decision Log / RFC Archive

Goal: record contentious decisions and their rationale.

Requirements

- Short format: context -> options -> decision -> consequences.
- Tagging: component/pattern/platform.
- Linking from core documents: every rule has a "why".

## 4) Cross-Cutting Requirements for All Documents

- Execution-oriented: engineers can implement without guessing.
- Consistent terms: shared terminology across UX, UI, and engineering.
- Concrete examples: at least one "right / wrong" example for key rules.
- Structured: table of contents, anchors, fast search, decision tables.
- Ownership and upkeep: owners, review cadence (e.g., quarterly), change process.
- Traceability: link to design source (Figma) and implementation (repo/package), if any.

## 5) Minimal "Set That Actually Works" (if starting compact)

- Unified Experience Spec.
- Design System (tokens + components).
- Quality Gates (DoD/checklist).
- Platform Appendices (at least short ones).
