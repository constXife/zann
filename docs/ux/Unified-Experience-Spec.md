# Unified Experience Specification (UX "North Star") - zann

## Metadata

- Version:
- Owners: Design / PM / Security / Engineering
- Links: Figma, implementations, epics
- Scope:

## Product Promise and Trust Goals

### Promise (3-5)

- MUST: Zero-knowledge handling.
- MUST: No data loss.
- SHOULD: No interference with system autofill.
- MUST: Always recoverable within defined policy.

### Trust goals

- MUST: Lock/unlock states are predictable.
- MUST: Sync state is transparent and never misleading.
- MUST: No fear-based messaging.
- MUST: Minimize data leakage risk.

## UX Principles (Normative)

- MUST: Secure by default without daily-use friction.
- MUST: Users always understand locked/unlocked and synced/not synced.
- MUST: No irreversible actions without warning and recovery path.
- MUST: Secrets never stay on screen/clipboard longer than policy.

## Domain Model (IA)

- Vault(s)
- Item types: Login, Card, Identity, Secure note, SSH key, Software license
- Folders/Tags
- Favorites
- Trash
- Sharing (if available)
- Devices/Sessions

## Core Journeys (End-to-End)

- First run -> create vault -> enable biometric/PIN -> import -> first item -> first autofill.
- Daily use: search -> copy -> autofill -> generate password -> save/update.
- Recovery: forgot master password (if impossible, explain); recovery key/contacts (if available); change master password.
- Device change: sign in on new device, trusted/untrusted device flow.
- Incident: suspected compromise, password changes, audit.

## Security UX Contracts (Core)

- Unlock/lock, idle timeout, biometric/PIN fallback, re-auth for sensitive actions.
- Clipboard policy.
- Screenshot/screen recording policy (platform-specific).
- Export/print/backup policy and UX.

## Autofill and Capture Contracts

- Autofill flow (account selection, domain matching precision, TOTP).
- Save/update prompts (when to save vs update, avoid spam).
- MUST: Never intercept input without explicit context.

## Sync and Conflict Contracts

- Sync states, queues, offline-first behavior, conflict resolution.
- MUST: Never show "synced" unless confirmed.

## States and Resilience

- Empty/loading/error/offline states.
- Critical states: vault corrupted, storage full, keychain unavailable, extension unavailable.
- Degradation policy: what works offline vs blocked.

## Notifications and User Feedback

- Toast/banner/dialog usage for: copied, password generated, sync stopped, biometrics unavailable, session expired.

## Content and Terminology

- Glossary: vault, master password, recovery key, device, session, autofill, extension.
- Tone: calm, no FUD; clarity over fear.

## Accessibility Baseline

- Desktop: full keyboard navigation (tables/lists/trees).
- Screen reader: do not read secrets aloud without explicit action.
- Reduced motion supported.

## Platform Adaptation Matrix

- Autofill, extensions, windowing, menus, hotkeys, system vaults, system dialogs.

## Governance

- RFCs for security UX changes.
- Exceptions (waivers).
- Release gates.

---

## Required Sections (MUST)

### A) Unlock / Lock

- MUST: Single state machine: Locked / Unlocked / Requires re-auth / Migration required.
- MUST: Policies: idle timeout, background timeout (esp. iOS), lock on app switch.
- MUST: Fallbacks: biometric -> PIN -> master password (or inverse), clear failure copy.
- MUST: Re-auth for export, reveal password, view recovery key, change master password, manage sharing, disable 2FA (if available).
- Acceptance criteria: secrets inaccessible in Locked; UI does not leak previews/recent items.

### B) Clipboard

- MUST: Clear timer and repeat-copy behavior.
- SHOULD: Block copy to unsafe targets if available.
- MUST: Unified notifications ("Copied, clears in N seconds").
- Desktop SHOULD: option to avoid clipboard history when possible.
- Acceptance criteria: clipboard is cleared/overwritten after N seconds; no persistent secret data.

### C) Reveal Secrets

- MUST: Masked by default; reveal requires explicit action; optional re-auth.
- SHOULD: "Copy instead of reveal" for high-risk scenarios.
- Acceptance criteria: password never auto-reveals on open or search.

### D) Autofill and Save/Update

- MUST: Domain matching (eTLD+1, subdomains, exceptions) and ordering.
- MUST: Fast account selection with search and domain indicator.
- MUST: Save/update rules that avoid prompt spam.
- MUST: TOTP display/copy with timer.
- Acceptance criteria: at least one end-to-end flow per platform documented (Safari/Chrome/iOS/Windows).

### E) Sync and Conflicts

- MUST: Clear states: Synced / Syncing / Needs connection / Paused / Error / Conflict.
- MUST: Conflict strategy (last-write-wins vs merge) and resolution UX.
- Acceptance criteria: user sees whether a change is local vs uploaded.

### F) Destructive Actions and Recovery

- MUST: Trash vs hard delete, recovery window, warnings.
- MUST: Export/backup warnings, format, encryption (if available).
- Acceptance criteria: vault cannot be lost without two-step confirmation and consequences.
