# Client Window Map (Tauri reference)

Goal: provide a concrete, platform-agnostic window map based on the current Tauri app.
Use this as a reference when building a new client for another platform.

This is about windows and flows, not visual design details.

## Principles

- Minimal window count: reuse windows with states where safe.
- Security first: locked state should never leak sensitive content.
- Clear entry/exit criteria: each window has explicit entry and exit conditions.
- Cross-platform names: use the same window names in all clients.

## Windows and flows

### 1) App Lock (locked state)

Purpose:
- Protect local vault content.
- Gate all sensitive UI until unlock succeeds.

Entry:
- App start when a local vault exists.
- Manual lock action.
- Auto-lock (timeout or OS session lock).

Primary actions:
- Unlock with master password.
- Show failed attempt error.
- Access "forgot password" guidance (no recovery of encrypted data).

Exit:
- Successful unlock -> Vault Home.

### 2) Welcome / First Run

Purpose:
- First-time entry point when no local vault exists.

Entry:
- App start with no local vault.

Primary actions:
- Create local vault (internal auth).
- Connect to server (OIDC) for shared vaults.
- Import from file (if supported).

Exit:
- After vault creation -> Onboarding.
- After OIDC connect and first sync -> Onboarding (or Vault Home if onboarding skipped).

### 3) Internal Registration (local vault creation)

Purpose:
- Create a local vault with internal credentials.

Entry:
- From Welcome / First Run.

Primary actions:
- Set master password.
- Confirm password.
- Optional: set vault name.

Exit:
- Success -> Onboarding.
- Cancel -> Welcome / First Run.

### 4) OIDC Authorization (server connect)

Purpose:
- Authenticate with external IdP and bind the client to a server.

Entry:
- From Welcome / First Run or Settings (Add server).

Primary actions:
- Start OIDC login in system browser.
- Handle redirect callback.
- Select or confirm server target.

Exit:
- Success -> Onboarding or Vault Home (if already onboarded).
- Failure -> Return to entry point with error.

### 5) Onboarding

Purpose:
- Introduce key concepts and set baseline preferences.

Entry:
- After first vault creation or first server connect.

Primary actions:
- Guided steps (short list, skippable).
- Set basics: theme, auto-lock timeout, sync behavior (if server).
- Offer import (optional) if not done.

Exit:
- Completion or skip -> Vault Home.

### 6) Vault Home (main app window)

Purpose:
- Primary workspace for viewing and editing items.

Entry:
- After unlock or onboarding.

Primary actions:
- Browse vaults and items.
- Create, edit, delete items.
- Search.
- Sync (if server).
- Open settings.

Exit:
- Lock action -> App Lock.
- Logout/disconnect -> Welcome / First Run.

### 7) Import Flow

Purpose:
- Bring data into the vault (CSV, 1Password, Bitwarden, etc).

Entry:
- From Welcome / First Run or Settings.

Primary actions:
- Select source format.
- Choose file.
- Preview and confirm import.

Exit:
- Success -> Vault Home.
- Cancel -> Previous window.

### 8) Settings

Purpose:
- Manage security, sync, and account settings.

Entry:
- From Vault Home.

Primary actions:
- Change master password.
- Auto-lock settings.
- Server connection management (OIDC connect/disconnect).
- Export/backup.

Exit:
- Close -> Vault Home.

## Notes for new clients

- Keep window names consistent in code and docs for cross-platform parity.
- If the platform uses navigation stacks instead of windows, map each window to a primary route/state.
- Preserve entry/exit conditions as acceptance criteria.
