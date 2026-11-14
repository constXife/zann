# Native Client Window Map

Goal: define platform-neutral windows and flows for COSMIC and Apple clients.
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
- Protect encrypted cached vault content.
- Gate all sensitive UI until unlock succeeds.

Entry:
- App start when a server replica has cached vaults.
- Manual lock action.
- Auto-lock (timeout or OS session lock).

Primary actions:
- Unlock all enrolled accounts with the device-local Zann password.
- Show failed attempt error.
- Access "forgot password" guidance (no recovery of encrypted data).

Exit:
- Successful unlock -> Vault Home.

### 2) Welcome / First Run

Purpose:
- Connect a fresh device to its server.

Entry:
- App start without a synced server replica.

Primary actions:
- Enter the server address.
- Sign in or register using the methods that server offers.

Exit:
- After authentication -> create/unlock Zann -> one-time account key enrollment -> Vault Home with background first sync.

### 3) Account Registration and Key Enrollment

Purpose:
- Create an account on the selected server, then unlock its local replica.

Entry:
- From Welcome / First Run.

Primary actions:
- Register with the server if needed.
- Create or enter the device-local Zann unlock password.
- For an account not enrolled on this device, enter its existing encryption password or create one for a new account; the shared core derives and verifies its independent account key.
- Already-enrolled accounts require no additional password after Zann unlock.
- Open cached content while the first sync runs; no local-only vault is created.

Exit:
- Success -> First Sync -> Onboarding.
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
- Select storage and vault from the navigation sidebar.
- Browse categories/folders and items.
- Create, edit, delete items.
- Search.
- Sync with the server when connected; keep offline edits pending.
- Open settings.

Exit:
- Lock action -> App Lock.
- Forget connection -> retain the disconnected offline replica; reconnect from Settings.

### 7) Import Flow

Purpose:
- Bring data into the vault (CSV, 1Password, Bitwarden, etc).

Entry:
- From Settings after syncing a destination vault.

Primary actions:
- Select source format.
- Choose file and an explicit server storage destination.
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
