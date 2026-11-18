# Linux account passkeys: development acceptance

This slice targets **Internal Auth + Linux/COSMIC + Chromium + an external
UV/PRF-capable authenticator**. Account sign-in keys are separate from website
passkeys stored inside Zann and from local DeviceUnlock hardware keys.
Other native account-ceremony providers and first-key enrollment through fresh
OIDC reauthentication remain follow-up work under #30.

## Server and browser setup

Configure a stable RP ID and exact origins in the server YAML; RP identity must
not change with a proxy Host header. For example:

```yaml
auth:
  passkey:
    rp_id: vault.example.com
    rp_name: Zann
    origins:
      - https://vault.example.com
      - chrome-extension://abcdefghijklmnopabcdefghijklmnop
```

Replace the example extension ID with the ID shown by Chromium for the installed
Zann extension. An unpacked extension's path determines its ID; allow that exact
origin explicitly. The server accepts 1–16 distinct HTTPS/localhost/extension
origins. Chromium must grant the configured RP host permission from the private
confirmation page's user gesture. Use Chromium 122 or newer; actual PRF support
also depends on the authenticator/browser combination. Full mode never silently
changes to Auth-only when PRF is missing.

Update server, native app, native host and extension together. The old immediate
`POST /v1/users/me/recovery-kit` endpoint is removed; previously issued kits have
no staged-save acknowledgement and cannot start this protocol. Issue and confirm
a new code before disabling server-password sign-in. A staged code lives in the OS
credential store only until the server confirms activation; then the client deletes
it, so the user's independent copy is the only one. Personal vault/item crypto
and DeviceUnlock `v1` formats are unchanged.

## Physical-key acceptance

Use an isolated client root and test account with a recognizable synthetic
personal item. Keep the account encryption password and current Server Recovery
Key outside Zann. Never erase a working root to perform this test.

1. Sign in normally and independently unlock the local device/account. Open
   **Settings → Security → Zann account sign-in keys**. Load keys/browsers,
   select the paired Chromium, name the YubiKey, and add it in Full mode.
   First descriptor bootstrap also asks for fresh server-password authorization.
   Open the extension for registration, then again for the discoverable test.
   Both ceremonies require PIN/user verification; a touch alone is insufficient.
2. Create a Server Recovery Key, save it outside Zann, re-enter it, and activate.
   Select “Disable server password sign-in” only with a saved code. This changes
   server login authority and does not change the local encryption password.
3. Start a separate clean native root. Probe the server, pair Chromium before
   opening a vault, choose that browser and passkey sign-in, and use YubiKey PIN.
   Configure the new device's own local protection. The Full grant opens the
   personal account key and existing personal item without sending the encryption
   password to the server or using it in the browser.
4. Repeat with explicitly selected Auth-only mode. Server login succeeds and
   local personal-vault enrollment asks once for the account encryption password.
   Missing/corrupt Full grants instead require explicit selection of that path.
5. Start recovery from Connect. Save and re-enter the generated successor code
   before consume. Consuming the old code revokes old account factors/grants and
   interactive sessions atomically. Close/reopen during the restricted operation
   and resume with the stored bundle; the burned old code is not a resume token.
6. Add and test a replacement key. Full mode proves the account encryption
   password locally against the personal wrapped key and custody descriptor.
   Complete recovery, return to sign-in and perform a fresh ordinary passkey login.
   Verify the personal item and independent DeviceUnlock. The saved successor
   code is now the current recovery code. Resuming an already registered candidate
   refreshes its discoverable test/PRF; it does not register another credential.
   Use the explicit restart control only when replacing that staged candidate.

A surviving open device can enroll a second key and revoke a lost key directly.
Revoking from this UI also invalidates sessions created by the selected key.
The server prevents removal of the last active factor through ordinary revoke.

## Self-hosted break-glass

With server configuration/DB access, use:

```sh
zann-server admin reset-recovery-key --email person@example.com --out /private/new-recovery.txt
```

The output path must be new. The CLI writes it with private permissions and
fsyncs before committing the server reset; stdout contains only receipt metadata.
This revokes old server factors/grants/sessions and supersedes active recovery,
but does not decrypt or modify personal E2EE data. Blocked/deleted accounts and
OIDC-only deployments cannot use this command to regain internal authority.

## Automated evidence and limits

Server tests cover RP origin/UV verification, public-login activation fencing,
replay, selected-factor revocation, recovery consume/supersession/expiry,
replacement testing, custody-signed grants and fresh-login completion. The real
HTTP/Postgres/native integration test drops committed consume, registration,
grant and completion replies, restarts the client facade and resolves exact
receipts; the replacement authenticator is registered exactly once. Client
journals test secret exclusion, root/pin binding and CredentialStore read-back.
The Chromium account test uses real WebAuthn with a virtual UV/PRF USB
authenticator, real WASM and Noise/native-host delivery, and negative web framing.
It does **not** qualify physical YubiKey firmware, PIN UX or hardware touch.
