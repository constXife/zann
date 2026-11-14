# ADR 0008: Device unlock — session vs persistent lifetime, FIDO2 PIN verification, and unified authenticator ports

- **Status:** Proposed
- **Proposed:** 2026-11-09
- **Scope:** `zann-keystore`, `zann-client::app::local`, `zann-client-sqlite`,
  `zann-ffi`, `apps/cosmic`, `apps/apple`, and future Android shells of
  [ADR 0002](0002-client-strategy.md)
- **Related:** [ADR 0001](0001-shared-client-core.md),
  [ADR 0002](0002-client-strategy.md), [ADR 0006](0006-passkey-provider.md),
  [#146](https://github.com/constXife/zann/issues/146),
  [#147](https://github.com/constXife/zann/issues/147),
  [#149](https://github.com/constXife/zann/issues/149)

## Implementation status

The Tauri application was retired in #249; its findings in the historical
context below are no longer active work items.

The context below records the proposal-time diagnosis, not a fresh audit of
every listed defect. As of 2026-11-13, `zann-keystore::HardwareAuthenticator`,
injected `LocalVaultPorts`, two-phase enrollment and structured unlock errors
already exist. The pseudocode below proposes extensions to those owners; it
must not create parallel ports or a second enrollment flow.

Unlock lifetime and PIN/UV policy remain proposed. In particular, the
`SessionOnly` slot-key design needs a demonstrated re-arming mechanism: after
process restart, the master password alone cannot recover a slot key wrapped
only by the token's DWK. Resolve that key-availability question before
implementation, without persisting the plaintext slot key or weakening the
hardware factor.

[ADR 0010](0010-device-unlock-account-keys.md) changes remembered key material
from the account master key to a stable device root. The lifetime and UV/PIN
proposal below remains proposed; its historical references to a global master
key do not define the current account-key model.

## Context

[#147](https://github.com/constXife/zann/issues/147) and
[#148](https://github.com/constXife/zann/pull/148) introduced two ways to
unlock a local vault without retyping the master password:

1. **`UnlockSource::Keystore`** — wraps the 32-byte master key (`ChaCha20-Poly1305`,
   AAD `zann:dwk:wrap:v1`) with a random device wrapping key (DWK) stored in the
   OS credential store (`keyring`).
2. **`UnlockSource::HardwareKey`** — wraps the master key with a DWK derived on
   every unlock from a FIDO2 authenticator's `hmac-secret` extension
   (`RP_ID = "zann.local"`, `blake3::derive_key` over the 32-byte HMAC output).

Using this in daily practice exposed three architectural and security problems
and six concrete UX defects.

### 1. A touch on a standard YubiKey proves presence (`UP`), not identity (`UV`)

Biometric authenticators (Touch ID, Face ID, Windows Hello, YubiKey Bio) combine
user presence (`UP`) and user verification (`UV`) in one gesture: a stranger next
to the machine cannot touch the sensor and pass.

A standard FIDO2 security key (e.g., YubiKey 5 Series) has a capacitive touch
sensor, not a fingerprint reader. Because `crates/zann-keystore/src/fido.rs:130`
calls `.without_pin_and_uv()`, any human finger satisfies the assertion. When
the key stays plugged into a dock or laptop port:

- **In a shared office, coworking space, or household:** anyone who walks past
  while the user is away can touch the key and open the vault.
- **Across a reboot or power-off (cold start):** because `wrapped_master_key` is
  always written to `unlock.json` on disk, a laptop stolen or seized while
  powered off—with the YubiKey in the bag or port—unlocks on first boot with a
  single touch and zero knowledge factors.

Conversely, a user living alone with a desktop machine genuinely wants
single-touch convenience, and forcing a PIN on every idle re-unlock for that
user only teaches them to disable auto-lock. One fixed policy cannot serve both
threat models.

### 2. Platform dependencies point outward and split `Keystore` from `fido`

- `crates/zann-keystore/src/lib.rs` defines `pub trait Keystore: Send + Sync` for
  byte-stored DWKs, but `crates/zann-client-sqlite/src/local_vault/unlock.rs:39`
  hardcodes `default_keystore()` rather than accepting an injected port.
- `KeyringKeystore` stores the DWK in the generic OS store with
  `biometrics_available: false`. In `apps/desktop/src-tauri/src/services/session.rs:299`,
  Touch ID is an in-process UI gate (`tauri_plugin_biometry`) ahead of a plain
  Keychain read rather than a `SecAccessControl` (`kSecAccessControlBiometryCurrentSet`)
  hardware ACL in the Secure Enclave ([#146](https://github.com/constXife/zann/issues/146)).
- `crates/zann-keystore/src/fido.rs` has no trait at all: `enroll`, `derive_dwk`,
  and `is_present` are free functions calling `ctap-hid-fido2` over raw USB HID
  behind `#[cfg(any(target_os = "linux", target_os = "macos"))]`.
  - Unprivileged processes on Windows cannot open raw FIDO HID devices and must
    go through `webauthn.dll`.
  - Native Apple (`apps/apple`) and Android (`apps/android`) shells consuming
    `zann-ffi` ([ADR 0002](0002-client-strategy.md) §1) cannot inject platform
    biometric or passkey/CTAP providers across the FFI boundary.
  - Headless flow tests in `apps/cosmic` and `zann-client-sqlite` cannot test
    hardware-key enrollment, unlock, or auto-lock presence polling without a
    physical token attached.

### 3. Six UX defects in the current implementation

1. **Silent two-touch enrollment:** `fido::enroll` (`fido.rs:127-144`) performs
   `make_credential` (touch 1) followed immediately by `derive_dwk_with`
   (touch 2, proving `hmac-secret` works) inside a single blocking call. Both
   COSMIC and Tauri display one static string (`"Insert the key and touch it…"`).
   Users touch once, assume enrollment finished, and wait 30 seconds for a
   timeout error.
2. **Hardcoded `"Hardware key"` labels:** Both `apps/cosmic/src/screens/settings.rs:204`
   and `apps/desktop/src/components/settings/SettingsTabSecurity.vue:46` pass
   `""` as the label. Enrolling a primary and a backup key produces two
   indistinguishable `"Hardware key"` rows (and Tauri omits `enrolled_at`).
3. **Hardware-key wait blocks password entry in COSMIC:** In
   `apps/cosmic/src/screens/master.rs:87-166`, auto-triggering
   `unlock_remembered` sets `self.busy = true` for the entire 30-second CTAP
   touch timeout, disabling the master-password `Submit` button until the token
   times out.
4. **Raw error strings in COSMIC:** `LocalVault` flattens `UnlockError` into
   `LocalError::Service(format!("{}: {other}", other.kind()))`
   (`local_vault.rs:285`), so COSMIC renders raw technical strings instead of
   localized `errors.hardware_key_*` messages.
5. **Tauri gates hardware keys on OS Keystore support:** In
   `SettingsTabSecurity.vue:208`, the entire "Remember unlock" section—including
   hardware keys—is disabled when `keystoreStatus.supported` is `false` (e.g., a
   Linux session without Secret Service), even though `UnlockSource::HardwareKey`
   never touches the OS keystore.
6. **Split persistence between COSMIC and Tauri:** `zann-client-sqlite` persists
   enrollments in `unlock.json` (`remembered.rs:25`), while Tauri still embeds
   `RememberedUnlock` inside `desktop.json` (`MIG-003` / `MIG-005`).

## Decision

### 1. Separate unlock lifetime (`SessionOnly` vs `Persistent`)

Device unlock gains an explicit lifetime policy:

```rust
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnlockLifetime {
    /// Default. Master password is required once after application launch or
    /// OS reboot; quick unlock (hardware key or keystore/biometrics) is armed
    /// in memory for subsequent locks during the session.
    #[default]
    SessionOnly,
    /// Opt-in ("Allow quick unlock after restart"). Wrapped master key is
    /// persisted in `unlock.json` (0600) across restarts and reboots.
    Persistent,
}
```

- **`SessionOnly` is the default.** Opening the vault after a cold start
  requires the master password. Once unlocked with the master password,
  `LocalVault` (or `zann-daemon` once active) wraps the master key with the
  configured DWK and holds the ciphertext envelope in process memory
  (`session_envelope: Mutex<Option<SessionEnvelope>>`). When `lock()` is called
  (manual lock, focus loss, idle timeout, or hardware-key removal), `master_key`
  is zeroized and dropped, while `session_envelope` remains in memory so the
  next unlock only needs a touch or biometric prompt. Process exit or OS reboot
  destroys `session_envelope`.
- **`Persistent` is an explicit toggle in Settings → Security**
  (*"Allow unlock without master password after app restart"*). When enabled,
  the wrapped master key is written to `unlock.json`. When disabled, any
  existing `wrapped_master_key` in `unlock.json` (and in `HardwareKeyEntry`) is
  cleared from disk while keeping the enrolled hardware-key descriptors
  (`credential_id`, `salt`, `label`, `verification`, `enrolled_at`) so the user
  does not have to re-enroll their tokens on every launch.
- Because `SessionOnly` keeps `credential_id` and `salt` in `unlock.json` (neither
  is secret) without `wrapped_master_key`, `LocalVault::unlock(password)`
  recomputes or re-wraps the in-memory `session_envelope` automatically using a
  stored per-key wrap key or on first enrollment/touch.
  - Specifically, to avoid asking for a hardware touch during a password unlock,
    each `HardwareKeyEntry` stores a random 32-byte `key_slot_secret` wrapped by
    the token's `DWK` (`wrapped_slot_key = E_dwk(slot_key)`). That `wrapped_slot_key`
    is static per enrollment and safe on disk because `slot_key` wraps nothing
    until the user enters their master password in a session. Once the master
    password is entered in `SessionOnly` mode, `LocalVault` wraps `master_key`
    under `slot_key` **in RAM only** (`E_slot_key(master_key)`). Subsequent
    session unlocks derive `DWK` from the token → unwrap `slot_key` → unwrap the
    in-memory `master_key`, with zero disk ciphertext of the master key!

### 2. Per-key verification mode (`TouchOnly` vs `PinAndTouch`)

Hardware-key enrollment lets the user choose the CTAP2 verification requirement:

```rust
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum HardwareVerification {
    /// User Presence (`up = true, uv = false`). Single touch, no PIN.
    #[default]
    TouchOnly,
    /// User Verification (`up = true, uv = true` via CTAP2 `clientPin` or
    /// on-device biometrics such as YubiKey Bio).
    UserVerification,
}
```

- **`TouchOnly`** preserves the current zero-PIN single-touch flow (`without_pin_and_uv()`).
- **`UserVerification`** uses CTAP2 PIN/UV authentication (`clientPin` / built-in
  biometric UV on tokens like YubiKey Bio):
  - If the authenticator supports built-in `uv` (e.g. YubiKey Bio), it can
    verify without a PIN prompt; otherwise the UI prompts for the token's FIDO2
    PIN and passes it to the authenticator to obtain the `pinUvAuthToken` for
    `makeCredential` / `getAssertion`.
  - The FIDO2 PIN is verified strictly by the authenticator's secure element
    under its hardware retry counter; it is never stored, logged, or used to
    derive keys in software.
  - Actionable error kinds are surfaced for PIN states:
    `hardware_key_pin_required`, `hardware_key_pin_invalid` (with remaining
    retries when reported by CTAP2 `0x31` / `getPinRetries`),
    `hardware_key_pin_locked` (`0x32` `CTAP2_ERR_PIN_BLOCKED`), and
    `hardware_key_pin_not_set` (`0x36` `CTAP2_ERR_PIN_NOT_SET`).

### 3. Two-step enrollment with explicit progress and user-supplied labels

Enrollment is split into two observable steps so callers never block across two
undifferentiated touches:

1. **Step 1 — Create credential (Touch 1):** `makeCredential` with `hmac-secret`
   enabled.
2. **Step 2 — Verify `hmac-secret` & derive DWK (Touch 2):** `getAssertion` with
   the new `credential_id` and `salt`.

In `LocalVaultService` / `zann-keystore`, this is exposed either as a two-phase
call (`begin_hardware_key_enroll(label, verification) -> PendingHardwareKey`
followed by `finish_hardware_key_enroll(pending) -> HardwareKey`) or via a
progress sink so COSMIC and Apple/FFI update the prompt from
*"Step 1 of 2: Touch your hardware key to register…"* to
*"Step 2 of 2: Touch again to confirm…"*.

The enrollment UI includes a text input for `label` (pre-filled from the
authenticator's product string via HID/CTAP `get_info` when available, e.g.,
`"YubiKey 5C NFC"`, falling back to `"Hardware key 1"`).

### 4. Invert platform dependencies behind `Keystore` and `HardwareAuthenticator` traits

`zann-keystore` defines two trait ports with zero UI or `$HOME` assumptions:

```rust
/// Platform secret / biometric-bound DWK storage.
pub trait Keystore: Send + Sync {
    fn status(&self) -> KeystoreStatus;
    fn store_dwk(&self, dwk: &[u8]) -> Result<(), KeystoreError>;
    fn load_dwk(&self) -> Result<Option<Vec<u8>>, KeystoreError>;
    fn delete_dwk(&self) -> Result<(), KeystoreError>;
}

/// FIDO2 `hmac-secret` authenticator port.
pub trait HardwareAuthenticator: Send + Sync {
    fn status(&self) -> Result<AuthenticatorInfo, FidoError>;
    fn create_credential(
        &self,
        verification: HardwareVerification,
        pin: Option<&SecretValue>,
    ) -> Result< Vec<u8>, FidoError>;
    fn derive_dwk(
        &self,
        credential: &HardwareCredential,
        verification: HardwareVerification,
        pin: Option<&SecretValue>,
    ) -> Result<[u8; 32], FidoError>;
    fn is_present(&self, credential: &HardwareCredential) -> bool;
}
```

- **Implementations of `HardwareAuthenticator`:**
  - `CtapHidAuthenticator` (`ctap-hid-fido2`, Linux and macOS);
  - `WindowsWebAuthnAuthenticator` (`webauthn.dll`, planned for Windows);
  - `FakeHardwareAuthenticator` (in-memory deterministic test double for unit
    and headless UI flow tests).
- **Implementations of `Keystore`:**
  - `KeyringKeystore` (Linux Secret Service, Windows Credential Manager, generic
    fallback);
  - `AppleBiometricKeystore` (`Security.framework` + `LocalAuthentication` with
    `SecAccessControlCreateWithFlags(.biometryCurrentSet)`, resolving
    [#146](https://github.com/constXife/zann/issues/146) for macOS and iOS);
  - `AndroidBiometricKeystore` (injected via `zann-ffi` foreign trait on
    Android).
- `LocalVault` accepts `Arc<dyn Keystore>` and `Arc<dyn HardwareAuthenticator>`
  at construction (with `default_keystore()` and `default_authenticator()` as
  defaults for desktop composition roots).

### 5. Concurrent password entry and structured error propagation

- **Non-blocking password input during hardware wait:** On the unlock screen
  (COSMIC `screens/master.rs` and native FFI consumers), waiting for a
  hardware touch tracks a separate `hardware_unlock_op_id` / `hardware_busy`
  state. Typing the master password and pressing Enter is always active; if the
  password unlocks the vault first, any late completion from the hardware-key
  worker is ignored.
- **Typed error kind across `LocalVaultService`:** `LocalError` carries `{ kind, message }`
  for unlock errors so COSMIC and FFI consumers translate `err.kind()` through
  `i18n` (`errors.hardware_key_*`, `errors.keystore_*`) rather than displaying
  raw Rust error strings.
- **Independent Hardware Key & Keystore controls:** Enrolling or unlocking with
  a hardware key does not require `KeystoreStatus::supported == true`.
- **Single `unlock.json` file:** Native local clients use the canonical
  remembered-unlock owner; the retired Tauri inline format has no active writer.

## Consequences

**Good.**
- The default (`SessionOnly`) closes the cold-boot / stolen-bag attack vector
  without sacrificing single-touch convenience during an active workday.
- The `slot_key` indirection (`wrapped_slot_key` on disk + `E_slot_key(master_key)`
  in RAM) allows `SessionOnly` mode to arm on a password unlock *without*
  requiring the user to touch the YubiKey during password entry.
- Users in shared spaces can require a FIDO2 PIN (`UserVerification`), turning a
  plugged-in YubiKey back into two factors (physical token + hardware-throttled
  PIN) and making `Persistent` mode defensible.
- `FakeHardwareAuthenticator` makes hardware-key enrollment, two-touch progress,
  PIN retry errors, and auto-lock presence polling testable in `cargo test` and
  `just cosmic-test` without physical hardware.
- Apple and Android clients can supply hardware-backed biometric keystores
  without forking `RememberedUnlock`.

**Bad.**
- Upgrading existing users whose `unlock.json` has `wrapped_master_key` either
  preserves `Persistent` for migrated files or resets them to `SessionOnly`
  once; migration must be explicit so users are not surprised.
- Supporting CTAP2 `clientPin` adds a PIN input state to the enrollment and
  unlock screens when `UserVerification` is selected.

## Plan

| Phase | Scope | Risk |
|---|---|---|
| 1 | `zann-keystore`: `HardwareAuthenticator` trait, `FakeHardwareAuthenticator`, `UnlockLifetime` (`SessionOnly` with `wrapped_slot_key` + `Persistent`), two-step enrollment API, and CTAP2 `clientPin` (`HardwareVerification`) | medium |
| 2 | `zann-client` & `zann-client-sqlite`: inject `Keystore` + `HardwareAuthenticator` into `LocalVault`, expose lifetime/verification/two-step enrollment and structured error kinds on `LocalVaultService` and `zann-ffi` | medium |
| 3 | `apps/cosmic` & `apps/apple`: two-step touch progress, custom key label + auto-detected device name, FIDO2 PIN prompt, `SessionOnly` vs `Persistent` toggle, non-blocking password entry in COSMIC, and localized error kinds | low–medium |
| 4 | Platform biometric ACLs: macOS/iOS `SecAccessControl` (`.biometryCurrentSet`, [#146](https://github.com/constXife/zann/issues/146)) and Windows `webauthn.dll` backend | medium |

## Alternatives considered

**Always require FIDO2 PIN on every unlock.**
Fixes the "stranger touches the key" threat unconditionally, but ruins the
single-occupant home workflow that motivated [#147](https://github.com/constXife/zann/issues/147)
in the first place. Making `HardwareVerification` a per-key choice and
`SessionOnly` the default lifetime gives a safe default while preserving
one-touch unlock where wanted.

**Touch the YubiKey during password unlock to arm `SessionOnly`.**
Simpler than `wrapped_slot_key`, because the token could wrap `master_key`
directly into RAM on password login. Rejected: if the user unlocks with their
password while the key is in their pocket and plugs the key in an hour later,
`SessionOnly` would not be armed. Storing `wrapped_slot_key = E_dwk(slot_key)`
at enrollment time lets a password unlock encrypt `master_key` under `slot_key`
in RAM immediately, without the token present.

**Store `SessionOnly` envelopes in the OS keyring instead of process memory.**
OS keyrings persist across reboots by default, defeating `SessionOnly` unless
tied to an ephemeral session collection. Process memory (in `LocalVault` and
later `zann-daemon`) is guaranteed to vanish on process exit and OS reboot.
