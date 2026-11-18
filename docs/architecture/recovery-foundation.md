# Account epoch and recovery persistence foundation (#30)

This implements the first slice of [#30](https://github.com/constXife/zann/issues/30).
The design is reviewed separately in [PR #306](https://github.com/constXife/zann/pull/306).
This document records phase 1. The consuming RP/recovery flow is now specified in
[ADR 0018](../adr/0018-passkey-account-access.md), [account grants](passkey-account-keys.md)
and [consume/resume](passkey-recovery.md); its native owner is `app::account_access`.

## Active owners and guarantees

- `zann-core::recovery` owns value-only states, status and cardinality limits.
- `zann-crypto::recovery` owns the shared 48-character server-code generator,
  256-bit resume credentials, zeroizing bundle encoding and operation-bound
  token hashing. Staged recovery-code issuance and admin reset reuse it; codes are not E2EE keys.
- `zann-db::repo::sessions` owns epoch-aware persistence and refresh CAS. Issuance
  locks/checks the user before device FK acquisition, then creates device/session
  and personal-vault membership in one transaction. Password and OIDC use the same
  issuer; registration uses the same session writer in its existing transaction.
  Access/refresh lookups require current epoch, active account, no pending recovery
  and an unrevoked device belonging to that account. Refresh also matches its
  previous hash and expiration under the account lock; concurrent reuse has one winner.
- `zann-db::repo::recovery` persists start, exact mutation receipts, terminal
  cancellation/expiry and bounded retention. Start compares the verified source
  generation/code verifier and atomically installs the successor, bumps auth epoch,
  supersedes prior recovery and reserves quota. Callers must verify the actual code
  before invoking this storage primitive. Raw codes/tokens are never persisted.
  No method pretends a credential was tested, completes recovery or issues tokens.
- `zann-client::config::v2::recovery` is a crate-private foundation for the future
  canonical auth flow. It requires a verified endpoint binding, confirms saving
  the successor, stores/reads back an operation-scoped CredentialStore bundle,
  then publishes a private, bounded, duplicate-free secret-free intent. Prepared
  cancellation can remove its bundle; after dispatch secrets are retained.
  Resumption checks the exact observed endpoint/server/pin before reading secrets;
  status cannot change account/epoch or move backward. Recovery records do not
  participate in the ordinary global auth-intent barrier, so waiting A does not
  block unrelated B. Keystore calls never hold a config lock.

Existing ordinary session tokens still use the same wire format. Direct OIDC JWTs
remain separate IdP authority: ordinary OIDC admission refuses a pending local
recovery; future explicit IdP recovery must use its dedicated transition.
Machine tokens remain independent, cannot become recovery authority and do not
acquire personal-key access. Old session rows need not be scanned/deleted to revoke
interactive authority; authorization rejects their stale epoch in its existing query.

## Migration and deployment

Server migration `0004_account_recovery.sql` stamps existing users/sessions with
initial epoch 1, preserves recovery verifiers and ciphertext, and initializes
code version 1 where a verifier already exists. New session writes must explicitly
supply an epoch: the temporary migration default is dropped in the same migration.
Upgrade the server binary with this schema; an old binary cannot issue sessions
against the new schema. There is no rolling mixed-binary compatibility path.
Local SQLite, device roots, item/vault envelopes and KDF encodings are unchanged.

The store's caps are 1,024 active / 8,192 retained operations and 32 receipts per
operation; expiry is 24 hours. Maintenance processes at most one 100-row expiry
page and one 100-row terminal-retention page per invocation, with seven-day
retention. It preserves the current successor verifier on expiry/abandon.
Client intents have a four-operation cap, 64 KiB file limit and exact root-bound
credential references. Future auth admission must also check expiry at request
execution rather than depend on cleanup timing.

## Required before a public consume endpoint

The storage primitive is not a recovery authorization service. Later slices must
add configured Internal/OIDC eligibility, actual code/KDF verification and bounded
admission, passkey/grant revocation in the same transaction, RP staged tests,
custody proofs, typed recovery router scope, request/transaction deadlines,
completion/ordinary-login reconciliation and proof-gated secret cleanup.
Protected mutation paths/long-lived streams need epoch rechecks at commit/message
boundaries before exposing destructive recovery. Endpoint absence is intentional;
no browser/UI or raw recovery-bearer transport is introduced here.

The immediate recovery-kit endpoint is removed. Server Recovery Keys are now
staged in the client credential store, re-entered and activated with a fresh
management proof ([passkey recovery](passkey-recovery.md)); that gate precedes
password-free onboarding. Public APIs cannot use this store to bypass it.
