# zann-flows

Toolkit- and runtime-independent native interaction policy (ADR 0001 phase 6).
Connect is the first active slice. Startup, unlock/remembered unlock and idle
flows remain planned; this crate does not claim to retire all of MIG-006.

`Connect::dispatch(Action)` and `Connect::complete(OperationId, Completion)`
mutate one deterministic state machine and return typed effects. The composition
root gives each instance a unique ID; the reducer allocates operation sequence
numbers and distinguishes OIDC start/finish phases. `snapshot()` is the sole
owner of visible stage, busy/error state, interactive methods and registration
availability. Passwords travel only in redacted actions/effects, not snapshots.

Native adapters own form drafts, rendering and OS actions. They execute work
against the canonical application APIs, register cancellation before scheduling,
and validate `accepts(id, step)` before installing opaque connection/trust/browser
capabilities or submitting a completion. Back cancels the active operation and
returns to the previous step; Cancel is terminal. Successful authentication is
terminal and carries the canonical storage ID and personal-vault status.
Registration is explicit and available only when advertised by the server.

COSMIC links this crate directly. Apple consumes the same reducer through
`zann-ffi::ConnectFlowFfi`; the FFI layer only converts records/enums. Auth,
credential custody, TOFU and transaction terminalization stay in `zann-client`.
Cancellation suppresses stale UI/OS effects and signals cancellable auth work;
it does not undo an already committed canonical credential/trust transition.
