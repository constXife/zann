//! Toolkit- and runtime-independent interactive client flows.
pub mod connect;

pub mod unlock;

/// The composition root supplies a unique instance ID. Sequence numbers are
/// allocated by the reducer, so replaying an input trace is deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationId {
    pub instance: u64,
    pub sequence: u64,
}
