//! Explicit local destinations; no selection inference and no private-key DTOs.
pub use crate::passkey_exchange::ExchangeFormat as PasskeyExchangeFormat;
#[derive(Clone, Debug)]
pub struct PasskeyTarget {
    pub storage_id: String,
    pub vault_id: String,
}
#[derive(Clone, Debug)]
pub struct PasskeyImportPreview {
    pub credentials: u64,
    pub items: u64,
    pub ignored_records: u64,
}
#[derive(Clone, Debug)]
pub struct PasskeyImportReport {
    pub imported: u64,
    pub skipped_existing: u64,
}

#[derive(Clone, Debug)]
pub struct PasskeyTargetSummary {
    pub target: PasskeyTarget,
    pub name: String,
}
