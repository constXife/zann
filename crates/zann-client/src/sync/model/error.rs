use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncModelError {
    InvalidIdentifier,
    DuplicateIdentifier,
    InvalidCursor,
    InvalidSequence,
    InvalidChecksum,
    InvalidText,
    InvalidPath,
    InvalidPendingProof,
    InvalidTimestamp,
    PayloadTooLarge,
    CatalogTooLarge,
    PageTooLarge,
    PendingTooLarge,
}

impl fmt::Display for SyncModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "invalid sync identifier",
            Self::DuplicateIdentifier => "duplicate sync identifier",
            Self::InvalidCursor => "invalid sync cursor",
            Self::InvalidSequence => "invalid sync sequence",
            Self::InvalidChecksum => "invalid content checksum",
            Self::InvalidText => "invalid bounded text",
            Self::InvalidPath => "invalid item path",
            Self::InvalidPendingProof => "invalid pending proof",
            Self::InvalidTimestamp => "invalid sync timestamp",
            Self::PayloadTooLarge => "sync payload is too large",
            Self::CatalogTooLarge => "sync catalog is too large",
            Self::PageTooLarge => "sync page is too large",
            Self::PendingTooLarge => "pending sync set is too large",
        })
    }
}

impl std::error::Error for SyncModelError {}
