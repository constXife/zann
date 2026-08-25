pub mod http;
pub mod service;

pub(crate) const SYNC_CIPHERTEXT_MAX_BYTES: usize = 256 * 1_024 + 256;
