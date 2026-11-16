//! Portable archive v1. Independent from vault Item envelopes (ADR 0017).
use crate::SecretKey;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    io::{self, Read, Write},
};
use zeroize::Zeroizing;

mod header;
mod reader;
mod recipient;
mod writer;
pub use header::{ArchiveHeader, UnlockedArchive};
pub use reader::ArchiveReader;
pub use recipient::{RecipientDescriptor, RecipientKey};
pub use writer::ArchiveWriter;

pub const CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_RECIPIENTS: usize = 16;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAGIC: &[u8; 8] = b"ZANNBK01";
const TAG_BYTES: usize = 16;

pub struct ArchiveError {
    kind: &'static str,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl ArchiveError {
    pub fn kind(&self) -> &'static str {
        self.kind
    }
    fn new(kind: &'static str) -> Self {
        Self { kind, source: None }
    }
    fn source(
        kind: &'static str,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}
impl fmt::Debug for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchiveError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind)
    }
}
impl std::error::Error for ArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}
impl From<io::Error> for ArchiveError {
    fn from(error: io::Error) -> Self {
        Self::source("backup_archive_io", error)
    }
}
impl From<serde_json::Error> for ArchiveError {
    fn from(error: serde_json::Error) -> Self {
        Self::source("backup_archive_header_invalid", error)
    }
}
fn random<const N: usize>() -> [u8; N] {
    let mut value = [0; N];
    OsRng.fill_bytes(&mut value);
    value
}
fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ArchiveError> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(Nonce::from_slice(nonce), Payload { msg: data, aad })
        .map_err(|_| ArchiveError::new("backup_archive_encrypt"))
}
fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    data: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ArchiveError> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(Nonce::from_slice(nonce), Payload { msg: data, aad })
        .map(Zeroizing::new)
        .map_err(|_| ArchiveError::new("backup_archive_authentication"))
}
fn derived(key: &SecretKey, context: &str) -> SecretKey {
    SecretKey::from_bytes(blake3::derive_key(context, key.as_bytes()))
}
fn nonce(index: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&index.to_le_bytes());
    nonce
}
fn frame_aad(header: &[u8; 32], index: u64, length: u32, final_frame: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(45);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&length.to_le_bytes());
    aad.push(u8::from(final_frame));
    aad
}
#[cfg(test)]
mod tests;
