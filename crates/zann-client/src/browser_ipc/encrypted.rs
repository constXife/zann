use super::{IpcError, Result};
use serde::{Deserialize, Serialize};
use zann_crypto::ipc_transport::{IpcTransport, MAX_CHUNKS, MAX_CIPHERTEXT_CHUNK};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoiseHandshakePacket {
    pub data: String,
}
impl NoiseHandshakePacket {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            data: hex::encode(bytes),
        }
    }
    pub fn decode(&self) -> Result<Vec<u8>> {
        if self.data.len() > 256 {
            return Err(IpcError::Limit);
        }
        hex::decode(&self.data).map_err(|_| IpcError::Protocol)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedFrame {
    chunks: Vec<String>,
}
impl EncryptedFrame {
    pub fn seal(channel: &mut IpcTransport, bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            chunks: channel.seal(bytes)?.iter().map(hex::encode).collect(),
        })
    }
    pub fn open(self, channel: &mut IpcTransport) -> Result<Zeroizing<Vec<u8>>> {
        if self.chunks.is_empty() || self.chunks.len() > MAX_CHUNKS {
            return Err(IpcError::Limit);
        }
        let chunks = self
            .chunks
            .iter()
            .map(|chunk| {
                if chunk.len() > 2 * MAX_CIPHERTEXT_CHUNK {
                    return Err(IpcError::Limit);
                }
                hex::decode(chunk).map_err(|_| IpcError::Protocol)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(channel.open(&chunks)?)
    }
}
