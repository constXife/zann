use crate::{DaemonError, Result};
use std::os::unix::net::UnixStream;
use zann_client::browser_ipc::{EncryptedFrame, NoiseHandshakePacket};
use zann_crypto::ipc_transport::{IpcHandshake, IpcTransport};
use zeroize::Zeroizing;

pub(crate) struct Channel<'a> {
    stream: &'a mut UnixStream,
    noise: IpcTransport,
    binding: [u8; 32],
}
impl<'a> Channel<'a> {
    pub fn accept(stream: &'a mut UnixStream, mut handshake: IpcHandshake) -> Result<Self> {
        let bytes = crate::transport::read(stream)?.ok_or(DaemonError::Protocol)?;
        let packet: NoiseHandshakePacket = serde_json::from_slice(&bytes)?;
        handshake.read(&packet.decode()?)?;
        let reply = NoiseHandshakePacket::new(&handshake.write()?);
        crate::transport::write(stream, &serde_json::to_vec(&reply)?)?;
        let binding = handshake.binding()?;
        Ok(Self {
            binding,
            stream,
            noise: handshake.finish()?,
        })
    }
    pub fn binding(&self) -> &[u8; 32] {
        &self.binding
    }
    pub fn read(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Some(bytes) = crate::transport::read(self.stream)? else {
            return Ok(None);
        };
        let packet: EncryptedFrame = serde_json::from_slice(&bytes)?;
        Ok(Some(packet.open(&mut self.noise)?))
    }
    pub fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        let packet = EncryptedFrame::seal(&mut self.noise, plaintext)?;
        crate::transport::write(self.stream, &serde_json::to_vec(&packet)?)?;
        Ok(())
    }
}
