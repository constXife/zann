use crate::{DaemonError, Result};
use std::os::unix::net::UnixStream;
use zann_client::browser_ipc::{EncryptedFrame, NoiseHandshakePacket};
use zann_crypto::ipc_transport::{IpcHandshake, IpcTransport};
use zeroize::Zeroizing;

pub(crate) struct Channel<'a> {
    stream: &'a mut UnixStream,
    noise: IpcTransport,
    binding: [u8; 32],
    confirmation_pending: bool,
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
            confirmation_pending: false,
            stream,
            noise: handshake.finish()?,
        })
    }
    pub fn binding(&self) -> &[u8; 32] {
        &self.binding
    }
    pub fn await_confirmation(&mut self) {
        self.confirmation_pending = true;
    }
    pub fn read(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let duration = if std::mem::take(&mut self.confirmation_pending) {
            std::time::Duration::from_secs(35)
        } else {
            std::time::Duration::from_secs(5)
        };
        let Some(bytes) = crate::transport::read_deadline(self.stream, duration)? else {
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
