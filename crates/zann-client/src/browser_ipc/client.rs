//! Serialized, single-flight client. Any invalid transition poisons the channel.
use super::*;
use zann_crypto::{
    ipc_signatures::IpcSigningKey,
    ipc_transport::{IpcHandshake, IpcTransport},
};
use zeroize::Zeroizing;

enum State {
    New,
    Handshake(Box<IpcHandshake>),
    Ready(IpcTransport),
    Closed,
}
pub struct BrowserClient {
    pub(super) key: IpcSigningKey,
    pub(super) server: [u8; 32],
    pub(super) nonce: [u8; 32],
    pub(super) binding: [u8; 32],
    sequence: u64,
    pending: bool,
    state: State,
}
impl BrowserClient {
    pub fn new(seed: &str, pinned_server: &str) -> Result<Self> {
        Ok(Self {
            key: IpcSigningKey::from_seed(decode_array(seed)?),
            server: decode_array(pinned_server)?,
            nonce: [0; 32],
            binding: [0; 32],
            sequence: 0,
            pending: false,
            state: State::New,
        })
    }
    pub fn public_key(&self) -> String {
        hex::encode(self.key.public_key())
    }
    pub fn connect(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        let state = std::mem::replace(&mut self.state, State::Closed);
        if !matches!(state, State::New) {
            return Err(IpcError::Protocol);
        }
        let hello: Hello = serde_json::from_slice(bytes)?;
        self.nonce = hello.verify(&self.server)?;
        let mut handshake = IpcHandshake::initiator(&decode_array(&hello.transport_key)?, bytes)?;
        let packet = serde_json::to_vec(&NoiseHandshakePacket::new(&handshake.write()?))?;
        self.state = State::Handshake(Box::new(handshake));
        Ok(packet)
    }
    pub fn finish(&mut self, bytes: &[u8]) -> Result<()> {
        let State::Handshake(mut handshake) = std::mem::replace(&mut self.state, State::Closed)
        else {
            return Err(IpcError::Protocol);
        };
        let packet: NoiseHandshakePacket = serde_json::from_slice(bytes)?;
        handshake.read(&packet.decode()?)?;
        self.binding = handshake.binding()?;
        self.state = State::Ready((*handshake).finish()?);
        Ok(())
    }
    pub fn request(&mut self, request: &Request) -> Result<Vec<u8>> {
        let State::Ready(mut channel) = std::mem::replace(&mut self.state, State::Closed) else {
            return Err(IpcError::Protocol);
        };
        if self.pending {
            return Err(IpcError::Protocol);
        }
        self.sequence = self.sequence.checked_add(1).ok_or(IpcError::Limit)?;
        let signed =
            SignedRequest::sign(&self.key, &self.server, &self.nonce, self.sequence, request)?;
        let bytes = Zeroizing::new(serde_json::to_vec(&signed)?);
        let packet = serde_json::to_vec(&EncryptedFrame::seal(&mut channel, &bytes)?)?;
        self.pending = true;
        self.state = State::Ready(channel);
        Ok(packet)
    }
    pub fn reply(&mut self, bytes: &[u8]) -> Result<Reply> {
        let State::Ready(mut channel) = std::mem::replace(&mut self.state, State::Closed) else {
            return Err(IpcError::Protocol);
        };
        if !self.pending {
            return Err(IpcError::Protocol);
        }
        let frame: EncryptedFrame = serde_json::from_slice(bytes)?;
        let plaintext = frame.open(&mut channel)?;
        let signed: SignedReply = serde_json::from_slice(&plaintext)?;
        let reply = signed.verify(&self.server, &self.nonce, self.sequence)?;
        self.pending = false;
        self.state = State::Ready(channel);
        Ok(reply)
    }
}
