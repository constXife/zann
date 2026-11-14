//! Standard Noise NK channel; pairing authorization remains in the daemon.
//! No vault envelope changes. Lengths and chunk boundaries are authenticated.
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::{Builder, HandshakeState, TransportState};
use zeroize::Zeroizing;

const PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
pub const MAX_PLAINTEXT: usize = 264 * 1024;
const CHUNK: usize = 32 * 1024;
pub const MAX_CHUNKS: usize = 9;
pub const MAX_CIPHERTEXT_CHUNK: usize = CHUNK + 16;

pub enum IpcTransportError {
    Noise(snow::Error),
    Protocol,
}
impl From<snow::Error> for IpcTransportError {
    fn from(error: snow::Error) -> Self {
        Self::Noise(error)
    }
}
impl std::fmt::Display for IpcTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("local encrypted channel refused")
    }
}
impl std::fmt::Debug for IpcTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for IpcTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Noise(error) => Some(error),
            Self::Protocol => None,
        }
    }
}
type Result<T> = std::result::Result<T, IpcTransportError>;

pub struct IpcTransportKey(Zeroizing<[u8; 32]>);
impl IpcTransportKey {
    pub fn generate() -> Self {
        Self::from_seed(super::ipc_signatures::random_nonce())
    }
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(Zeroizing::new(seed))
    }
    pub fn seed(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn public_key(&self) -> [u8; 32] {
        let mut dh = DefaultResolver
            .resolve_dh(&snow::params::DHChoice::Curve25519)
            .expect("pinned Noise resolver supports X25519");
        dh.set(&self.0[..]);
        let mut public = [0; 32];
        public.copy_from_slice(dh.pubkey());
        public
    }
    pub fn responder(&self, prologue: &[u8]) -> Result<IpcHandshake> {
        Ok(IpcHandshake(
            Builder::new(PATTERN.parse()?)
                .local_private_key(&self.0[..])?
                .prologue(prologue)?
                .build_responder()?,
        ))
    }
}

pub struct IpcHandshake(HandshakeState);
impl IpcHandshake {
    pub fn initiator(server: &[u8; 32], prologue: &[u8]) -> Result<Self> {
        Ok(Self(
            Builder::new(PATTERN.parse()?)
                .remote_public_key(server)?
                .prologue(prologue)?
                .build_initiator()?,
        ))
    }
    pub fn write(&mut self) -> Result<Vec<u8>> {
        let mut packet = vec![0; 128];
        let size = self.0.write_message(&[], &mut packet)?;
        packet.truncate(size);
        Ok(packet)
    }
    pub fn read(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > 128 {
            return Err(IpcTransportError::Protocol);
        }
        let mut payload = Zeroizing::new(vec![0; 128]);
        if self.0.read_message(packet, &mut payload)? != 0 {
            return Err(IpcTransportError::Protocol);
        }
        Ok(())
    }
    pub fn finish(self) -> Result<IpcTransport> {
        Ok(IpcTransport(self.0.into_transport_mode()?))
    }
    /// Final Noise transcript hash, used to bind code pairing to this channel.
    pub fn binding(&self) -> Result<[u8; 32]> {
        if !self.0.is_handshake_finished() {
            return Err(IpcTransportError::Protocol);
        }
        self.0
            .get_handshake_hash()
            .try_into()
            .map_err(|_| IpcTransportError::Protocol)
    }
}

pub struct IpcTransport(TransportState);
impl IpcTransport {
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<Vec<u8>>> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(IpcTransportError::Protocol);
        }
        let mut framed = Zeroizing::new((plaintext.len() as u32).to_be_bytes().to_vec());
        framed.extend_from_slice(plaintext);
        let mut packets = Vec::new();
        for chunk in framed.chunks(CHUNK) {
            let mut encrypted = vec![0; chunk.len() + 16];
            let count = self.0.write_message(chunk, &mut encrypted)?;
            encrypted.truncate(count);
            packets.push(encrypted);
        }
        Ok(packets)
    }
    pub fn open(&mut self, packets: &[Vec<u8>]) -> Result<Zeroizing<Vec<u8>>> {
        if packets.is_empty() || packets.len() > MAX_CHUNKS {
            return Err(IpcTransportError::Protocol);
        }
        let mut plaintext = Zeroizing::new(Vec::new());
        for packet in packets {
            if packet.len() > CHUNK + 16 {
                return Err(IpcTransportError::Protocol);
            }
            let mut chunk = Zeroizing::new(vec![0; CHUNK]);
            let size = self.0.read_message(packet, &mut chunk)?;
            plaintext.extend_from_slice(&chunk[..size]);
            if plaintext.len() > MAX_PLAINTEXT + 4 {
                return Err(IpcTransportError::Protocol);
            }
        }
        let header: [u8; 4] = plaintext
            .get(..4)
            .ok_or(IpcTransportError::Protocol)?
            .try_into()
            .map_err(|_| IpcTransportError::Protocol)?;
        if u32::from_be_bytes(header) as usize != plaintext.len() - 4 {
            return Err(IpcTransportError::Protocol);
        }
        plaintext.drain(..4);
        Ok(plaintext)
    }
}
