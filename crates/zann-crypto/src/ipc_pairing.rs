//! One-use SPAKE2 code exchange with directional key confirmation.
//! The caller supplies the canonical endpoint/channel binding, never a vault key.
use rand::{rngs::OsRng, Rng};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const CODE_DIGITS: usize = 6;
pub const MESSAGE_BYTES: usize = 33;

#[derive(Debug)]
pub enum PairingError {
    Invalid,
    Exchange(spake2::Error),
}
impl std::fmt::Display for PairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => f.write_str("one-time browser pairing refused"),
            Self::Exchange(error) => write!(f, "SPAKE2 exchange refused: {error:?}"),
        }
    }
}
impl std::error::Error for PairingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // Upstream exposes a structured enum, not std::error::Error.
            // Retain it in this error and its Display/Debug diagnostics.
            Self::Exchange(_) => None,
            Self::Invalid => None,
        }
    }
}
type Result<T> = std::result::Result<T, PairingError>;

pub fn generate_code() -> Zeroizing<String> {
    Zeroizing::new(format!("{:06}", OsRng.gen_range(0..1_000_000_u32)))
}
pub fn validate_code(code: &str) -> Result<()> {
    if code.len() != CODE_DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PairingError::Invalid);
    }
    Ok(())
}

pub struct CodeExchange(Spake2<Ed25519Group>);
impl CodeExchange {
    pub fn client(code: &str, binding: &[u8]) -> Result<(Self, Vec<u8>)> {
        Self::start(code, binding, true)
    }
    pub fn server(code: &str, binding: &[u8]) -> Result<(Self, Vec<u8>)> {
        Self::start(code, binding, false)
    }
    fn start(code: &str, binding: &[u8], client: bool) -> Result<(Self, Vec<u8>)> {
        validate_code(code)?;
        let mut client_id = b"zann-browser-code-v1\0client\0".to_vec();
        client_id.extend_from_slice(binding);
        let mut server_id = b"zann-browser-code-v1\0server\0".to_vec();
        server_id.extend_from_slice(binding);
        let password = Password::new(code.as_bytes());
        let a = Identity::new(&client_id);
        let b = Identity::new(&server_id);
        let (state, message) = if client {
            Spake2::start_a(&password, &a, &b)
        } else {
            Spake2::start_b(&password, &a, &b)
        };
        Ok((Self(state), message))
    }
    pub fn finish(self, message: &[u8]) -> Result<CodeConfirmation> {
        if message.len() != MESSAGE_BYTES {
            return Err(PairingError::Invalid);
        }
        let key = Zeroizing::new(self.0.finish(message).map_err(PairingError::Exchange)?);
        // Separate the PAKE output from the directional confirmation MAC keys.
        Ok(CodeConfirmation(Zeroizing::new(blake3::derive_key(
            "zann browser code v1 key confirmation",
            &key,
        ))))
    }
}

pub struct CodeConfirmation(Zeroizing<[u8; 32]>);
impl CodeConfirmation {
    pub fn server_proof(&self) -> [u8; 32] {
        *blake3::keyed_hash(&self.0, b"zann-browser-code-v1\0server").as_bytes()
    }
    pub fn client_proof(&self) -> [u8; 32] {
        *blake3::keyed_hash(&self.0, b"zann-browser-code-v1\0client").as_bytes()
    }
    pub fn verify_server(&self, proof: &[u8; 32]) -> Result<()> {
        Self::verify(&self.server_proof(), proof)
    }
    pub fn verify_client(&self, proof: &[u8; 32]) -> Result<()> {
        Self::verify(&self.client_proof(), proof)
    }
    fn verify(expected: &[u8; 32], supplied: &[u8; 32]) -> Result<()> {
        if !bool::from(expected.ct_eq(supplied)) {
            return Err(PairingError::Invalid);
        }
        Ok(())
    }
}
