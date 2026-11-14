//! Bootstrap has no application API and publishes a pin only after PAKE and
//! durable native enrollment. Reconnect uses the normal, strictly pinned client.
use super::*;
use zann_crypto::ipc_pairing::{validate_code, CodeExchange, MESSAGE_BYTES};
use zeroize::{Zeroize, Zeroizing};

pub fn pairing_binding(
    server: &[u8; 32],
    nonce: &[u8; 32],
    channel: &[u8; 32],
    client: &[u8; 32],
    name: &str,
) -> Vec<u8> {
    let mut binding = b"zann-browser-pairing-v1\0".to_vec();
    binding.extend_from_slice(server);
    binding.extend_from_slice(nonce);
    binding.extend_from_slice(channel);
    binding.extend_from_slice(client);
    binding.extend_from_slice(&(name.len() as u64).to_be_bytes());
    binding.extend_from_slice(name.as_bytes());
    binding
}

enum Stage {
    New(Zeroizing<String>),
    Connecting(Zeroizing<String>),
    Ready(Zeroizing<String>),
    Challenge(CodeExchange),
    Commit,
    Closed,
}
pub struct BrowserPairingClient {
    client: Option<BrowserClient>,
    seed: Zeroizing<String>,
    name: String,
    stage: Stage,
}
impl BrowserPairingClient {
    pub fn new(seed: &str, code: String, name: String) -> Result<Self> {
        let code = Zeroizing::new(code);
        validate_code(&code)?;
        decode_array::<32>(seed)?;
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err(IpcError::Protocol);
        }
        Ok(Self {
            client: None,
            seed: Zeroizing::new(seed.into()),
            name,
            stage: Stage::New(code),
        })
    }
    pub fn connect(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        let Stage::New(code) = std::mem::replace(&mut self.stage, Stage::Closed) else {
            return Err(IpcError::Protocol);
        };
        let hello: Hello = serde_json::from_slice(bytes)?;
        // Provisional identity only. Self-signature authenticates no endpoint;
        // the code exchange below must bind it before it can be persisted.
        let mut client = BrowserClient::new(&self.seed, &hello.server_key)?;
        self.seed.zeroize();
        let packet = client.connect(bytes)?;
        self.client = Some(client);
        self.stage = Stage::Connecting(code);
        Ok(packet)
    }
    pub fn finish(&mut self, bytes: &[u8]) -> Result<()> {
        let Stage::Connecting(code) = std::mem::replace(&mut self.stage, Stage::Closed) else {
            return Err(IpcError::Protocol);
        };
        self.client
            .as_mut()
            .ok_or(IpcError::Protocol)?
            .finish(bytes)?;
        self.stage = Stage::Ready(code);
        Ok(())
    }
    pub fn begin(&mut self) -> Result<Vec<u8>> {
        let Stage::Ready(code) = std::mem::replace(&mut self.stage, Stage::Closed) else {
            return Err(IpcError::Protocol);
        };
        let client = self.client.as_mut().ok_or(IpcError::Protocol)?;
        let binding = pairing_binding(
            &client.server,
            &client.nonce,
            &client.binding,
            &client.key.public_key(),
            &self.name,
        );
        let (exchange, message) = CodeExchange::client(&code, &binding)?;
        let packet = client.request(&Request::PairStart {
            name: self.name.clone(),
            message: hex::encode(message),
        })?;
        self.stage = Stage::Challenge(exchange);
        Ok(packet)
    }
    pub fn confirm(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        let Stage::Challenge(exchange) = std::mem::replace(&mut self.stage, Stage::Closed) else {
            return Err(IpcError::Protocol);
        };
        let client = self.client.as_mut().ok_or(IpcError::Protocol)?;
        let reply = client.reply(bytes)?;
        let Reply::PairChallenge {
            message,
            confirmation,
        } = &reply
        else {
            return Err(IpcError::Authentication);
        };
        let key = exchange.finish(&decode_array::<MESSAGE_BYTES>(message)?)?;
        key.verify_server(&decode_array(confirmation)?)?;
        let packet = client.request(&Request::PairFinish {
            confirmation: hex::encode(key.client_proof()),
        })?;
        self.stage = Stage::Commit;
        Ok(packet)
    }
    pub fn complete(&mut self, bytes: &[u8]) -> Result<String> {
        if !matches!(
            std::mem::replace(&mut self.stage, Stage::Closed),
            Stage::Commit
        ) {
            return Err(IpcError::Protocol);
        }
        let client = self.client.as_mut().ok_or(IpcError::Protocol)?;
        if !matches!(client.reply(bytes)?, Reply::Paired {}) {
            return Err(IpcError::Authentication);
        }
        Ok(hex::encode(client.server))
    }
}
