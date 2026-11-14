use super::*;
use zann_crypto::ipc_signatures::{self, IpcSigningKey};
use zeroize::Zeroizing;

pub fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(IpcError::Protocol);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| IpcError::Protocol)?;
    Ok(bytes)
}

fn transcript(
    direction: u8,
    server: &[u8; 32],
    nonce: &[u8; 32],
    sequence: u64,
    body: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut message = Zeroizing::new(b"zann-local-ipc-v1\0".to_vec());
    message.push(direction);
    message.extend_from_slice(server);
    message.extend_from_slice(nonce);
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(&(body.len() as u64).to_be_bytes());
    message.extend_from_slice(body);
    message
}

impl Hello {
    pub fn new(key: &IpcSigningKey, transport: [u8; 32], nonce: [u8; 32]) -> Self {
        let server = key.public_key();
        Self {
            version: VERSION,
            server_key: hex::encode(server),
            nonce: hex::encode(nonce),
            transport_key: hex::encode(transport),
            signature: hex::encode(key.sign(&transcript(0, &server, &nonce, 0, &transport))),
        }
    }
    pub fn verify(&self, pinned_key: &[u8; 32]) -> Result<[u8; 32]> {
        let server = decode_array::<32>(&self.server_key)?;
        let nonce = decode_array::<32>(&self.nonce)?;
        let signature = decode_array::<64>(&self.signature)?;
        let transport = decode_array::<32>(&self.transport_key)?;
        if self.version != VERSION
            || &server != pinned_key
            || !ipc_signatures::verify(
                &server,
                &transcript(0, &server, &nonce, 0, &transport),
                &signature,
            )
        {
            return Err(IpcError::Authentication);
        }
        Ok(nonce)
    }
}

impl SignedRequest {
    pub fn sign(
        key: &IpcSigningKey,
        server: &[u8; 32],
        nonce: &[u8; 32],
        sequence: u64,
        request: &Request,
    ) -> Result<Self> {
        let bytes = Zeroizing::new(serde_json::to_vec(request)?);
        if bytes.len() > MAX_BODY_BYTES {
            return Err(IpcError::Limit);
        }
        Ok(Self {
            public_key: hex::encode(key.public_key()),
            sequence,
            body: hex::encode(&bytes),
            signature: hex::encode(key.sign(&transcript(1, server, nonce, sequence, &bytes))),
        })
    }
    pub fn verify(&self, server: &[u8; 32], nonce: &[u8; 32]) -> Result<([u8; 32], Request)> {
        if self.body.len() > MAX_BODY_BYTES * 2 {
            return Err(IpcError::Limit);
        }
        let public = decode_array::<32>(&self.public_key)?;
        let signature = decode_array::<64>(&self.signature)?;
        let bytes = Zeroizing::new(hex::decode(&self.body).map_err(|_| IpcError::Protocol)?);
        if !ipc_signatures::verify(
            &public,
            &transcript(1, server, nonce, self.sequence, &bytes),
            &signature,
        ) {
            return Err(IpcError::Authentication);
        }
        Ok((public, serde_json::from_slice(&bytes)?))
    }
}

impl SignedReply {
    pub fn sign(
        key: &IpcSigningKey,
        nonce: &[u8; 32],
        sequence: u64,
        reply: &Reply,
    ) -> Result<Self> {
        let bytes = Zeroizing::new(serde_json::to_vec(reply)?);
        if bytes.len() > MAX_BODY_BYTES {
            return Err(IpcError::Limit);
        }
        Ok(Self {
            sequence,
            body: hex::encode(&bytes),
            signature: hex::encode(key.sign(&transcript(
                2,
                &key.public_key(),
                nonce,
                sequence,
                &bytes,
            ))),
        })
    }
    pub fn verify(&self, server: &[u8; 32], nonce: &[u8; 32], sequence: u64) -> Result<Reply> {
        if self.sequence != sequence || self.body.len() > MAX_BODY_BYTES * 2 {
            return Err(IpcError::Protocol);
        }
        let signature = decode_array::<64>(&self.signature)?;
        let bytes = Zeroizing::new(hex::decode(&self.body).map_err(|_| IpcError::Protocol)?);
        if !ipc_signatures::verify(
            server,
            &transcript(2, server, nonce, sequence, &bytes),
            &signature,
        ) {
            return Err(IpcError::Authentication);
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
}
