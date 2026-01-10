use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use zeroize::{Zeroize, ZeroizeOnDrop};

const BLOB_MAGIC: [u8; 3] = *b"ZAN";
const BLOB_VERSION: u8 = 1;
const ALG_XCHACHA20POLY1305: u8 = 1;
const XCHACHA_NONCE_LEN: usize = 24;
const MAX_BLOB_SECTION_LEN: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub kek_id: u32,
    pub algo_dek: u8,
    pub algo_kek: u8,
    pub enc_dek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidBlob,
    UnsupportedVersion(u8),
    UnsupportedAlgorithm(u8),
    EncryptionFailed,
    DecryptionFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBlob => write!(f, "invalid encrypted blob"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported blob version: {version}")
            }
            Self::UnsupportedAlgorithm(alg) => write!(f, "unsupported algorithm: {alg}"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey(REDACTED)")
    }
}

impl EncryptedBlob {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let enc_dek_len = u32::try_from(self.enc_dek.len()).unwrap_or(u32::MAX);
        let nonce_len = u32::try_from(self.nonce.len()).unwrap_or(u32::MAX);
        let mut out = Vec::with_capacity(
            3 + 1
                + 4
                + 1
                + 1
                + 4
                + 4
                + self.enc_dek.len()
                + self.nonce.len()
                + self.ciphertext.len(),
        );
        out.extend_from_slice(&BLOB_MAGIC);
        out.push(BLOB_VERSION);
        out.extend_from_slice(&self.kek_id.to_le_bytes());
        out.push(self.algo_dek);
        out.push(self.algo_kek);
        out.extend_from_slice(&enc_dek_len.to_le_bytes());
        out.extend_from_slice(&nonce_len.to_le_bytes());
        out.extend_from_slice(&self.enc_dek);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    #[instrument(level = "debug", skip(bytes), fields(bytes_len = bytes.len()))]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 3 + 1 {
            return Err(CryptoError::InvalidBlob);
        }

        if bytes[..3] != BLOB_MAGIC {
            return Err(CryptoError::InvalidBlob);
        }

        let version = bytes[3];
        if version != BLOB_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        parse_v1_envelope(bytes)
    }
}

#[instrument(
    level = "debug",
    skip(key, plaintext, aad),
    fields(plaintext_len = plaintext.len(), aad_len = aad.len())
)]
pub fn encrypt_blob(
    key: &SecretKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedBlob, CryptoError> {
    let dek = SecretKey::generate();
    let enc_dek = wrap_dek(key, &dek)?;

    let cipher = XChaCha20Poly1305::new(dek.as_bytes().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let header = v1_header_bytes(0, ALG_XCHACHA20POLY1305, ALG_XCHACHA20POLY1305);
    let payload_aad = v1_payload_aad(&header, aad);
    let payload = Payload {
        msg: plaintext,
        aad: &payload_aad,
    };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(EncryptedBlob {
        kek_id: 0,
        algo_dek: ALG_XCHACHA20POLY1305,
        algo_kek: ALG_XCHACHA20POLY1305,
        enc_dek,
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

#[instrument(
    level = "debug",
    skip(key, blob, aad),
    fields(ciphertext_len = blob.ciphertext.len(), aad_len = aad.len())
)]
pub fn decrypt_blob(
    key: &SecretKey,
    blob: &EncryptedBlob,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    decrypt_v1_envelope(key, blob, aad)
}

fn parse_v1_envelope(bytes: &[u8]) -> Result<EncryptedBlob, CryptoError> {
    let min_len = 3 + 1 + 4 + 1 + 1 + 4 + 4;
    if bytes.len() < min_len {
        return Err(CryptoError::InvalidBlob);
    }
    let kek_id = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let dek_algo = bytes[8];
    let kek_algo = bytes[9];
    let enc_dek_len = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    let nonce_len = u32::from_le_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]) as usize;
    if enc_dek_len > MAX_BLOB_SECTION_LEN || nonce_len > MAX_BLOB_SECTION_LEN {
        return Err(CryptoError::InvalidBlob);
    }
    let mut offset = 18;
    if bytes.len() < offset + enc_dek_len + nonce_len {
        return Err(CryptoError::InvalidBlob);
    }
    let enc_dek = bytes[offset..offset + enc_dek_len].to_vec();
    offset += enc_dek_len;
    let nonce = bytes[offset..offset + nonce_len].to_vec();
    offset += nonce_len;
    let ciphertext = bytes[offset..].to_vec();
    Ok(EncryptedBlob {
        kek_id,
        algo_dek: dek_algo,
        algo_kek: kek_algo,
        enc_dek,
        nonce,
        ciphertext,
    })
}

fn v1_header_bytes(kek_id: u32, dek_algo: u8, kek_algo: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 1);
    out.extend_from_slice(&kek_id.to_le_bytes());
    out.push(dek_algo);
    out.push(kek_algo);
    out
}

fn v1_payload_aad(header: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + aad.len());
    out.extend_from_slice(header);
    out.extend_from_slice(aad);
    out
}

fn wrap_dek(kek: &SecretKey, dek: &SecretKey) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(kek.as_bytes().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let payload = Payload {
        msg: dek.as_bytes(),
        aad: &[],
    };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut out = Vec::with_capacity(XCHACHA_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn unwrap_dek(kek: &SecretKey, enc_dek: &[u8]) -> Result<SecretKey, CryptoError> {
    if enc_dek.len() < XCHACHA_NONCE_LEN {
        return Err(CryptoError::InvalidBlob);
    }
    let (nonce_bytes, ciphertext) = enc_dek.split_at(XCHACHA_NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(kek.as_bytes().into());
    let payload = Payload {
        msg: ciphertext,
        aad: &[],
    };
    let dek_bytes = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    if dek_bytes.len() != 32 {
        return Err(CryptoError::InvalidBlob);
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);
    Ok(SecretKey::from_bytes(dek))
}

fn decrypt_v1_envelope(
    key: &SecretKey,
    blob: &EncryptedBlob,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if blob.algo_kek != ALG_XCHACHA20POLY1305 || blob.algo_dek != ALG_XCHACHA20POLY1305 {
        return Err(CryptoError::UnsupportedAlgorithm(blob.algo_dek));
    }
    let dek = unwrap_dek(key, &blob.enc_dek)?;
    if blob.nonce.len() != XCHACHA_NONCE_LEN {
        return Err(CryptoError::InvalidBlob);
    }
    let header = v1_header_bytes(blob.kek_id, blob.algo_dek, blob.algo_kek);
    let payload_aad = v1_payload_aad(&header, aad);
    let cipher = XChaCha20Poly1305::new(dek.as_bytes().into());
    let nonce = XNonce::from_slice(&blob.nonce);
    let payload = Payload {
        msg: &blob.ciphertext,
        aad: &payload_aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_roundtrip() {
        let key = SecretKey::generate();
        let aad = b"aad";
        let plaintext = b"secret";
        let blob = encrypt_blob(&key, plaintext, aad).expect("encrypt");
        let bytes = blob.to_bytes();
        let parsed = EncryptedBlob::from_bytes(&bytes).expect("parse");
        let decrypted = decrypt_blob(&key, &parsed, aad).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn v1_aad_mismatch_fails() {
        let key = SecretKey::generate();
        let blob = encrypt_blob(&key, b"secret", b"aad").expect("encrypt");
        let result = decrypt_blob(&key, &blob, b"other");
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = SecretKey::generate();
        let other = SecretKey::generate();
        let blob = encrypt_blob(&key, b"secret", b"aad").expect("encrypt");
        let result = decrypt_blob(&other, &blob, b"aad");
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn invalid_nonce_length_fails() {
        let key = SecretKey::generate();
        let mut blob = encrypt_blob(&key, b"secret", b"aad").expect("encrypt");
        blob.nonce = vec![0u8; 10];
        let result = decrypt_blob(&key, &blob, b"aad");
        assert!(matches!(result, Err(CryptoError::InvalidBlob)));
    }

    #[test]
    fn corrupted_ciphertext_fails() {
        let key = SecretKey::generate();
        let mut blob = encrypt_blob(&key, b"secret", b"aad").expect("encrypt");
        blob.ciphertext[0] ^= 0xff;
        let result = decrypt_blob(&key, &blob, b"aad");
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }
}
