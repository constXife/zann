use super::*;
use crate::crypto::{decrypt_blob, encrypt_blob_verified, EncryptedBlob};
use crate::signatures::verify_ed25519;
use subtle::ConstantTimeEq;

impl AccountGrant {
    fn context(&self, transcript: Transcript) -> Result<Transcript> {
        if self.format != 1
            || self.grant_id.get_version_num() != 4
            || self.key_epoch == 0
            || !valid_server_id(&self.server_id)
            || self.user_id.is_nil()
            || self.algorithm != "xchacha20poly1305"
        {
            return Err(AccountAccessError::Invalid("grant context"));
        }
        validate_rp(&self.rp_id)?;
        let credential = decode(&self.credential_id, 1024)?;
        if credential.is_empty() {
            return Err(AccountAccessError::Invalid("credential ID"));
        }
        Ok(transcript
            .field(&self.format.to_be_bytes())
            .field(self.server_id.as_bytes())
            .field(self.user_id.as_bytes())
            .field(self.rp_id.as_bytes())
            .field(&credential)
            .field(self.grant_id.as_bytes())
            .field(&self.key_epoch.to_be_bytes())
            .field(&array::<32>(&self.proof_public_key)?)
            .field(self.algorithm.as_bytes()))
    }
    fn aad(&self) -> Result<Transcript> {
        self.context(Transcript::new("zann account grant aad v1"))
    }
    fn wrapping_key(&self, prf: &AccountPrf) -> Result<SecretKey> {
        let material =
            self.context(Transcript::new("zann account grant material v1").field(&*prf.0))?;
        Ok(SecretKey::from_bytes(blake3::derive_key(
            "zann account grant wrapping v1",
            material.bytes(),
        )))
    }
    pub fn create(
        descriptor: &AccountDescriptor,
        rp_id: String,
        credential_id: String,
        grant_id: Uuid,
        account_key: &SecretKey,
        prf: &AccountPrf,
    ) -> Result<Self> {
        let custody = AccountCustody::derive(
            account_key,
            &descriptor.server_id,
            descriptor.user_id,
            descriptor.key_epoch,
        )?;
        custody.proves(descriptor)?;
        let mut grant = Self {
            format: 1,
            server_id: descriptor.server_id.clone(),
            user_id: descriptor.user_id,
            rp_id,
            credential_id,
            grant_id,
            key_epoch: descriptor.key_epoch,
            proof_public_key: descriptor.proof_public_key.clone(),
            algorithm: "xchacha20poly1305".into(),
            blob: String::new(),
            signature: String::new(),
        };
        let aad = grant.aad()?;
        grant.blob = encode(
            &encrypt_blob_verified(
                &grant.wrapping_key(prf)?,
                account_key.as_bytes(),
                aad.bytes(),
            )?
            .to_bytes(),
        );
        grant.signature = encode(
            &custody.0.sign(
                Transcript::new("zann account grant signature v1")
                    .field(aad.bytes())
                    .field(&decode(&grant.blob, 2048)?)
                    .bytes(),
            ),
        );
        let trial = grant.open(descriptor, prf)?;
        if !bool::from(trial.as_bytes().ct_eq(account_key.as_bytes())) {
            return Err(AccountAccessError::Invalid("grant trial unwrap"));
        }
        Ok(grant)
    }
    pub fn verify(&self, descriptor: &AccountDescriptor) -> Result<()> {
        descriptor.validate()?;
        if serde_json::to_vec(self)
            .map_err(|_| AccountAccessError::Invalid("grant encoding"))?
            .len()
            > 4096
        {
            return Err(AccountAccessError::Invalid("grant budget"));
        }
        if self.server_id != descriptor.server_id
            || self.user_id != descriptor.user_id
            || self.key_epoch != descriptor.key_epoch
            || self.proof_public_key != descriptor.proof_public_key
        {
            return Err(AccountAccessError::Invalid("grant descriptor"));
        }
        let blob = decode(&self.blob, 2048)?;
        if !verify_ed25519(
            &array::<32>(&self.proof_public_key)?,
            Transcript::new("zann account grant signature v1")
                .field(self.aad()?.bytes())
                .field(&blob)
                .bytes(),
            &array::<64>(&self.signature)?,
        ) {
            return Err(AccountAccessError::Invalid("grant signature"));
        }
        Ok(())
    }
    pub fn open(&self, descriptor: &AccountDescriptor, prf: &AccountPrf) -> Result<SecretKey> {
        self.verify(descriptor)?;
        let blob = EncryptedBlob::from_bytes(&decode(&self.blob, 2048)?)?;
        let plain = Zeroizing::new(decrypt_blob(
            &self.wrapping_key(prf)?,
            &blob,
            self.aad()?.bytes(),
        )?);
        let bytes: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| AccountAccessError::Invalid("account key length"))?;
        let key = SecretKey::from_bytes(bytes);
        AccountCustody::derive(&key, &self.server_id, self.user_id, self.key_epoch)?
            .proves(descriptor)?;
        Ok(key)
    }
    pub fn body_digest(&self) -> Result<[u8; 32]> {
        Ok(self
            .context(Transcript::new("zann account grant body v1"))?
            .field(&decode(&self.blob, 2048)?)
            .field(&array::<64>(&self.signature)?)
            .digest())
    }
}
