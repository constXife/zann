use super::*;

impl DeviceUnlock {
    fn account_aad(&self, storage: &str, envelope: &AccountKeyEnvelope) -> Vec<u8> {
        // JSON gives unambiguous, length-delimited bindings without a new crypto format.
        serde_json::to_vec(&(
            &self.device_id,
            storage,
            &envelope.server_id,
            &envelope.account_subject,
            envelope.origin,
        ))
        .expect("serializing string tuple cannot fail")
    }

    pub fn insert_account(
        &mut self,
        root: &SecretKey,
        storage: String,
        server_id: String,
        subject: String,
        key: &SecretKey,
        origin: crate::sync::AccountKeyOrigin,
    ) -> Result<(), DeviceUnlockError> {
        self.check_root(root)?;
        if self.accounts.len() >= model::MAX_ACCOUNTS {
            return Err(DeviceUnlockError::Invalid("keyring account limit reached"));
        }
        if self.accounts.contains_key(&storage) {
            return Err(DeviceUnlockError::Invalid(
                "account key is already enrolled",
            ));
        }
        let mut envelope = AccountKeyEnvelope {
            server_id,
            account_subject: subject,
            origin,
            ciphertext: String::new(),
        };
        model::validate_account_binding(&storage, &envelope)?;
        envelope.ciphertext = STANDARD.encode(
            encrypt_blob_verified(root, key.as_bytes(), &self.account_aad(&storage, &envelope))?
                .to_bytes(),
        );
        self.accounts.insert(storage, envelope);
        Ok(())
    }

    /// Authenticate purpose together with this exact account's key, even in an
    /// already-unlocked process. Decoding public JSON is not purpose admission.
    pub fn account_key(
        &self,
        root: &SecretKey,
        storage: &str,
    ) -> Result<(Arc<SecretKey>, crate::sync::AccountKeyOrigin), DeviceUnlockError> {
        self.check_root(root)?;
        let envelope = self
            .accounts
            .get(storage)
            .ok_or(DeviceUnlockError::Invalid("account key is not enrolled"))?;
        let key = open_key(
            root,
            &envelope.ciphertext,
            &self.account_aad(storage, envelope),
        )?;
        Ok((Arc::new(key), envelope.origin))
    }

    pub fn account_keys(
        &self,
        root: &SecretKey,
    ) -> Result<BTreeMap<String, Arc<SecretKey>>, DeviceUnlockError> {
        self.check_root(root)?;
        self.accounts
            .iter()
            .map(|(storage, envelope)| {
                Ok((
                    storage.clone(),
                    Arc::new(open_key(
                        root,
                        &envelope.ciphertext,
                        &self.account_aad(storage, envelope),
                    )?),
                ))
            })
            .collect()
    }
}
