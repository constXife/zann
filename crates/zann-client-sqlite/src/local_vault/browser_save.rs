use super::*;

impl LocalVault {
    pub fn browser_save(
        &self,
        context: BrowserContext,
        scope: BrowserScope,
        mut login: CapturedLogin,
        sink: &mut dyn FnMut(String) -> LocalResult<()>,
    ) -> LocalResult<()> {
        let policy = |error| LocalError::BrowserPolicy(Box::new(error));
        let (_, frame) = context.credential_context().map_err(policy)?;
        login.validate().map_err(policy)?;
        let _lease = self.context_gate.read().expect("lock poisoned");
        let key = self.account_key()?;
        let storage = self.storage_id()?;
        let vault = self.vault_id()?;
        if scope
            != (BrowserScope {
                storage_id: storage.to_string(),
                vault_id: vault.to_string(),
                generation: self.context_generation.load(Ordering::SeqCst),
            })
        {
            return Err(LocalError::InvalidArgument(
                "browser selection changed".into(),
            ));
        }
        let mut payload = EncryptedPayload::new("login");
        payload.fields.insert(
            "url".into(),
            zann_core::FieldValue {
                kind: zann_core::FieldKind::Url,
                value: frame.origin_url(),
                meta: None,
            },
        );
        payload.fields.insert(
            "username".into(),
            zann_core::FieldValue {
                kind: zann_core::FieldKind::Text,
                value: std::mem::take(&mut login.username),
                meta: None,
            },
        );
        payload.fields.insert(
            "password".into(),
            zann_core::FieldValue {
                kind: zann_core::FieldKind::Password,
                value: std::mem::take(&mut login.password),
                meta: None,
            },
        );
        let pool = self.pool();
        let service = LocalServices::new(&pool, key.as_ref());
        let id = self.runtime.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                service.put_item_with_metadata(
                    storage,
                    vault,
                    login.title.clone(),
                    "login".into(),
                    payload,
                    zann_core::ItemMetadata::default(),
                ),
            )
            .await
            .map_err(|_| LocalError::DeadlineExceeded)?
            .map_err(LocalError::BrowserPolicy)
        })?;
        sink(id.to_string())
    }
}
