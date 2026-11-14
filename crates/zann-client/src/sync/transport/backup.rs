use super::*;

impl HttpSyncRemote {
    pub(crate) async fn create_backup_vault(
        &self,
        access: &SessionAccess,
        slug: &str,
        name: &str,
        timeout: Duration,
    ) -> Result<(), RemoteError> {
        #[derive(Serialize)]
        struct Request {
            slug: String,
            name: String,
            kind: zann_core::VaultKind,
            cache_policy: zann_core::CachePolicy,
            vault_key_enc: Option<Vec<u8>>,
            tags: Option<Vec<String>>,
        }
        let request = Request {
            slug: slug.to_string(),
            name: name.to_string(),
            kind: zann_core::VaultKind::Shared,
            cache_policy: zann_core::CachePolicy::Full,
            vault_key_enc: None,
            tags: None,
        };
        let _: super::super::wire::VaultDetailWire = self
            .post_json(
                access,
                "v1/vaults",
                &request,
                timeout,
                MAX_DETAIL_BODY_BYTES,
            )
            .await?;
        Ok(())
    }
}
