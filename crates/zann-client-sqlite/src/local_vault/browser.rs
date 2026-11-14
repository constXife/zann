use super::*;
use zann_autofill::{authorize_fill, FillContext, LoginMatcher, SiteUrl, UserGesture};

fn policy(source: impl std::error::Error + Send + Sync + 'static) -> LocalError {
    LocalError::BrowserPolicy(Box::new(source))
}

impl LocalVault {
    fn browser_block_on<T, E, F>(&self, future: F) -> LocalResult<T>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::error::Error + Send + Sync + 'static,
    {
        self.runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(2), future)
                .await
                .map_err(|_| LocalError::DeadlineExceeded)?
                .map_err(policy)
        })
    }
    pub fn browser_query(
        &self,
        context: BrowserContext,
        cursor: Option<BrowserCursor>,
        sink: &mut dyn FnMut(BrowserMatches) -> LocalResult<()>,
    ) -> LocalResult<()> {
        let (_, frame) = context.checked().map_err(policy)?;
        let _lease = self.context_gate.read().expect("lock poisoned");
        let key = self.account_key()?;
        let scope = BrowserScope {
            storage_id: self.storage_id()?.to_string(),
            vault_id: self.vault_id()?.to_string(),
            generation: self.context_generation.load(Ordering::SeqCst),
        };
        let after = match cursor {
            Some(cursor) if cursor.scope == scope => {
                Some(Uuid::parse_str(&cursor.after_id).map_err(policy)?)
            }
            Some(_) => {
                return Err(LocalError::InvalidArgument(
                    "browser selection changed".into(),
                ))
            }
            None => None,
        };
        let pool = self.pool();
        let service = LocalServices::new(&pool, key.as_ref());
        let (rows, next) = self.browser_block_on(service.browser_login_page(
            self.storage_id()?,
            self.vault_id()?,
            after,
        ))?;
        let mut items = Vec::new();
        for row in rows {
            // A login without a website is not an autofill candidate. This is
            // eligibility, not a hostname/default repair for malformed URLs.
            if !row.payload.fields.get("url").is_some_and(|field| {
                field.kind == zann_core::FieldKind::Url && !field.value.is_empty()
            }) {
                continue;
            }
            let matcher = LoginMatcher::from_payload(&row.payload).map_err(policy)?;
            if let Some(match_quality) = matcher.match_quality(&frame) {
                let username = row
                    .payload
                    .fields
                    .get("username")
                    .filter(|f| {
                        f.kind == zann_core::FieldKind::Text
                            && f.meta.as_ref().is_none_or(|m| m.masked != Some(true))
                    })
                    .map(|f| f.value.clone());
                if username
                    .as_ref()
                    .is_some_and(|u| u.len() > zann_core::BROWSER_MAX_USERNAME_BYTES)
                {
                    return Err(LocalError::InvalidArgument(
                        "browser username size bound".into(),
                    ));
                }
                items.push(BrowserMatch {
                    item_id: row.id.to_string(),
                    title: row.name,
                    username,
                    match_quality,
                });
            }
        }
        sink(BrowserMatches {
            items,
            scope: scope.clone(),
            next_cursor: next.map(|id| BrowserCursor {
                after_id: id.to_string(),
                scope,
            }),
        })
    }

    pub fn browser_fill(
        &self,
        context: BrowserContext,
        item_id: String,
        sink: &mut dyn FnMut(&EncryptedPayload) -> LocalResult<()>,
    ) -> LocalResult<()> {
        let (top, frame): (SiteUrl, SiteUrl) = context.checked().map_err(policy)?;
        let id = Uuid::parse_str(&item_id).map_err(policy)?;
        let _lease = self.context_gate.read().expect("lock poisoned");
        let key = self.account_key()?;
        let pool = self.pool();
        let storage = self.storage_id()?;
        let vault = self.vault_id()?;
        let row = self
            .browser_block_on(LocalItemRepo::new(&pool).get_by_id(storage, id))?
            .ok_or_else(|| LocalError::InvalidArgument("browser item unavailable".into()))?;
        if row.vault_id != vault || row.deleted_at.is_some() || row.type_id != "login" {
            return Err(LocalError::InvalidArgument(
                "browser item unavailable".into(),
            ));
        }
        let payload = self.browser_block_on(
            LocalServices::new(&pool, key.as_ref()).decrypt_payload_for_item(
                storage,
                vault,
                id,
                &row.payload_enc,
            ),
        )?;
        let matcher = LoginMatcher::from_payload(&payload).map_err(policy)?;
        authorize_fill(
            &matcher,
            &FillContext {
                top_level: &top,
                frame: &frame,
                gesture: UserGesture::Explicit,
            },
        )
        .map_err(policy)?;
        sink(&payload)
    }
}
