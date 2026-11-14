//! Opaque, expiring cursors: never expose an unmatched item's ID to a browser.
use crate::{DaemonError, Result};
use std::time::{Duration, Instant};
use zann_client::app::local::{BrowserContext, BrowserCursor};
use zann_client::browser_ipc::decode_array;

struct Binding {
    token: String,
    public_key: String,
    nonce: [u8; 32],
    context: BrowserContext,
    cursor: BrowserCursor,
    expires: Instant,
}

#[derive(Default)]
pub(crate) struct CursorStore(Vec<Binding>);

impl CursorStore {
    pub fn begin(
        &mut self,
        token: Option<String>,
        key: &str,
        nonce: &[u8; 32],
        context: &BrowserContext,
    ) -> Result<Option<BrowserCursor>> {
        self.0.retain(|cursor| cursor.expires > Instant::now());
        let Some(token) = token else {
            return Ok(None);
        };
        decode_array::<32>(&token)?;
        let index = self
            .0
            .iter()
            .position(|c| {
                c.token == token
                    && c.public_key == key
                    && &c.nonce == nonce
                    && &c.context == context
            })
            .ok_or(DaemonError::Authentication)?;
        Ok(Some(self.0.swap_remove(index).cursor))
    }
    pub fn check_capacity(&self, nonce: &[u8; 32]) -> Result<()> {
        if self.0.len() >= 128 || self.0.iter().filter(|c| &c.nonce == nonce).count() >= 4 {
            return Err(DaemonError::Limit);
        }
        Ok(())
    }
    pub fn issue(
        &mut self,
        cursor: Option<BrowserCursor>,
        key: &str,
        nonce: &[u8; 32],
        context: &BrowserContext,
    ) -> Result<Option<String>> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        self.check_capacity(nonce)?;
        let token = hex::encode(zann_crypto::ipc_signatures::random_nonce());
        self.0.push(Binding {
            token: token.clone(),
            public_key: key.into(),
            nonce: *nonce,
            context: context.clone(),
            cursor,
            expires: Instant::now() + Duration::from_secs(30),
        });
        Ok(Some(token))
    }
    pub fn revoke(&mut self, key: &str) {
        self.0.retain(|cursor| cursor.public_key != key);
    }
}
