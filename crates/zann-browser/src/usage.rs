//! Thin browser-local storage projection of shared ranking/retention policy.
use wasm_bindgen::prelude::*;
use zann_client::browser_ipc::{BrowserScope, BrowserUsage, LoginSearchResult};

#[wasm_bindgen]
pub struct NativeBrowserUsage(BrowserUsage);
#[wasm_bindgen]
impl NativeBrowserUsage {
    #[wasm_bindgen(constructor)]
    pub fn new(snapshot: &str) -> Result<Self, JsError> {
        Ok(Self(BrowserUsage::from_json(snapshot)?))
    }
    pub fn rank(&self, server: &str, result: &str) -> Result<String, JsError> {
        if result.len() > crate::MAX_METADATA_BYTES {
            return Err(JsError::new("Login metadata exceeds its size limit."));
        }
        let mut result: LoginSearchResult = serde_json::from_str(result)?;
        self.0.rank(server, &result.scope, &mut result.items)?;
        Ok(serde_json::to_string(&result)?)
    }
    pub fn record_success(&mut self, server: &str, scope: &str, item: &str) -> Result<(), JsError> {
        let scope: BrowserScope = serde_json::from_str(scope)?;
        Ok(self.0.record_success(server, &scope, item)?)
    }
    pub fn snapshot(&self) -> Result<String, JsError> {
        Ok(self.0.to_json()?)
    }
}
