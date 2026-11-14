//! Coarse-grained projection of the canonical complete-login search.
use wasm_bindgen::prelude::*;
use zann_client::browser_ipc::{BrowserContext, LoginSearch, MatchPage};

#[wasm_bindgen]
pub struct NativeLoginSearch(LoginSearch);
#[wasm_bindgen]
impl NativeLoginSearch {
    #[wasm_bindgen(constructor)]
    pub fn new(context: &str) -> Result<Self, JsError> {
        let context: BrowserContext = serde_json::from_str(context)?;
        Ok(Self(LoginSearch::new(context)?))
    }
    pub fn request(&mut self, elapsed_ms: f64) -> Result<String, JsError> {
        Ok(serde_json::to_string(&self.0.request(elapsed_ms)?)?)
    }
    pub fn accept_page(&mut self, page: &str, elapsed_ms: f64) -> Result<bool, JsError> {
        let page: MatchPage = serde_json::from_str(page)?;
        Ok(self.0.accept_page(page, elapsed_ms)?)
    }
    pub fn matches_found(&self) -> usize {
        self.0.matches_found()
    }
    pub fn result(&mut self, elapsed_ms: f64) -> Result<String, JsError> {
        Ok(serde_json::to_string(&self.0.take_result(elapsed_ms)?)?)
    }
}
