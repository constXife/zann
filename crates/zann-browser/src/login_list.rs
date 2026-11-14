//! Browser metadata projection over the shared presentation filter.
use wasm_bindgen::prelude::*;
use zann_client::browser_ipc::{BrowserMatch, SEARCH_MAX_MATCHES};
use zann_ui_core::login_list::{LoginList, LoginListItem, MAX_LOGIN_QUERY_CHARS};

struct Label(BrowserMatch);
impl LoginListItem for Label {
    fn title(&self) -> &str {
        &self.0.title
    }
    fn username(&self) -> Option<&str> {
        self.0.username.as_deref()
    }
}
#[wasm_bindgen]
pub struct NativeLoginList(LoginList<Label>);
#[wasm_bindgen]
impl NativeLoginList {
    #[wasm_bindgen(constructor)]
    pub fn new(items: &str) -> Result<Self, JsError> {
        if items.len() > crate::MAX_METADATA_BYTES {
            return Err(JsError::new("Login metadata exceeds its size limit."));
        }
        let items: Vec<BrowserMatch> = serde_json::from_str(items)?;
        if items.len() > SEARCH_MAX_MATCHES {
            return Err(JsError::new("Too many matching logins."));
        }
        Ok(Self(LoginList::new(items.into_iter().map(Label).collect())))
    }
    pub fn query_limit(&self) -> usize {
        MAX_LOGIN_QUERY_CHARS
    }
    pub fn total(&self) -> usize {
        self.0.total()
    }
    pub fn count(&self) -> usize {
        self.0.len()
    }
    pub fn filter(&mut self, query: &str) -> Result<usize, JsError> {
        Ok(self.0.filter(query)?)
    }
    pub fn window(&self, start: usize, limit: usize) -> Result<String, JsError> {
        if limit > 64 {
            return Err(JsError::new("Login window exceeds its size limit."));
        }
        let rows = self
            .0
            .window(start, limit)
            .ok_or_else(|| JsError::new("Login window is unavailable."))?;
        Ok(serde_json::to_string(
            &rows.into_iter().map(|row| &row.0).collect::<Vec<_>>(),
        )?)
    }
}
