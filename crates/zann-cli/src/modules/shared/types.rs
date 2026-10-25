use serde::Serialize;
use std::collections::BTreeMap;
pub use zann_core::api::items::*;

#[derive(Serialize)]
pub struct SharedListJsonItem {
    pub path: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct SharedListJsonResponse {
    pub items: Vec<SharedListJsonItem>,
    pub next_cursor: Option<String>,
}
