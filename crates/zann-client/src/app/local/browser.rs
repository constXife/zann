//! Native selection leases for the shared browser wire model.
pub use crate::browser_ipc::{
    BrowserContext, BrowserMatch, BrowserScope, CapturedLogin, PasskeyMatches, PasskeyRequest,
    PasskeyResponse,
};
pub use zann_core::BROWSER_PAGE_LIMIT;
pub use zann_passkey as passkey_engine;

#[derive(Clone)]
pub struct BrowserCursor {
    pub after_id: String,
    pub scope: BrowserScope,
}

pub struct BrowserMatches {
    pub items: Vec<BrowserMatch>,
    pub scope: BrowserScope,
    pub next_cursor: Option<BrowserCursor>,
}
