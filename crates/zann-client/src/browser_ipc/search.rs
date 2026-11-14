//! Complete metadata search over bounded, authenticated native pages.
use super::{decode_array, BrowserContext, BrowserMatch, BrowserScope, MatchPage, Request};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const SEARCH_DEADLINE_MS: f64 = 30_000.0;
pub const SEARCH_MAX_PAGES: u32 = 4096;
pub const SEARCH_MAX_MATCHES: usize = 8192;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SearchError {
    #[error("Invalid login search response. Refresh to search again.")]
    Protocol,
    #[error("The selected desktop vault changed. Refresh to search again.")]
    SelectionChanged,
    #[error("Login search timed out. Refresh to start a new search.")]
    Timeout,
    #[error("Login search exceeded its resource limit. No partial results were published.")]
    Limit,
}
type Result<T> = std::result::Result<T, SearchError>;

enum State {
    Ready(Option<String>),
    Waiting,
    Complete,
    Closed,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoginSearchResult {
    pub items: Vec<BrowserMatch>,
    pub scope: BrowserScope,
}
pub struct LoginSearch {
    context: BrowserContext,
    state: State,
    scope: Option<BrowserScope>,
    items: Vec<BrowserMatch>,
    item_indices: HashMap<String, usize>,
    cursors: HashSet<String>,
    pages: u32,
    elapsed_ms: f64,
}
impl LoginSearch {
    pub fn new(context: BrowserContext) -> super::Result<Self> {
        context.credential_context()?;
        Ok(Self {
            context,
            state: State::Ready(None),
            scope: None,
            items: Vec::new(),
            item_indices: HashMap::new(),
            cursors: HashSet::new(),
            pages: 0,
            elapsed_ms: 0.0,
        })
    }
    pub fn matches_found(&self) -> usize {
        self.items.len()
    }
    /// The platform adapter supplies elapsed monotonic milliseconds, never wall time.
    fn check_time(&mut self, elapsed_ms: f64) -> Result<()> {
        if !elapsed_ms.is_finite() || elapsed_ms < self.elapsed_ms {
            return Err(SearchError::Protocol);
        }
        self.elapsed_ms = elapsed_ms;
        if elapsed_ms >= SEARCH_DEADLINE_MS {
            return Err(SearchError::Timeout);
        }
        Ok(())
    }
    pub fn request(&mut self, elapsed_ms: f64) -> Result<Request> {
        let State::Ready(cursor) = std::mem::replace(&mut self.state, State::Closed) else {
            return Err(SearchError::Protocol);
        };
        self.check_time(elapsed_ms)?;
        if self.pages >= SEARCH_MAX_PAGES {
            return Err(SearchError::Limit);
        }
        self.state = State::Waiting;
        Ok(Request::Query {
            context: self.context.clone(),
            cursor,
        })
    }
    pub fn accept_page(&mut self, page: MatchPage, elapsed_ms: f64) -> Result<bool> {
        let state = std::mem::replace(&mut self.state, State::Closed);
        if !matches!(state, State::Waiting) {
            return Err(SearchError::Protocol);
        }
        self.check_time(elapsed_ms)?;
        if page.items.len() > zann_core::BROWSER_PAGE_LIMIT as usize {
            return Err(SearchError::Protocol);
        }
        match &self.scope {
            Some(scope) if scope != &page.scope => return Err(SearchError::SelectionChanged),
            None => self.scope = Some(page.scope),
            Some(_) => {}
        }
        for item in page.items {
            if let Some(index) = self.item_indices.get(&item.item_id) {
                if self.items[*index] != item {
                    return Err(SearchError::Protocol);
                }
                continue;
            }
            if self.items.len() >= SEARCH_MAX_MATCHES {
                return Err(SearchError::Limit);
            }
            self.item_indices
                .insert(item.item_id.clone(), self.items.len());
            self.items.push(item);
        }
        self.pages += 1;
        if let Some(cursor) = page.next_cursor {
            decode_array::<32>(&cursor).map_err(|_| SearchError::Protocol)?;
            if !self.cursors.insert(cursor.clone()) {
                return Err(SearchError::Protocol);
            }
            if self.pages >= SEARCH_MAX_PAGES {
                return Err(SearchError::Limit);
            }
            self.state = State::Ready(Some(cursor));
            Ok(false)
        } else {
            self.state = State::Complete;
            Ok(true)
        }
    }
    pub fn take_result(&mut self, elapsed_ms: f64) -> Result<LoginSearchResult> {
        let state = std::mem::replace(&mut self.state, State::Closed);
        if !matches!(state, State::Complete) {
            return Err(SearchError::Protocol);
        }
        self.check_time(elapsed_ms)?;
        Ok(LoginSearchResult {
            items: std::mem::take(&mut self.items),
            scope: self.scope.take().ok_or(SearchError::Protocol)?,
        })
    }
}
