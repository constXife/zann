//! Filtering and window projection of an already authorized, ranked login list.
//! No URL admission, usage writer or toolkit geometry lives here.
use crate::filter::TextQuery;

pub const MAX_LOGIN_QUERY_CHARS: usize = 256;

pub trait LoginListItem {
    fn title(&self) -> &str;
    fn username(&self) -> Option<&str>;
}
#[derive(Debug, thiserror::Error)]
#[error("Login search is limited to 256 characters.")]
pub struct QueryTooLong;

pub struct LoginList<T> {
    items: Vec<T>,
    indices: Vec<usize>,
}
impl<T: LoginListItem> LoginList<T> {
    pub fn new(items: Vec<T>) -> Self {
        let indices = (0..items.len()).collect();
        Self { items, indices }
    }
    pub fn total(&self) -> usize {
        self.items.len()
    }
    pub fn len(&self) -> usize {
        self.indices.len()
    }
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }
    /// Stable narrowing only: preserve match-quality/MRU order from the owner.
    pub fn filter(&mut self, query: &str) -> Result<usize, QueryTooLong> {
        if query.chars().count() > MAX_LOGIN_QUERY_CHARS {
            return Err(QueryTooLong);
        }
        let query = TextQuery::new(query);
        self.indices = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| query.matches(std::iter::once(item.title()).chain(item.username())))
            .map(|(index, _)| index)
            .collect();
        Ok(self.len())
    }
    pub fn window(&self, start: usize, limit: usize) -> Option<Vec<&T>> {
        let end = start.saturating_add(limit).min(self.len());
        Some(
            self.indices
                .get(start..end)?
                .iter()
                .map(|index| &self.items[*index])
                .collect(),
        )
    }
}
