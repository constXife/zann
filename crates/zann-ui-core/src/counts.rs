use std::collections::BTreeMap;

use crate::item::ItemLike;

/// Item counts used to render category badges.
///
/// `all` and `trash` are totals reported by the backend (they cover items that
/// have not been paged in yet), `by_type` maps `type_id` to its count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemCounts {
    pub all: u64,
    pub trash: u64,
    pub by_type: BTreeMap<String, u64>,
}

impl ItemCounts {
    pub fn new(all: u64, trash: u64) -> Self {
        Self {
            all,
            trash,
            by_type: BTreeMap::new(),
        }
    }

    pub fn with_type(mut self, type_id: impl Into<String>, count: u64) -> Self {
        self.by_type.insert(type_id.into(), count);
        self
    }

    pub fn of_type(&self, type_id: &str) -> u64 {
        self.by_type.get(type_id).copied().unwrap_or(0)
    }

    /// Sum the counts of several types, e.g. every type in a category filter.
    pub fn sum_types<S: AsRef<str>>(&self, type_ids: &[S]) -> u64 {
        type_ids
            .iter()
            .map(|type_id| self.of_type(type_id.as_ref()))
            .sum()
    }

    /// Derive counts from the items currently loaded.
    ///
    /// Only correct when the caller holds the full item set; prefer the
    /// backend-reported counts when paging.
    pub fn from_items<I: ItemLike>(items: &[I]) -> Self {
        let mut counts = Self::default();
        for item in items {
            if item.is_deleted() {
                counts.trash += 1;
                continue;
            }
            counts.all += 1;
            *counts
                .by_type
                .entry(item.type_id().to_string())
                .or_insert(0) += 1;
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::ItemView;

    fn item(type_id: &str, path: &str, deleted: bool) -> ItemView {
        ItemView {
            title: path.to_string(),
            type_id: type_id.to_string(),
            path: path.to_string(),
            deleted,
        }
    }

    #[test]
    fn counts_items_by_type_and_skips_deleted_from_all() {
        let items = vec![
            item("login", "a", false),
            item("login", "b", false),
            item("note", "c", false),
            item("card", "d", true),
        ];
        let counts = ItemCounts::from_items(&items);
        assert_eq!(counts.all, 3);
        assert_eq!(counts.trash, 1);
        assert_eq!(counts.of_type("login"), 2);
        assert_eq!(counts.of_type("note"), 1);
        assert_eq!(counts.of_type("card"), 0);
    }

    #[test]
    fn sums_types_of_a_category_filter() {
        let counts = ItemCounts::new(10, 0)
            .with_type("ssh_key", 3)
            .with_type("database", 2);
        assert_eq!(counts.sum_types(&["ssh_key", "database", "missing"]), 5);
    }
}
