use crate::categories::{self, Category};
use crate::item::ItemLike;

/// Which folder the item list is narrowed to.
///
/// Clients spell the "no folder" selection differently in their own state
/// (`""` in the desktop app, `"__no_folder__"` in QML); they map it onto this
/// enum rather than the crate guessing a sentinel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum FolderFilter {
    #[default]
    Any,
    /// Only items that live at the root, with no folder component.
    WithoutFolder,
    /// The folder itself and everything below it.
    Path(String),
}

impl FolderFilter {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            FolderFilter::Any => true,
            FolderFilter::WithoutFolder => crate::folders::folder_of(path).is_none(),
            FolderFilter::Path(selected) => match crate::folders::folder_of(path) {
                Some(folder) => folder == selected || folder.starts_with(&format!("{selected}/")),
                None => false,
            },
        }
    }
}

/// The complete client-side narrowing of the loaded item list.
#[derive(Debug, Clone, Default)]
pub struct ItemFilter {
    /// Category id from the schema; an unknown id falls back to the schema's
    /// `fallback_category_id`.
    pub category_id: Option<String>,
    pub folder: FolderFilter,
    /// Free-text search over title, path and type. Leave empty when the
    /// backend already applied the query.
    pub query: String,
}

impl ItemFilter {
    pub fn category(&self) -> Option<&'static Category> {
        match self.category_id.as_deref() {
            None => categories::fallback_category(),
            Some(id) => categories::category(id).or_else(categories::fallback_category),
        }
    }

    pub fn matches<I: ItemLike + ?Sized>(&self, item: &I) -> bool {
        item_matches(item, self.category(), &self.folder) && matches_query(item, &self.query)
    }
}

/// Whether an item survives the category and folder narrowing.
pub fn item_matches<I: ItemLike + ?Sized>(
    item: &I,
    category: Option<&Category>,
    folder: &FolderFilter,
) -> bool {
    if let Some(category) = category {
        if !category.matches(item) {
            return false;
        }
    } else if item.is_deleted() {
        return false;
    }
    folder.matches(item.path())
}

/// Case-insensitive substring search over the fields shown in the list.
///
/// An empty query matches everything.
pub fn matches_query<I: ItemLike + ?Sized>(item: &I, query: &str) -> bool {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    [item.title(), item.path(), item.type_id()]
        .iter()
        .any(|field| field.to_lowercase().contains(&needle))
}

/// Positions of the items that pass `filter`, for list views that index back
/// into the unfiltered item vector.
pub fn filtered_indices<I: ItemLike>(items: &[I], filter: &ItemFilter) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| filter.matches(*item))
        .map(|(index, _)| index)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::ItemView;

    fn item(title: &str, type_id: &str, path: &str, deleted: bool) -> ItemView {
        ItemView {
            title: title.to_string(),
            type_id: type_id.to_string(),
            path: path.to_string(),
            deleted,
        }
    }

    fn sample() -> Vec<ItemView> {
        vec![
            item("AWS root", "login", "work/aws/root", false),
            item("CI token", "api", "work/aws/ci", false),
            item("Personal mail", "login", "personal/mail", false),
            item("Scratch", "note", "scratch", false),
            item("Old key", "ssh_key", "work/old", true),
        ]
    }

    #[test]
    fn folder_filter_includes_descendants() {
        let filter = FolderFilter::Path("work".to_string());
        assert!(filter.matches("work/aws/root"));
        assert!(filter.matches("work/notes"));
        assert!(!filter.matches("workshop/notes"));
        assert!(!filter.matches("scratch"));
    }

    #[test]
    fn without_folder_matches_root_items_only() {
        let filter = FolderFilter::WithoutFolder;
        assert!(filter.matches("scratch"));
        assert!(!filter.matches("work/aws/root"));
    }

    #[test]
    fn default_filter_hides_deleted_items() {
        let items = sample();
        let filter = ItemFilter::default();
        assert_eq!(filtered_indices(&items, &filter), vec![0, 1, 2, 3]);
    }

    #[test]
    fn trash_shows_deleted_items_only() {
        let items = sample();
        let filter = ItemFilter {
            category_id: Some("trash".to_string()),
            ..Default::default()
        };
        assert_eq!(filtered_indices(&items, &filter), vec![4]);
    }

    #[test]
    fn category_and_folder_narrow_together() {
        let items = sample();
        let filter = ItemFilter {
            category_id: Some("login".to_string()),
            folder: FolderFilter::Path("work".to_string()),
            query: String::new(),
        };
        assert_eq!(filtered_indices(&items, &filter), vec![0]);
    }

    #[test]
    fn query_searches_title_path_and_type() {
        let items = sample();
        let by_title = ItemFilter {
            query: "aws root".to_string(),
            ..Default::default()
        };
        assert_eq!(filtered_indices(&items, &by_title), vec![0]);

        let by_path = ItemFilter {
            query: "personal/".to_string(),
            ..Default::default()
        };
        assert_eq!(filtered_indices(&items, &by_path), vec![2]);

        let by_type = ItemFilter {
            query: "api".to_string(),
            ..Default::default()
        };
        assert_eq!(filtered_indices(&items, &by_type), vec![1]);
    }

    #[test]
    fn unknown_category_falls_back_instead_of_emptying_the_list() {
        let items = sample();
        let filter = ItemFilter {
            category_id: Some("does-not-exist".to_string()),
            ..Default::default()
        };
        assert_eq!(filtered_indices(&items, &filter), vec![0, 1, 2, 3]);
    }
}
