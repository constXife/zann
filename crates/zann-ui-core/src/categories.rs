use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::counts::ItemCounts;
use crate::item::ItemLike;

/// The navigation schema shared by every client, embedded at compile time.
pub const UI_CATEGORIES_SCHEMA: &str = include_str!("../../../schemas/ui_categories.json");

/// Whether the categories are rendered for a personal or a shared vault.
///
/// The schema uses it twice: to hide categories scoped to one kind of vault,
/// and to pick a different label (trash is "Shared trash" in a shared vault).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VaultScope {
    #[default]
    Personal,
    Shared,
}

impl VaultScope {
    fn as_str(self) -> &'static str {
        match self {
            VaultScope::Personal => "personal",
            VaultScope::Shared => "shared",
        }
    }

    fn allows(self, declared: Option<&str>) -> bool {
        match declared {
            None | Some("both") => true,
            Some(scope) => scope == self.as_str(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CategoriesSchema {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub fallback_category_id: String,
    #[serde(default)]
    pub categories: Vec<Category>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Category {
    pub id: String,
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub icon: String,
    #[serde(default)]
    pub view: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub order: i32,
    #[serde(default)]
    pub filter: Option<CategoryFilter>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Label {
    pub key: String,
    #[serde(default)]
    pub when: Option<LabelCondition>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LabelCondition {
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CategoryFilter {
    #[serde(default)]
    pub type_ids: Option<Vec<String>>,
    #[serde(default)]
    pub is_deleted: Option<bool>,
}

/// A category resolved for rendering: label key, icon name and badge count.
///
/// The label is an i18n key and the icon a schema-level name; mapping them to
/// translated text and toolkit icon names stays with the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct CategoryView {
    pub id: String,
    pub label_key: String,
    pub icon: String,
    pub order: i32,
    pub count: u64,
    pub filter: Option<CategoryFilter>,
}

impl Category {
    /// Trash is the one category whose contents are the deleted items.
    pub fn is_trash(&self) -> bool {
        self.view.as_deref() == Some("trash") || self.id == "trash"
    }

    pub fn visible_in(&self, scope: VaultScope) -> bool {
        scope.allows(self.scope.as_deref())
    }

    /// The most specific label key for `scope`, falling back to the
    /// unconditional one.
    pub fn label_key(&self, scope: VaultScope) -> &str {
        self.labels
            .iter()
            .find(|label| {
                label
                    .when
                    .as_ref()
                    .and_then(|when| when.scope.as_deref())
                    .is_some_and(|declared| declared == scope.as_str())
            })
            .or_else(|| self.labels.iter().find(|label| label.when.is_none()))
            .or_else(|| self.labels.first())
            .map(|label| label.key.as_str())
            .unwrap_or("")
    }

    /// Badge count for this category.
    pub fn count(&self, counts: &ItemCounts) -> u64 {
        if self.is_trash() {
            return counts.trash;
        }
        match self.filter.as_ref().and_then(|f| f.type_ids.as_ref()) {
            // No type restriction means "everything that is not deleted".
            None => counts.all,
            Some(type_ids) => counts.sum_types(type_ids),
        }
    }

    /// Whether a loaded item belongs to this category.
    pub fn matches<I: ItemLike + ?Sized>(&self, item: &I) -> bool {
        if self.is_trash() {
            return item.is_deleted();
        }
        let Some(filter) = self.filter.as_ref() else {
            return !item.is_deleted();
        };
        if let Some(is_deleted) = filter.is_deleted {
            if is_deleted != item.is_deleted() {
                return false;
            }
        }
        if let Some(type_ids) = filter.type_ids.as_ref() {
            if !type_ids.iter().any(|type_id| type_id == item.type_id()) {
                return false;
            }
        }
        true
    }

    pub fn to_view(&self, counts: &ItemCounts, scope: VaultScope) -> CategoryView {
        CategoryView {
            id: self.id.clone(),
            label_key: self.label_key(scope).to_string(),
            icon: self.icon.clone(),
            order: self.order,
            count: self.count(counts),
            filter: self.filter.clone(),
        }
    }
}

/// The parsed schema.
///
/// The JSON is embedded at compile time and lives in this repository, so a
/// parse failure is a build bug rather than a runtime condition — `schema_parses`
/// keeps CI honest about it.
pub fn schema() -> &'static CategoriesSchema {
    static SCHEMA: OnceLock<CategoriesSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(UI_CATEGORIES_SCHEMA).expect("schemas/ui_categories.json is malformed")
    })
}

pub fn category(id: &str) -> Option<&'static Category> {
    schema().categories.iter().find(|cat| cat.id == id)
}

/// The category to fall back to when the selected id is unknown.
pub fn fallback_category() -> Option<&'static Category> {
    category(&schema().fallback_category_id)
}

/// Every category visible in `scope`, ordered as the schema declares.
pub fn category_views(counts: &ItemCounts, scope: VaultScope) -> Vec<CategoryView> {
    let mut views: Vec<CategoryView> = schema()
        .categories
        .iter()
        .filter(|cat| cat.visible_in(scope))
        .map(|cat| cat.to_view(counts, scope))
        .collect();
    views.sort_by_key(|view| view.order);
    views
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::ItemView;

    fn item(type_id: &str, deleted: bool) -> ItemView {
        ItemView {
            title: "Item".to_string(),
            type_id: type_id.to_string(),
            path: "root/item".to_string(),
            deleted,
        }
    }

    #[test]
    fn schema_parses() {
        let schema = schema();
        assert!(!schema.categories.is_empty());
        assert!(category(&schema.fallback_category_id).is_some());
    }

    #[test]
    fn views_are_ordered_and_counted() {
        let counts = ItemCounts::new(12, 4)
            .with_type("login", 5)
            .with_type("ssh_key", 2)
            .with_type("database", 1);
        let views = category_views(&counts, VaultScope::Personal);

        let orders: Vec<i32> = views.iter().map(|view| view.order).collect();
        let mut sorted = orders.clone();
        sorted.sort_unstable();
        assert_eq!(orders, sorted);

        let by_id = |id: &str| {
            views
                .iter()
                .find(|view| view.id == id)
                .unwrap_or_else(|| panic!("category {id} missing"))
        };
        assert_eq!(by_id("all").count, 12);
        assert_eq!(by_id("trash").count, 4);
        assert_eq!(by_id("login").count, 5);
        assert_eq!(by_id("infra").count, 3);
    }

    #[test]
    fn trash_label_depends_on_scope() {
        let trash = category("trash").expect("trash category");
        assert_eq!(trash.label_key(VaultScope::Personal), "nav.trash");
        assert_eq!(trash.label_key(VaultScope::Shared), "items.trashShared");
    }

    #[test]
    fn trash_matches_only_deleted_items() {
        let trash = category("trash").expect("trash category");
        assert!(trash.matches(&item("login", true)));
        assert!(!trash.matches(&item("login", false)));
    }

    #[test]
    fn typed_category_matches_its_types_only() {
        let infra = category("infra").expect("infra category");
        assert!(infra.matches(&item("ssh_key", false)));
        assert!(!infra.matches(&item("login", false)));
        assert!(!infra.matches(&item("ssh_key", true)));
    }

    #[test]
    fn all_matches_every_live_item() {
        let all = category("all").expect("all category");
        assert!(all.matches(&item("login", false)));
        assert!(all.matches(&item("ssh_key", false)));
        assert!(!all.matches(&item("login", true)));
    }
}
