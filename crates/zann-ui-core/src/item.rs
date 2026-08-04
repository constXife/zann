/// The item fields the shared view logic needs.
///
/// Every client already has its own item summary type (`zann_ffi::ItemSummary`,
/// the Tauri `ItemSummary`, ...). Implementing this trait for it avoids copying
/// items into a crate-local struct just to build a folder tree or run a filter.
pub trait ItemLike {
    fn title(&self) -> &str;
    fn type_id(&self) -> &str;
    fn path(&self) -> &str;
    fn is_deleted(&self) -> bool;
}

/// Owned item view, for callers that have no type of their own to adapt
/// (tests, ad-hoc conversions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemView {
    pub title: String,
    pub type_id: String,
    pub path: String,
    pub deleted: bool,
}

impl ItemLike for ItemView {
    fn title(&self) -> &str {
        &self.title
    }

    fn type_id(&self) -> &str {
        &self.type_id
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }
}

impl<T: ItemLike> ItemLike for &T {
    fn title(&self) -> &str {
        (*self).title()
    }

    fn type_id(&self) -> &str {
        (*self).type_id()
    }

    fn path(&self) -> &str {
        (*self).path()
    }

    fn is_deleted(&self) -> bool {
        (*self).is_deleted()
    }
}
