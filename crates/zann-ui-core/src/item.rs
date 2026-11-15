/// The item fields the shared view logic needs.
///
/// Every client already has its own item summary type (`zann_ffi::ItemSummary`,
/// an FFI item projection, ...). Implementing this trait for it avoids copying
/// items into a crate-local struct just to build a folder tree or run a filter.
pub trait ItemLike {
    fn title(&self) -> &str;
    fn type_id(&self) -> &str;
    fn path(&self) -> &str;
    fn is_deleted(&self) -> bool;
}

/// Decode a domain-only item title for display. Paths, URLs and free text keep
/// their original spelling; this never changes stored identity or URL matching.
pub fn display_item_title(title: &str) -> String {
    if !title.split('.').any(|label| label.starts_with("xn--"))
        || title
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '/' | ':' | '@' | '?' | '#'))
    {
        return title.to_string();
    }
    let (unicode, validity) = idna::domain_to_unicode(title);
    if validity.is_ok() {
        unicode
    } else {
        title.to_string()
    }
}

#[cfg(test)]
mod title_tests {
    use super::display_item_title;

    #[test]
    fn domain_titles_are_readable_without_changing_other_item_names() {
        assert_eq!(display_item_title("xn--e1afmkfd.xn--p1ai"), "пример.рф");
        for name in [
            "GitHub",
            "work/xn--e1afmkfd.xn--p1ai",
            "xn--.test",
            "xn-- example",
            "https://xn--e1afmkfd.xn--p1ai",
        ] {
            assert_eq!(display_item_title(name), name);
        }
    }
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
