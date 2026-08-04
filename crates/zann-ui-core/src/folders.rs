use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::item::ItemLike;

/// One folder in the sidebar tree.
///
/// `item_count` is the number of items stored directly in this folder,
/// `total_count` also counts everything in its descendants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FolderNode {
    pub name: String,
    pub path: String,
    pub item_count: usize,
    pub total_count: usize,
    pub children: Vec<FolderNode>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FolderTree {
    /// Items whose path has no folder component, shown as a separate entry.
    pub items_without_folder: usize,
    pub tree: Vec<FolderNode>,
}

impl FolderTree {
    /// Every folder path in the tree, depth-first, for autocompletion.
    pub fn flat_paths(&self) -> Vec<String> {
        fn walk(nodes: &[FolderNode], out: &mut Vec<String>) {
            for node in nodes {
                out.push(node.path.clone());
                walk(&node.children, out);
            }
        }
        let mut paths = Vec::new();
        walk(&self.tree, &mut paths);
        paths
    }
}

/// The folder part of an item path, i.e. everything before the last segment.
///
/// Returns `None` for items that live at the root.
pub fn folder_of(path: &str) -> Option<&str> {
    path.rsplit_once('/')
        .map(|(folder, _)| folder)
        .filter(|folder| !folder.is_empty())
}

/// Build the folder tree from the loaded items.
///
/// Deleted items are ignored: they are shown under trash, not under their
/// original folder, so counting them here would inflate every badge.
pub fn build_folder_tree<I: ItemLike>(items: &[I]) -> FolderTree {
    let mut items_without_folder = 0usize;
    let mut direct_counts = BTreeMap::<String, usize>::new();
    let mut folders = BTreeSet::<String>::new();

    for item in items {
        if item.is_deleted() {
            continue;
        }
        let Some(folder) = folder_of(item.path()) else {
            items_without_folder += 1;
            continue;
        };

        *direct_counts.entry(folder.to_string()).or_insert(0) += 1;

        // Register the folder and every ancestor, so intermediate levels
        // without items of their own still show up.
        let mut ancestor = String::new();
        for segment in folder.split('/').filter(|segment| !segment.is_empty()) {
            if !ancestor.is_empty() {
                ancestor.push('/');
            }
            ancestor.push_str(segment);
            folders.insert(ancestor.clone());
        }
    }

    let mut children = BTreeMap::<String, BTreeSet<String>>::new();
    let mut roots = BTreeSet::<String>::new();
    for path in &folders {
        match path.rsplit_once('/') {
            Some((parent, _)) => {
                children
                    .entry(parent.to_string())
                    .or_default()
                    .insert(path.clone());
            }
            None => {
                roots.insert(path.clone());
            }
        }
    }

    let tree = roots
        .iter()
        .map(|path| build_node(path, &children, &direct_counts))
        .collect();

    FolderTree {
        items_without_folder,
        tree,
    }
}

fn build_node(
    path: &str,
    children: &BTreeMap<String, BTreeSet<String>>,
    direct_counts: &BTreeMap<String, usize>,
) -> FolderNode {
    let child_nodes: Vec<FolderNode> = children
        .get(path)
        .map(|paths| {
            paths
                .iter()
                .map(|child| build_node(child, children, direct_counts))
                .collect()
        })
        .unwrap_or_default();

    let item_count = direct_counts.get(path).copied().unwrap_or(0);
    let total_count = item_count
        + child_nodes
            .iter()
            .map(|child| child.total_count)
            .sum::<usize>();

    FolderNode {
        name: path.rsplit('/').next().unwrap_or(path).to_string(),
        path: path.to_string(),
        item_count,
        total_count,
        children: child_nodes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::ItemView;

    fn item(path: &str) -> ItemView {
        ItemView {
            title: path.to_string(),
            type_id: "login".to_string(),
            path: path.to_string(),
            deleted: false,
        }
    }

    fn deleted(path: &str) -> ItemView {
        ItemView {
            deleted: true,
            ..item(path)
        }
    }

    #[test]
    fn splits_folder_from_item_name() {
        assert_eq!(folder_of("work/aws/root"), Some("work/aws"));
        assert_eq!(folder_of("root"), None);
        assert_eq!(folder_of(""), None);
        assert_eq!(folder_of("/root"), None);
    }

    #[test]
    fn counts_rootless_items_separately() {
        let items = vec![item("alpha"), item(""), item("work/beta")];
        let tree = build_folder_tree(&items);
        assert_eq!(tree.items_without_folder, 2);
        assert_eq!(tree.tree.len(), 1);
    }

    #[test]
    fn rolls_counts_up_through_intermediate_folders() {
        let items = vec![
            item("work/aws/root"),
            item("work/aws/ci"),
            item("work/gcp/root"),
            item("work/notes"),
            item("personal/mail"),
        ];
        let tree = build_folder_tree(&items);

        assert_eq!(tree.items_without_folder, 0);
        let names: Vec<&str> = tree.tree.iter().map(|node| node.name.as_str()).collect();
        assert_eq!(names, vec!["personal", "work"]);

        let work = &tree.tree[1];
        assert_eq!(work.item_count, 1);
        assert_eq!(work.total_count, 4);

        let aws = &work.children[0];
        assert_eq!(aws.path, "work/aws");
        assert_eq!(aws.item_count, 2);
        assert_eq!(aws.total_count, 2);
    }

    #[test]
    fn deleted_items_do_not_count_towards_folders() {
        let items = vec![item("work/a"), deleted("work/b"), deleted("c")];
        let tree = build_folder_tree(&items);
        assert_eq!(tree.items_without_folder, 0);
        assert_eq!(tree.tree[0].total_count, 1);
    }

    #[test]
    fn flat_paths_are_depth_first() {
        let items = vec![item("work/aws/root"), item("personal/mail")];
        let tree = build_folder_tree(&items);
        assert_eq!(
            tree.flat_paths(),
            vec!["personal", "work", "work/aws"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }
}
