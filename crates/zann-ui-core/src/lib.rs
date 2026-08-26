//! UI-facing view logic shared by every zann client.
//!
//! This crate holds the presentation rules that used to be duplicated in each
//! frontend: the navigation categories described by `schemas/ui_categories.json`,
//! the folder tree derived from item paths, the client-side item filter, TOTP
//! code generation, server URL normalization, settings semantics and the
//! translation catalogue.
//!
//! It deliberately depends on nothing but `serde` and two leaf crates: no
//! database, no HTTP, no UI toolkit, no FFI. Callers adapt their own item type
//! through the [`ItemLike`] trait instead of the crate reaching into theirs.

pub mod categories;
pub mod counts;
pub mod filter;
pub mod folders;
pub mod i18n;
pub mod item;
pub mod server_url;
pub mod settings;
pub mod totp;

pub use categories::{
    category, category_views, fallback_category, CategoriesSchema, Category, CategoryFilter,
    CategoryView, VaultScope,
};
pub use counts::ItemCounts;
pub use filter::{filtered_indices, item_matches, FolderFilter, ItemFilter};
pub use folders::{build_folder_tree, FolderNode, FolderTree};
pub use i18n::{Catalogue, LANGUAGES};
pub use item::{ItemLike, ItemView};
pub use server_url::normalize_server_url;
pub use settings::{DevicePreferences, SettingsSection};
pub use totp::{generate_totp, TotpCode, TotpError, TotpParams};
