//! UI-facing view logic shared by every zann client.
//!
//! This crate holds the presentation rules that used to be duplicated in each
//! frontend: the navigation categories described by `schemas/ui_categories.json`,
//! the folder tree derived from item paths, the client-side item filter, TOTP
//! code generation, item-detail field projection, server URL normalization,
//! settings semantics and the translation catalogue.
//!
//! It uses canonical domain payload types from `zann-core`, with no database
//! adapter, HTTP client, UI toolkit or FFI. Callers adapt their own list item
//! type through the [`ItemLike`] trait.

pub mod categories;
pub mod counts;
pub mod filter;
pub mod folders;
pub mod i18n;
pub mod item;
pub mod item_detail;
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
pub use item_detail::{project_item_fields, ItemDetailField};
pub use server_url::normalize_server_url;
pub use settings::{DevicePreferences, SettingsSection};
pub use totp::{generate_totp, TotpCode, TotpError, TotpParams};
