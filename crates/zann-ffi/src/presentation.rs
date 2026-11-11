//! `zann-ui-core` presentation rules projected over UniFFI.
//!
//! Each function is a one-to-one mirror: field order, masking, category and
//! folder semantics stay in `zann-ui-core`, so native shells render the same
//! lists the Rust shells do.

use zann_ui_core::settings::{
    AUTO_LOCK_MINUTES, CLIPBOARD_SECONDS, REVEAL_SECONDS, TRASH_RETENTION_DAYS,
};
use zann_ui_core::{
    CategoryView, DevicePreferences, FolderFilter, FolderNode, ItemDetailField, ItemFilter,
    TotpCode, TotpParams, VaultScope, LANGUAGES,
};

use crate::{CoreError, CoreResult, ItemCountsFfi, ItemSummary};

#[uniffi::export]
pub fn normalize_server_url(value: String) -> String {
    zann_ui_core::normalize_server_url(&value)
}

#[derive(Clone, uniffi::Record)]
pub struct TotpParamsFfi {
    pub secret: String,
    pub algorithm: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u32>,
}

impl std::fmt::Debug for TotpParamsFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpParamsFfi(<redacted>)")
    }
}

impl From<TotpParams> for TotpParamsFfi {
    fn from(params: TotpParams) -> Self {
        Self {
            secret: params.secret,
            algorithm: params.algorithm,
            digits: params.digits,
            period: params.period,
        }
    }
}

impl From<TotpParamsFfi> for TotpParams {
    fn from(params: TotpParamsFfi) -> Self {
        Self {
            secret: params.secret,
            algorithm: params.algorithm,
            digits: params.digits,
            period: params.period,
        }
    }
}

#[derive(Clone, uniffi::Record)]
pub struct ItemDetailFieldFfi {
    pub key: String,
    pub value: String,
    pub masked: bool,
    pub multiline: bool,
    pub totp: Option<TotpParamsFfi>,
}

impl std::fmt::Debug for ItemDetailFieldFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemDetailFieldFfi(<redacted>)")
    }
}

impl From<ItemDetailField> for ItemDetailFieldFfi {
    fn from(field: ItemDetailField) -> Self {
        Self {
            key: field.key,
            value: field.value,
            masked: field.masked,
            multiline: field.multiline,
            totp: field.totp.map(Into::into),
        }
    }
}

/// Item fields in canonical reading order with masking and TOTP metadata.
#[uniffi::export]
pub fn project_item_fields(payload_json: String) -> CoreResult<Vec<ItemDetailFieldFfi>> {
    zann_ui_core::project_item_fields(&payload_json)
        .map(|fields| fields.into_iter().map(Into::into).collect())
        .map_err(|error| CoreError::InvalidArgument(error.to_string()))
}

#[derive(Clone, uniffi::Record)]
pub struct TotpCodeFfi {
    pub code: String,
    pub remaining_seconds: u32,
    pub period: u32,
}

impl std::fmt::Debug for TotpCodeFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpCodeFfi(<redacted>)")
    }
}

impl From<TotpCode> for TotpCodeFfi {
    fn from(code: TotpCode) -> Self {
        Self {
            code: code.code,
            remaining_seconds: code.remaining_seconds,
            period: code.period,
        }
    }
}

#[uniffi::export]
pub fn generate_totp(params: TotpParamsFfi) -> CoreResult<TotpCodeFfi> {
    zann_ui_core::generate_totp(&params.into())
        .map(Into::into)
        .map_err(|error| CoreError::InvalidArgument(error.to_string()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum VaultScopeFfi {
    Personal,
    Shared,
}

impl From<VaultScopeFfi> for VaultScope {
    fn from(scope: VaultScopeFfi) -> Self {
        match scope {
            VaultScopeFfi::Personal => Self::Personal,
            VaultScopeFfi::Shared => Self::Shared,
        }
    }
}

/// A navigation category; the shell translates `label_key` and filters items
/// by passing `id` back in `ItemFilterFfi::category_id`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CategoryViewFfi {
    pub id: String,
    pub label_key: String,
    pub icon: String,
    pub order: i32,
    pub count: u64,
}

impl From<CategoryView> for CategoryViewFfi {
    fn from(view: CategoryView) -> Self {
        Self {
            id: view.id,
            label_key: view.label_key,
            icon: view.icon,
            order: view.order,
            count: view.count,
        }
    }
}

#[uniffi::export]
pub fn category_views(counts: ItemCountsFfi, scope: VaultScopeFfi) -> Vec<CategoryViewFfi> {
    zann_ui_core::category_views(&(&counts).into(), scope.into())
        .into_iter()
        .map(Into::into)
        .collect()
}

/// The type a new item takes when created from the selected category.
#[uniffi::export]
pub fn create_type_for_category(category_id: Option<String>) -> String {
    zann_ui_core::create_type_for(category_id.as_deref()).to_string()
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum FolderFilterFfi {
    Any,
    WithoutFolder,
    Path { path: String },
}

/// The client-side list filter over already loaded items, unlike the
/// storage query `ItemsFilter` passed to `CoreFacade::items_list`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemFilterFfi {
    pub category_id: Option<String>,
    pub folder: FolderFilterFfi,
    pub query: String,
}

impl From<ItemFilterFfi> for ItemFilter {
    fn from(filter: ItemFilterFfi) -> Self {
        Self {
            category_id: filter.category_id,
            folder: match filter.folder {
                FolderFilterFfi::Any => FolderFilter::Any,
                FolderFilterFfi::WithoutFolder => FolderFilter::WithoutFolder,
                FolderFilterFfi::Path { path } => FolderFilter::Path(path),
            },
            query: filter.query,
        }
    }
}

/// Positions in `items` of the entries that pass `filter`.
#[uniffi::export]
pub fn filter_items(items: Vec<ItemSummary>, filter: ItemFilterFfi) -> Vec<u64> {
    zann_ui_core::filtered_indices(&items, &filter.into())
        .into_iter()
        .map(|index| index as u64)
        .collect()
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FolderNodeFfi {
    pub name: String,
    pub path: String,
    pub item_count: u64,
    pub total_count: u64,
    pub children: Vec<FolderNodeFfi>,
}

impl From<FolderNode> for FolderNodeFfi {
    fn from(node: FolderNode) -> Self {
        Self {
            name: node.name,
            path: node.path,
            item_count: node.item_count as u64,
            total_count: node.total_count as u64,
            children: node.children.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FolderTreeFfi {
    pub items_without_folder: u64,
    pub tree: Vec<FolderNodeFfi>,
}

#[uniffi::export]
pub fn build_folder_tree(items: Vec<ItemSummary>) -> FolderTreeFfi {
    let tree = zann_ui_core::build_folder_tree(&items);
    FolderTreeFfi {
        items_without_folder: tree.items_without_folder as u64,
        tree: tree.tree.into_iter().map(Into::into).collect(),
    }
}

#[derive(Debug, Clone, Eq, PartialEq, uniffi::Record)]
pub struct DevicePreferencesFfi {
    pub language: Option<String>,
    pub auto_lock_minutes: u32,
    pub lock_on_focus_loss: bool,
    pub lock_on_hidden: bool,
    pub clipboard_clear_seconds: u32,
    pub clipboard_clear_on_lock: bool,
    pub clipboard_clear_on_exit: bool,
    pub clipboard_clear_if_unchanged: bool,
    pub auto_hide_reveal_seconds: u32,
    pub trash_auto_purge_days: u32,
}

impl From<DevicePreferences> for DevicePreferencesFfi {
    fn from(preferences: DevicePreferences) -> Self {
        Self {
            language: preferences.language,
            auto_lock_minutes: preferences.auto_lock_minutes,
            lock_on_focus_loss: preferences.lock_on_focus_loss,
            lock_on_hidden: preferences.lock_on_hidden,
            clipboard_clear_seconds: preferences.clipboard_clear_seconds,
            clipboard_clear_on_lock: preferences.clipboard_clear_on_lock,
            clipboard_clear_on_exit: preferences.clipboard_clear_on_exit,
            clipboard_clear_if_unchanged: preferences.clipboard_clear_if_unchanged,
            auto_hide_reveal_seconds: preferences.auto_hide_reveal_seconds,
            trash_auto_purge_days: preferences.trash_auto_purge_days,
        }
    }
}

#[uniffi::export]
pub fn device_preferences_default() -> DevicePreferencesFfi {
    DevicePreferences::default().into()
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct LanguageFfi {
    pub code: String,
    pub name: String,
}

/// The values a settings screen offers for each preference.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DevicePreferenceOptionsFfi {
    pub languages: Vec<LanguageFfi>,
    pub auto_lock_minutes: Vec<u32>,
    pub clipboard_clear_seconds: Vec<u32>,
    pub auto_hide_reveal_seconds: Vec<u32>,
    pub trash_auto_purge_days: Vec<u32>,
}

#[uniffi::export]
pub fn device_preference_options() -> DevicePreferenceOptionsFfi {
    DevicePreferenceOptionsFfi {
        languages: LANGUAGES
            .iter()
            .map(|(code, name)| LanguageFfi {
                code: (*code).to_string(),
                name: (*name).to_string(),
            })
            .collect(),
        auto_lock_minutes: AUTO_LOCK_MINUTES.to_vec(),
        clipboard_clear_seconds: CLIPBOARD_SECONDS.to_vec(),
        auto_hide_reveal_seconds: REVEAL_SECONDS.to_vec(),
        trash_auto_purge_days: TRASH_RETENTION_DAYS.to_vec(),
    }
}
