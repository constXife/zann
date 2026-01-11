mod actions;
pub(crate) mod args;
mod fetch;
mod format;
mod format_table;
mod http;
mod render;
mod render_fs;
mod resolve;
pub(crate) mod types;
mod utils;

pub(crate) use actions::{handle_get, handle_list, handle_materialize, handle_render};
pub(crate) use fetch::{fetch_shared_item, fetch_shared_items};
pub(crate) use format::{flatten_payload, format_env_flat, format_kv_flat, is_valid_env_key};
pub(crate) use format_table::print_list_table;
pub(crate) use http::fetch_vaults;
pub(crate) use render::render_shared_template;
pub(crate) use render_fs::materialize_shared;
pub(crate) use resolve::{
    resolve_path_arg, resolve_path_for_context, resolve_shared_item_id, resolve_vault_arg,
};
pub(crate) use types::{
    SharedItemResponse, SharedItemsResponse, SharedListJsonItem, SharedListJsonResponse,
    VaultListResponse,
};
pub(crate) use utils::{
    parse_selector_if_present, parse_template, parse_template_placeholder, secret_not_found_error,
    TemplateToken,
};
