use cxx_qt::CxxQtType;
use cxx_qt_lib::{QString, QStringList};
use data_encoding::BASE32;
use serde::Deserialize;
use std::sync::{mpsc, Arc};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP};
use tokio::runtime::Runtime;
use zann_client::types::OidcLoginStatusResponse;
use zann_db::{connect_sqlite_with_max, migrate_local};
use zann_core::AuthMethod;
use zann_ffi::{create_core, CoreFacade, CoreResult, ItemCountsFfi, ItemsFilter, Page};

/// Embed the UI categories schema at compile time
const UI_CATEGORIES_SCHEMA: &str = include_str!("../../../schemas/ui_categories.json");
const LOCAL_DB_FILENAME: &str = "local.sqlite";

/// Schema parsing structures
#[derive(Clone, Deserialize)]
struct UiCategoriesSchema {
    categories: Vec<CategoryDef>,
    #[allow(dead_code)]
    fallback_category_id: String,
}

#[derive(Clone, Deserialize)]
struct CategoryDef {
    id: String,
    labels: Vec<LabelDef>,
    icon: String,
    order: i32,
    filter: Option<CategoryFilter>,
}

#[derive(Clone, Deserialize)]
struct LabelDef {
    key: String,
}

#[derive(Clone, Deserialize)]
struct CategoryFilter {
    type_ids: Option<Vec<String>>,
    #[allow(dead_code)]
    is_deleted: Option<bool>,
}

/// Map schema icon names to Kirigami icon names
fn map_icon_to_kirigami(schema_icon: &str) -> &'static str {
    match schema_icon {
        "grid" => "view-list-icons",
        "key" => "dialog-password",
        "doc" => "text-x-generic",
        "card" => "view-bank-card",
        "person" => "contact-new",
        "network" => "preferences-system-network",
        "list" => "view-list-text",
        "trash" => "user-trash",
        _ => "folder-symbolic",
    }
}

/// Map i18n label keys to English strings (Qt i18n integration can be added later)
fn translate_label_key(key: &str) -> &'static str {
    match key {
        "nav.allItems" => "All items",
        "nav.logins" => "Logins",
        "nav.notes" => "Notes",
        "nav.cards" => "Cards",
        "nav.identity" => "Identity",
        "nav.api" => "API keys",
        "nav.kv" => "Key/Value",
        "nav.infrastructure" => "Infrastructure",
        "nav.trash" => "Trash",
        _ => "Unknown",
    }
}

struct VaultRow {
    id: String,
    name: String,
    is_default: bool,
    item_count: u64,
}

struct StorageRow {
    id: String,
    name: String,
}

pub struct AppModelRust {
    message: QString,
    counter: i32,
    storages: QStringList,
    storages_raw: Vec<StorageRow>,
    vaults: QStringList,
    current_storage_index: i32,
    current_vault_index: i32,
    vaults_raw: Vec<VaultRow>,
    unlocked: bool,
    status: QString,
    core: Option<Arc<CoreFacade>>,
    client_state: Option<zann_client::ClientState>,
    items: Vec<zann_ffi::ItemSummary>,
    items_next_cursor: Option<String>,
    items_has_more: bool,
    filtered_indices: Vec<usize>,
    filtered_items_count: i32,
    current_category: QString,
    selected_folder: QString,
    categories_json: QString,
    folders_json: QString,
    selected_item_id: QString,
    selected_item_json: QString,
    search_query: QString,
    // Setup wizard state
    app_state: QString,      // "loading" | "welcome" | "password" | "connect" | "unlock" | "main"
    setup_flow: QString,     // "local" | "remote"
    setup_error: QString,
    setup_busy: bool,
    setup_password_mode: QString, // "create" | "unlock"
    setup_storage_id: QString,
    connect_server_url: QString,
    connect_status: QString, // "" | "waiting" | "fingerprint" | "success"
    connect_error: QString,
    connect_busy: bool,
    connect_login_id: QString,
    connect_verification: QString,
    connect_old_fp: QString,
    connect_new_fp: QString,
    connect_methods: QStringList,
    connect_password_mode: QString, // "login" | "register"
    oidc_rx: Option<std::sync::mpsc::Receiver<zann_client::types::OidcLoginStatusResponse>>,
}

impl Default for AppModelRust {
    fn default() -> Self {
        let storages_raw = Vec::new();
        let storages = build_storages_list(&storages_raw);
        let vaults_raw = Vec::new();
        let vaults = build_vaults_list(&vaults_raw);

        Self {
            message: QString::from("Hello from Rust"),
            counter: 0,
            storages,
            storages_raw,
            vaults,
            current_storage_index: 0,
            current_vault_index: 0,
            vaults_raw,
            unlocked: false,
            status: QString::from("Locked"),
            core: None,
            client_state: None,
            items: Vec::new(),
            items_next_cursor: None,
            items_has_more: false,
            filtered_indices: Vec::new(),
            filtered_items_count: 0,
            current_category: QString::from("all"),
            selected_folder: QString::from(""),
            categories_json: QString::from("[]"),
            folders_json: QString::from("{\"items_without_folder\":0,\"tree\":[]}"),
            selected_item_id: QString::from(""),
            selected_item_json: QString::from(""),
            search_query: QString::from(""),
            // Setup wizard state
            app_state: QString::from("loading"),
            setup_flow: QString::from("local"),
            setup_error: QString::from(""),
            setup_busy: false,
            setup_password_mode: QString::from("create"),
            setup_storage_id: QString::from(""),
            connect_server_url: QString::from(""),
            connect_status: QString::from(""),
            connect_error: QString::from(""),
            connect_busy: false,
            connect_login_id: QString::from(""),
            connect_verification: QString::from(""),
            connect_old_fp: QString::from(""),
            connect_new_fp: QString::from(""),
            connect_methods: QStringList::default(),
            connect_password_mode: QString::from("login"),
            oidc_rx: None,
        }
    }
}

#[cxx_qt::bridge(namespace = "zann")]
mod ffi {
    #[namespace = ""]
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        include!("cxx-qt-lib/qstringlist.h");
        type QString = cxx_qt_lib::QString;
        type QStringList = cxx_qt_lib::QStringList;
    }

    #[namespace = ""]
    unsafe extern "C++" {
        include!("clipboard.h");

        type QClipboard;

        #[rust_name = "get_clipboard"]
        unsafe fn zann_get_clipboard() -> *mut QClipboard;

        #[rust_name = "clipboard_set_text"]
        unsafe fn zann_clipboard_set_text(clipboard: *mut QClipboard, text: &QString);
    }

    #[qml_element]
    qnamespace!("zann");

    extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qproperty(QString, message, READ, WRITE = set_message, NOTIFY = message_changed)]
        #[qproperty(i32, counter, READ, NOTIFY = counter_changed)]
        #[qproperty(QStringList, storages, READ, NOTIFY = storages_changed)]
        #[qproperty(QStringList, vaults, READ, NOTIFY = vaults_changed)]
        #[qproperty(
            i32,
            current_storage_index,
            READ,
            WRITE = set_current_storage_index,
            NOTIFY = current_storage_index_changed
        )]
        #[qproperty(
            i32,
            current_vault_index,
            READ,
            WRITE = set_current_vault_index,
            NOTIFY = current_vault_index_changed
        )]
        #[qproperty(bool, unlocked, READ, NOTIFY = unlocked_changed)]
        #[qproperty(QString, status, READ, NOTIFY = status_changed)]
        #[qproperty(bool, items_has_more, READ, NOTIFY = items_has_more_changed)]
        #[qproperty(i32, filtered_items_count, READ, NOTIFY = filtered_items_count_changed)]
        #[qproperty(QString, current_category, READ, WRITE = set_current_category, NOTIFY = current_category_changed)]
        #[qproperty(QString, selected_folder, READ, WRITE = set_selected_folder, NOTIFY = selected_folder_changed)]
        #[qproperty(QString, categories_json, READ, NOTIFY = categories_json_changed)]
        #[qproperty(QString, folders_json, READ, NOTIFY = folders_json_changed)]
        #[qproperty(QString, selected_item_id, READ, NOTIFY = selected_item_id_changed)]
        #[qproperty(QString, selected_item_json, READ, NOTIFY = selected_item_json_changed)]
        #[qproperty(QString, search_query, READ, WRITE = set_search_query, NOTIFY = search_query_changed)]
        #[qproperty(QString, app_state, READ, NOTIFY = app_state_changed)]
        #[qproperty(QString, setup_flow, READ, NOTIFY = setup_flow_changed)]
        #[qproperty(QString, setup_error, READ, NOTIFY = setup_error_changed)]
        #[qproperty(bool, setup_busy, READ, NOTIFY = setup_busy_changed)]
        #[qproperty(QString, setup_password_mode, READ, NOTIFY = setup_password_mode_changed)]
        #[qproperty(QString, connect_server_url, READ, WRITE = set_connect_server_url, NOTIFY = connect_server_url_changed)]
        #[qproperty(QString, connect_status, READ, NOTIFY = connect_state_changed)]
        #[qproperty(QString, connect_error, READ, NOTIFY = connect_error_changed)]
        #[qproperty(bool, connect_busy, READ, NOTIFY = connect_busy_changed)]
        #[qproperty(QString, connect_login_id, READ, NOTIFY = connect_login_id_changed)]
        #[qproperty(QString, connect_verification, READ, NOTIFY = connect_verification_changed)]
        #[qproperty(QString, connect_old_fp, READ, NOTIFY = connect_old_fp_changed)]
        #[qproperty(QString, connect_new_fp, READ, NOTIFY = connect_new_fp_changed)]
        #[qproperty(QStringList, connect_methods, READ, NOTIFY = connect_methods_changed)]
        #[qproperty(QString, connect_password_mode, READ, NOTIFY = connect_password_mode_changed)]
        type AppModel = super::AppModelRust;

        #[qsignal]
        fn message_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn counter_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn storages_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn vaults_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn current_storage_index_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn current_vault_index_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn unlocked_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn status_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn items_has_more_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn filtered_items_count_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn current_category_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn selected_folder_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn categories_json_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn folders_json_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn selected_item_id_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn selected_item_json_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn search_query_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn app_state_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn setup_flow_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn setup_error_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn setup_busy_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn setup_password_mode_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn connect_server_url_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn connect_state_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn connect_error_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn connect_busy_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn connect_login_id_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn connect_verification_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn connect_old_fp_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn connect_new_fp_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn connect_methods_changed(self: Pin<&mut AppModel>);
        #[qsignal]
        fn connect_password_mode_changed(self: Pin<&mut AppModel>);

        #[qinvokable]
        fn bump(self: Pin<&mut AppModel>);
        fn set_message(self: Pin<&mut AppModel>, value: QString);
        fn set_current_storage_index(self: Pin<&mut AppModel>, value: i32);
        fn set_current_vault_index(self: Pin<&mut AppModel>, value: i32);
        fn set_current_category(self: Pin<&mut AppModel>, value: QString);
        fn set_selected_folder(self: Pin<&mut AppModel>, value: QString);
        fn set_search_query(self: Pin<&mut AppModel>, value: QString);
        fn set_connect_server_url(self: Pin<&mut AppModel>, value: QString);
        #[qinvokable]
        fn lock(self: Pin<&mut AppModel>);
        #[qinvokable]
        fn unlock(self: Pin<&mut AppModel>, password: QString);
        #[qinvokable]
        fn select_item(self: Pin<&mut AppModel>, item_id: QString);
        #[qinvokable]
        fn load_more_items(self: Pin<&mut AppModel>);
        #[qinvokable]
        fn filtered_item_json(self: Pin<&mut AppModel>, index: i32) -> QString;
        #[qinvokable]
        fn copy_to_clipboard(self: Pin<&mut AppModel>, text: QString);
        #[qinvokable]
        fn generate_totp(
            self: Pin<&mut AppModel>,
            secret: QString,
            algorithm: QString,
            digits: i32,
            period: i32,
        ) -> QString;
        #[qinvokable]
        fn check_app_status(self: Pin<&mut AppModel>);
        #[qinvokable]
        fn start_local_setup(self: Pin<&mut AppModel>);
        #[qinvokable]
        fn start_connect(self: Pin<&mut AppModel>);
        #[qinvokable]
        fn back_to_welcome(self: Pin<&mut AppModel>);
        #[qinvokable]
        fn create_master_password(self: Pin<&mut AppModel>, password: QString, confirm: QString);
        #[qinvokable]
        fn begin_server_connect(self: Pin<&mut AppModel>);
        #[qinvokable]
        fn connect_with_oidc(self: Pin<&mut AppModel>);
        #[qinvokable]
        fn connect_with_password(
            self: Pin<&mut AppModel>,
            email: QString,
            password: QString,
            full_name: QString,
            mode: QString,
        );
        #[qinvokable]
        fn trust_fingerprint(self: Pin<&mut AppModel>);
        #[qinvokable]
        fn poll_oidc_status(self: Pin<&mut AppModel>);
        #[qinvokable]
        fn debug_force_remote_setup(self: Pin<&mut AppModel>, storage_id: QString, has_personal_keys: bool);
        #[qinvokable]
        fn debug_reset_core(self: Pin<&mut AppModel>, db_url: QString);
        #[qinvokable]
        fn debug_cleanup_db(self: Pin<&mut AppModel>, db_url: QString);
        #[qinvokable]
        fn debug_make_temp_db_url(self: Pin<&mut AppModel>, prefix: QString) -> QString;
        #[qinvokable]
        fn debug_get_env(self: Pin<&mut AppModel>, key: QString) -> QString;
        #[qinvokable]
        fn debug_create_kv_item(self: Pin<&mut AppModel>, path: QString, key: QString, value: QString);
    }

    impl cxx_qt::Initialize for AppModel {}
}

impl ffi::AppModel {
    fn bump(mut self: std::pin::Pin<&mut Self>) {
        let next = self.rust().counter + 1;
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.counter = next;
            rust.message = QString::from(format!("Clicked {next}"));
        }
        self.as_mut().counter_changed();
        self.as_mut().message_changed();
    }

    fn set_message(mut self: std::pin::Pin<&mut Self>, value: QString) {
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.message = value;
        }
        self.as_mut().message_changed();
    }

    fn set_current_storage_index(mut self: std::pin::Pin<&mut Self>, value: i32) {
        let mut needs_refresh = false;
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.current_storage_index = value;
            if rust.unlocked {
                if let Some(core) = rust.core.as_ref() {
                    if let Some(storage) = rust.storages_raw.get(value.max(0) as usize) {
                        if let Err(err) = core.set_current_storage(storage.id.clone()) {
                            rust.status = QString::from(err.to_string());
                        } else {
                            needs_refresh = true;
                            // Clear selected item when switching storage
                            rust.selected_item_id = QString::from("");
                            rust.selected_item_json = QString::from("");
                        }
                    }
                }
            }
        }
        if needs_refresh {
            let core = self.as_mut().rust_mut().get_mut().core.clone();
            if let Some(core) = core {
                let rust = self.as_mut().rust_mut().get_mut();
                refresh_vaults_and_items(rust, core.as_ref());
            }
        }
        self.as_mut().current_storage_index_changed();
        self.as_mut().vaults_changed();
        self.as_mut().current_vault_index_changed();
        self.as_mut().items_has_more_changed();
        self.as_mut().filtered_items_count_changed();
        self.as_mut().categories_json_changed();
        self.as_mut().folders_json_changed();
        self.as_mut().status_changed();
        self.as_mut().selected_item_id_changed();
        self.as_mut().selected_item_json_changed();
    }

    fn set_current_vault_index(mut self: std::pin::Pin<&mut Self>, value: i32) {
        let mut core_for_refresh: Option<Arc<CoreFacade>> = None;
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.current_vault_index = value;
            if rust.unlocked {
                if let Some(core) = rust.core.as_ref().cloned() {
                    if let Some(vault) = rust
                        .vaults_raw
                        .get(value.max(0) as usize)
                        .map(|vault| vault.id.clone())
                    {
                        if let Err(err) = core.set_current_vault(vault) {
                            rust.status = QString::from(err.to_string());
                        } else {
                            core_for_refresh = Some(core);
                        }
                    }
                }
            }
        }
        if let Some(core) = core_for_refresh {
            let rust = self.as_mut().rust_mut().get_mut();
            refresh_items(rust, core.as_ref());
        }
        self.as_mut().current_vault_index_changed();
        self.as_mut().status_changed();
        self.as_mut().items_has_more_changed();
        self.as_mut().filtered_items_count_changed();
        self.as_mut().categories_json_changed();
        self.as_mut().folders_json_changed();
    }

    fn set_current_category(mut self: std::pin::Pin<&mut Self>, value: QString) {
        let should_update = {
            let rust = self.as_mut().rust_mut().get_mut();
            if rust.current_category == value {
                false
            } else {
                rust.current_category = value;
                rebuild_filtered_items(rust);
                true
            }
        };
        if should_update {
            self.as_mut().current_category_changed();
            self.as_mut().filtered_items_count_changed();
        }
    }

    fn set_selected_folder(mut self: std::pin::Pin<&mut Self>, value: QString) {
        let should_update = {
            let rust = self.as_mut().rust_mut().get_mut();
            if rust.selected_folder == value {
                false
            } else {
                rust.selected_folder = value;
                rebuild_filtered_items(rust);
                true
            }
        };
        if should_update {
            self.as_mut().selected_folder_changed();
            self.as_mut().filtered_items_count_changed();
        }
    }

    fn set_search_query(mut self: std::pin::Pin<&mut Self>, value: QString) {
        let mut core_for_refresh: Option<Arc<CoreFacade>> = None;
        let mut query: Option<String> = None;
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.search_query = value;
            if rust.unlocked {
                if let Some(core) = rust.core.as_ref().cloned() {
                    let query_str = rust.search_query.to_string();
                    let trimmed = query_str.trim();
                    query = if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    };
                    core_for_refresh = Some(core);
                }
            }
        }
        self.as_mut().search_query_changed();
        if let Some(core) = core_for_refresh {
            let rust = self.as_mut().rust_mut().get_mut();
            refresh_items_with_query(rust, core.as_ref(), query);
            self.as_mut().items_has_more_changed();
            self.as_mut().filtered_items_count_changed();
            self.as_mut().categories_json_changed();
            self.as_mut().folders_json_changed();
            self.as_mut().status_changed();
        }
    }

    fn set_connect_server_url(mut self: std::pin::Pin<&mut Self>, value: QString) {
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_server_url = value;
        }
        self.as_mut().connect_server_url_changed();
    }

    fn lock(mut self: std::pin::Pin<&mut Self>) {
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.unlocked = false;
            rust.status = QString::from("Locked");
            rust.selected_item_id = QString::from("");
            rust.selected_item_json = QString::from("");
            rust.app_state = QString::from("unlock");
            if let Some(core) = rust.core.as_ref() {
                let _ = core.lock();
            }
        }
        self.as_mut().unlocked_changed();
        self.as_mut().status_changed();
        self.as_mut().selected_item_id_changed();
        self.as_mut().selected_item_json_changed();
        self.as_mut().app_state_changed();
    }

    fn unlock(mut self: std::pin::Pin<&mut Self>, password: QString) {
        let set_state = |rust: &mut AppModelRust, result: CoreResult<()>| {
            match result {
                Ok(()) => {
                    rust.unlocked = true;
                    rust.status = QString::from("Unlocked");
                }
                Err(err) => {
                    rust.unlocked = false;
                    rust.status = QString::from(err.to_string());
                }
            }
        };

        let password = password.to_string();
        let needs_vault_refresh;
        {
            let rust = self.as_mut().rust_mut().get_mut();
            let core = match rust.core.as_ref() {
                Some(core) => core.clone(),
                None => match create_core(default_db_url()) {
                    Ok(core) => {
                        rust.core = Some(core.clone());
                        core
                    }
                    Err(err) => {
                        rust.unlocked = false;
                        rust.status = QString::from(err.to_string());
                        self.as_mut().unlocked_changed();
                        self.as_mut().status_changed();
                        return;
                    }
                },
            };

            let result = core.unlock(password).map(|_| ());
            set_state(rust, result);
            needs_vault_refresh = rust.unlocked;
        }

        self.as_mut().unlocked_changed();
        self.as_mut().status_changed();

        if needs_vault_refresh {
            let core = {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.core.as_ref().cloned()
            };
            if let Some(core) = core {
                // Load storages
                if let Ok(storages) = core.list_storages() {
                    let rust = self.as_mut().rust_mut().get_mut();
                    rust.storages_raw = storages
                        .into_iter()
                        .map(|s| StorageRow {
                            id: s.id,
                            name: s.name,
                        })
                        .collect();
                    rust.storages = build_storages_list(&rust.storages_raw);
                    // Find current storage index
                    let current_id = core.current_storage_id();
                    rust.current_storage_index = rust
                        .storages_raw
                        .iter()
                        .position(|s| s.id == current_id)
                        .unwrap_or(0) as i32;
                }

                // Load vaults and items
                let rust = self.as_mut().rust_mut().get_mut();
                refresh_vaults_and_items(rust, core.as_ref());
            }
            // Transition to main state after successful unlock
            {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.app_state = QString::from("main");
            }
            self.as_mut().storages_changed();
            self.as_mut().current_storage_index_changed();
            self.as_mut().vaults_changed();
            self.as_mut().current_vault_index_changed();
            self.as_mut().status_changed();
            self.as_mut().items_has_more_changed();
            self.as_mut().filtered_items_count_changed();
            self.as_mut().categories_json_changed();
            self.as_mut().folders_json_changed();
            self.as_mut().app_state_changed();
        }
    }

    fn select_item(mut self: std::pin::Pin<&mut Self>, item_id: QString) {
        let mut detail: Option<zann_ffi::ItemDetail> = None;
        {
            let rust = self.as_mut().rust_mut().get_mut();
            if !rust.unlocked {
                rust.status = QString::from("Locked");
            } else if let Some(core) = rust.core.as_ref() {
                match core.item_get(item_id.to_string()) {
                    Ok(item) => {
                        rust.selected_item_id = QString::from(item.id.as_str());
                        detail = Some(item);
                    }
                    Err(err) => {
                        rust.status = QString::from(err.to_string());
                        rust.selected_item_id = QString::from("");
                        rust.selected_item_json = QString::from("");
                    }
                }
            }
        }

        if let Some(item) = detail {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.selected_item_json = QString::from(serialize_item_detail(&item));
        }

        self.as_mut().status_changed();
        self.as_mut().selected_item_id_changed();
        self.as_mut().selected_item_json_changed();
    }

    fn load_more_items(mut self: std::pin::Pin<&mut Self>) {
        let mut core_for_refresh: Option<Arc<CoreFacade>> = None;
        let mut cursor: Option<String>;
        let mut query: Option<String> = None;
        {
            let rust = self.as_mut().rust_mut().get_mut();
            if !rust.unlocked {
                return;
            }
            cursor = rust.items_next_cursor.clone();
            if cursor.is_none() {
                return;
            }
            if let Some(core) = rust.core.as_ref().cloned() {
                let query_str = rust.search_query.to_string();
                let trimmed = query_str.trim();
                query = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
                core_for_refresh = Some(core);
            }
        }

        let (Some(core), Some(cursor)) = (core_for_refresh, cursor) else {
            return;
        };
        let is_search = query.is_some();
        let limit = if is_search { SEARCH_PAGE_LIMIT } else { BROWSE_PAGE_LIMIT };
        let filter = ItemsFilter {
            query,
            include_deleted: false,
        };
        let page = Page {
            limit,
            cursor: Some(cursor),
        };
        match core.items_list(filter, page) {
            Ok(page) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.items.extend(page.items);
                rust.items_next_cursor = page.next_cursor;
                rust.items_has_more = rust.items_next_cursor.is_some();

                let categories_json = serialize_categories(&page.counts);
                let folders_json = serialize_folders(&rust.items);

                rust.categories_json = QString::from(categories_json);
                rust.folders_json = QString::from(folders_json);
                rebuild_filtered_items(rust);
            }
            Err(err) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.status = QString::from(err.to_string());
            }
        }
        self.as_mut().items_has_more_changed();
        self.as_mut().filtered_items_count_changed();
        self.as_mut().categories_json_changed();
        self.as_mut().folders_json_changed();
        self.as_mut().status_changed();
    }

    fn filtered_item_json(mut self: std::pin::Pin<&mut Self>, index: i32) -> QString {
        let rust = self.as_mut().rust_mut().get_mut();
        if index < 0 {
            return QString::from("");
        }
        let idx = index as usize;
        let Some(item_idx) = rust.filtered_indices.get(idx).copied() else {
            return QString::from("");
        };
        let Some(item) = rust.items.get(item_idx) else {
            return QString::from("");
        };
        QString::from(serialize_item_summary(item))
    }

    fn copy_to_clipboard(self: std::pin::Pin<&mut Self>, text: QString) {
        unsafe {
            let clipboard = ffi::get_clipboard();
            ffi::clipboard_set_text(clipboard, &text);
        }
    }

    fn generate_totp(
        self: std::pin::Pin<&mut Self>,
        secret: QString,
        algorithm: QString,
        digits: i32,
        period: i32,
    ) -> QString {
        match generate_totp_internal(&secret.to_string(), &algorithm.to_string(), digits, period) {
            Ok(response) => QString::from(response),
            Err(_) => QString::from(""),
        }
    }

    fn check_app_status(mut self: std::pin::Pin<&mut Self>) {
        // Initialize core if needed
        let core = {
            let rust = self.as_mut().rust_mut().get_mut();
            match rust.core.as_ref() {
                Some(core) => core.clone(),
                None => {
                    ensure_app_data_dir();
                    match create_core(default_db_url()) {
                    Ok(core) => {
                        rust.core = Some(core.clone());
                        core
                    }
                    Err(err) => {
                        eprintln!("[DIAG] Failed to create core: {}", err);
                        rust.app_state = QString::from("welcome");
                        self.as_mut().app_state_changed();
                        return;
                    }
                }
                }
            }
        };

        // Ensure client state for remote flows
        {
            let rust = self.as_mut().rust_mut().get_mut();
            if rust.client_state.is_none() {
                let db_url = default_db_url();
                match build_client_state(&db_url) {
                    Ok(state) => {
                        rust.client_state = Some(state);
                    }
                    Err(err) => {
                        eprintln!("[DIAG] Failed to build client state: {}", err);
                    }
                }
            }
        }

        // Check app status
        match core.app_status() {
            Ok(status) => {
                let rust = self.as_mut().rust_mut().get_mut();
                if status.initialized {
                    // Vault exists, show unlock screen
                    rust.app_state = QString::from("unlock");
                } else {
                    // First run, show welcome screen
                    rust.app_state = QString::from("welcome");
                }
                eprintln!(
                    "[DIAG] App status: initialized={}, locked={}, storages={}, has_local={}",
                    status.initialized, status.locked, status.storages_count, status.has_local_vault
                );
            }
            Err(err) => {
                eprintln!("[DIAG] Failed to check app status: {}", err);
                let rust = self.as_mut().rust_mut().get_mut();
                rust.app_state = QString::from("welcome");
            }
        }
        self.as_mut().app_state_changed();
    }

    fn start_local_setup(mut self: std::pin::Pin<&mut Self>) {
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.setup_flow = QString::from("local");
            rust.setup_error = QString::from("");
            rust.setup_password_mode = QString::from("create");
            rust.app_state = QString::from("password");
        }
        self.as_mut().setup_flow_changed();
        self.as_mut().setup_error_changed();
        self.as_mut().setup_password_mode_changed();
        self.as_mut().app_state_changed();
    }

    fn start_connect(mut self: std::pin::Pin<&mut Self>) {
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.setup_flow = QString::from("remote");
            rust.setup_error = QString::from("");
            rust.app_state = QString::from("connect");
            rust.setup_storage_id = QString::from("");
            rust.connect_status = QString::from("");
            rust.connect_error = QString::from("");
            rust.connect_busy = false;
            rust.connect_login_id = QString::from("");
            rust.connect_verification = QString::from("");
            rust.connect_old_fp = QString::from("");
            rust.connect_new_fp = QString::from("");
            rust.connect_methods = QStringList::default();
            rust.connect_password_mode = QString::from("login");
            rust.oidc_rx = None;
        }
        self.as_mut().setup_flow_changed();
        self.as_mut().setup_error_changed();
        self.as_mut().app_state_changed();
        self.as_mut().connect_state_changed();
        self.as_mut().connect_error_changed();
        self.as_mut().connect_busy_changed();
        self.as_mut().connect_login_id_changed();
        self.as_mut().connect_verification_changed();
        self.as_mut().connect_old_fp_changed();
        self.as_mut().connect_new_fp_changed();
        self.as_mut().connect_methods_changed();
        self.as_mut().connect_password_mode_changed();
    }

    fn back_to_welcome(mut self: std::pin::Pin<&mut Self>) {
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.setup_error = QString::from("");
            rust.setup_busy = false;
            rust.app_state = QString::from("welcome");
            rust.setup_storage_id = QString::from("");
            rust.connect_status = QString::from("");
            rust.connect_error = QString::from("");
            rust.connect_busy = false;
            rust.connect_login_id = QString::from("");
            rust.connect_verification = QString::from("");
            rust.connect_old_fp = QString::from("");
            rust.connect_new_fp = QString::from("");
            rust.connect_methods = QStringList::default();
            rust.connect_password_mode = QString::from("login");
            rust.oidc_rx = None;
        }
        self.as_mut().setup_error_changed();
        self.as_mut().setup_busy_changed();
        self.as_mut().app_state_changed();
        self.as_mut().connect_state_changed();
        self.as_mut().connect_error_changed();
        self.as_mut().connect_busy_changed();
        self.as_mut().connect_login_id_changed();
        self.as_mut().connect_verification_changed();
        self.as_mut().connect_old_fp_changed();
        self.as_mut().connect_new_fp_changed();
        self.as_mut().connect_methods_changed();
        self.as_mut().connect_password_mode_changed();
    }

    fn create_master_password(mut self: std::pin::Pin<&mut Self>, password: QString, confirm: QString) {
        let password_str = password.to_string();
        let confirm_str = confirm.to_string();
        let (setup_mode, setup_flow, setup_storage_id) = {
            let rust = self.as_mut().rust_mut().get_mut();
            (
                rust.setup_password_mode.to_string(),
                rust.setup_flow.to_string(),
                rust.setup_storage_id.to_string(),
            )
        };

        if setup_mode != "unlock" {
            // Validate passwords match
            if password_str != confirm_str {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.setup_error = QString::from("Passwords do not match");
                self.as_mut().setup_error_changed();
                return;
            }

            // Validate password length
            if password_str.len() < 8 {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.setup_error = QString::from("Password must be at least 8 characters");
                self.as_mut().setup_error_changed();
                return;
            }
        } else if password_str.is_empty() {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.setup_error = QString::from("Password is required");
            self.as_mut().setup_error_changed();
            return;
        }

        // Set busy state
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.setup_busy = true;
            rust.setup_error = QString::from("");
        }
        self.as_mut().setup_busy_changed();
        self.as_mut().setup_error_changed();

        // Get core
        let core = {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.core.as_ref().cloned()
        };

        let Some(core) = core else {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.setup_error = QString::from("Core not initialized");
            rust.setup_busy = false;
            self.as_mut().setup_error_changed();
            self.as_mut().setup_busy_changed();
            return;
        };

        // Initialize or unlock master password
        let result = if setup_mode == "unlock" {
            core.unlock(password_str).map(|_| ())
        } else {
            core.initialize_master_password(password_str).map(|_| ())
        };

        match result {
            Ok(_) => {
                if setup_flow == "remote" {
                    if std::env::var("ZANN_TEST_SKIP_REMOTE_SYNC").as_deref() == Ok("1") {
                        // Skip remote sync in UI tests.
                    } else {
                        let storage_id = if setup_storage_id.trim().is_empty() {
                            None
                        } else {
                            Some(setup_storage_id.clone())
                        };
                        if let Err(err) = core.remote_sync(storage_id.clone()) {
                            let rust = self.as_mut().rust_mut().get_mut();
                            rust.setup_error = QString::from(err.to_string());
                            rust.setup_busy = false;
                            self.as_mut().setup_error_changed();
                            self.as_mut().setup_busy_changed();
                            return;
                        }
                        if let Some(storage_id) = storage_id {
                            if let Err(err) = core.set_current_storage(storage_id) {
                                let rust = self.as_mut().rust_mut().get_mut();
                                rust.status = QString::from(err.to_string());
                            }
                        }
                    }
                }

                // Success! Load storages and vaults, then transition to main
                if let Ok(storages) = core.list_storages() {
                    let rust = self.as_mut().rust_mut().get_mut();
                    rust.storages_raw = storages
                        .into_iter()
                        .map(|s| StorageRow {
                            id: s.id,
                            name: s.name,
                        })
                        .collect();
                    rust.storages = build_storages_list(&rust.storages_raw);
                    let current_id = core.current_storage_id();
                    rust.current_storage_index = rust
                        .storages_raw
                        .iter()
                        .position(|s| s.id == current_id)
                        .unwrap_or(0) as i32;
                }

                // Load vaults and items
                {
                    let rust = self.as_mut().rust_mut().get_mut();
                    refresh_vaults_and_items(rust, core.as_ref());
                }

                // Update state
                {
                    let rust = self.as_mut().rust_mut().get_mut();
                    rust.unlocked = true;
                    rust.status = QString::from("Unlocked");
                    rust.setup_busy = false;
                    rust.setup_password_mode = QString::from("create");
                    rust.setup_storage_id = QString::from("");
                    rust.app_state = QString::from("main");
                }

                self.as_mut().storages_changed();
                self.as_mut().current_storage_index_changed();
                self.as_mut().vaults_changed();
                self.as_mut().current_vault_index_changed();
                self.as_mut().unlocked_changed();
                self.as_mut().status_changed();
                self.as_mut().setup_busy_changed();
                self.as_mut().setup_password_mode_changed();
                self.as_mut().app_state_changed();
                self.as_mut().items_has_more_changed();
                self.as_mut().filtered_items_count_changed();
                self.as_mut().categories_json_changed();
                self.as_mut().folders_json_changed();
            }
            Err(err) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.setup_error = QString::from(err.to_string());
                rust.setup_busy = false;
                self.as_mut().setup_error_changed();
                self.as_mut().setup_busy_changed();
            }
        }
    }

    fn begin_server_connect(mut self: std::pin::Pin<&mut Self>) {
        let (server_url, client_state) = {
            let rust = self.as_mut().rust_mut().get_mut();
            let normalized = normalize_server_url(&rust.connect_server_url.to_string());
            rust.connect_server_url = QString::from(normalized.clone());
            rust.connect_error = QString::from("");
            rust.connect_status = QString::from("");
            rust.connect_busy = true;
            rust.connect_methods = QStringList::default();
            let state = ensure_client_state(rust);
            (normalized, state)
        };
        self.as_mut().connect_server_url_changed();
        self.as_mut().connect_error_changed();
        self.as_mut().connect_state_changed();
        self.as_mut().connect_busy_changed();
        self.as_mut().connect_methods_changed();

        if server_url.is_empty() {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_error = QString::from("Server URL is required");
            rust.connect_busy = false;
            self.as_mut().connect_error_changed();
            self.as_mut().connect_busy_changed();
            return;
        }

        let Some(client_state) = client_state else {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_error = QString::from("Client state not initialized");
            rust.connect_busy = false;
            self.as_mut().connect_error_changed();
            self.as_mut().connect_busy_changed();
            return;
        };

        let runtime = match Runtime::new() {
            Ok(rt) => rt,
            Err(err) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.connect_error = QString::from(err.to_string());
                rust.connect_busy = false;
                self.as_mut().connect_error_changed();
                self.as_mut().connect_busy_changed();
                return;
            }
        };

        let client = reqwest::Client::new();
        let info = runtime.block_on(zann_client::remote::fetch_system_info(&client, &server_url));
        let mut method_names: Vec<String> = Vec::new();
        let mut password_mode = "login".to_string();
        match info {
            Ok(info) => {
                if info.internal_users_present == Some(false) {
                    password_mode = "register".to_string();
                }
                for method in info.auth_methods {
                    if let Ok(parsed) = AuthMethod::try_from(method) {
                        match parsed {
                            AuthMethod::Oidc => method_names.push("oidc".to_string()),
                            AuthMethod::Password => method_names.push("password".to_string()),
                            AuthMethod::ServiceAccount => {}
                        }
                    }
                }
            }
            Err(err) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.connect_error = QString::from(err);
                rust.connect_busy = false;
                self.as_mut().connect_error_changed();
                self.as_mut().connect_busy_changed();
                return;
            }
        }

        if method_names.is_empty() {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_error = QString::from("No interactive auth methods available");
            rust.connect_busy = false;
            self.as_mut().connect_error_changed();
            self.as_mut().connect_busy_changed();
            return;
        }

        let auto_method = if method_names.len() == 1 {
            Some(method_names[0].clone())
        } else {
            None
        };

        {
            let rust = self.as_mut().rust_mut().get_mut();
            let mut list = QStringList::default();
            for method in &method_names {
                list.append_clone(&QString::from(method.as_str()));
            }
            rust.connect_methods = list;
            rust.connect_password_mode = QString::from(password_mode);
            rust.connect_busy = false;
        }
        self.as_mut().connect_methods_changed();
        self.as_mut().connect_password_mode_changed();
        self.as_mut().connect_busy_changed();

        if let Some(method) = auto_method {
            if method == "oidc" {
                self.connect_with_oidc();
            } else if method == "password" {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.connect_status = QString::from("password");
                self.as_mut().connect_state_changed();
            }
        }
    }

    fn connect_with_oidc(mut self: std::pin::Pin<&mut Self>) {
        let (server_url, client_state) = {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_error = QString::from("");
            rust.connect_status = QString::from("");
            rust.connect_busy = true;
            rust.connect_login_id = QString::from("");
            rust.connect_verification = QString::from("");
            rust.connect_old_fp = QString::from("");
            rust.connect_new_fp = QString::from("");
            let state = ensure_client_state(rust);
            (rust.connect_server_url.to_string(), state)
        };
        self.as_mut().connect_error_changed();
        self.as_mut().connect_state_changed();
        self.as_mut().connect_busy_changed();
        self.as_mut().connect_login_id_changed();
        self.as_mut().connect_verification_changed();
        self.as_mut().connect_old_fp_changed();
        self.as_mut().connect_new_fp_changed();

        let Some(client_state) = client_state else {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_error = QString::from("Client state not initialized");
            rust.connect_busy = false;
            self.as_mut().connect_error_changed();
            self.as_mut().connect_busy_changed();
            return;
        };

        let runtime = match Runtime::new() {
            Ok(rt) => rt,
            Err(err) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.connect_error = QString::from(err.to_string());
                rust.connect_busy = false;
                self.as_mut().connect_error_changed();
                self.as_mut().connect_busy_changed();
                return;
            }
        };

        let (tx, rx) = mpsc::channel::<OidcLoginStatusResponse>();
        let response = runtime.block_on(zann_client::auth_oidc::begin_login(
            server_url,
            &client_state,
            tx,
        ));

        match response {
            Ok(payload) => {
                if payload.ok {
                    if let Some(data) = payload.data {
                        let rust = self.as_mut().rust_mut().get_mut();
                        rust.connect_login_id = QString::from(data.login_id.as_str());
                        rust.connect_verification = QString::from(data.authorization_url.as_str());
                        rust.connect_status = QString::from("waiting");
                        rust.connect_busy = false;
                        rust.oidc_rx = Some(rx);
                        self.as_mut().connect_login_id_changed();
                        self.as_mut().connect_verification_changed();
                        self.as_mut().connect_state_changed();
                        self.as_mut().connect_busy_changed();
                        return;
                    }
                }

                let message = payload
                    .error
                    .as_ref()
                    .map(|err| err.message.clone())
                    .unwrap_or_else(|| "Missing login payload".to_string());
                let rust = self.as_mut().rust_mut().get_mut();
                rust.connect_error = QString::from(message);
                rust.connect_busy = false;
                self.as_mut().connect_error_changed();
                self.as_mut().connect_busy_changed();
            }
            Err(err) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.connect_error = QString::from(err);
                rust.connect_busy = false;
                self.as_mut().connect_error_changed();
                self.as_mut().connect_busy_changed();
            }
        }
    }

    fn connect_with_password(
        mut self: std::pin::Pin<&mut Self>,
        email: QString,
        password: QString,
        full_name: QString,
        mode: QString,
    ) {
        let (server_url, client_state, mode_str) = {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_error = QString::from("");
            rust.connect_busy = true;
            let state = ensure_client_state(rust);
            (
                rust.connect_server_url.to_string(),
                state,
                mode.to_string(),
            )
        };
        self.as_mut().connect_error_changed();
        self.as_mut().connect_busy_changed();

        let Some(client_state) = client_state else {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_error = QString::from("Client state not initialized");
            rust.connect_busy = false;
            self.as_mut().connect_error_changed();
            self.as_mut().connect_busy_changed();
            return;
        };

        let runtime = match Runtime::new() {
            Ok(rt) => rt,
            Err(err) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.connect_error = QString::from(err.to_string());
                rust.connect_busy = false;
                self.as_mut().connect_error_changed();
                self.as_mut().connect_busy_changed();
                return;
            }
        };

        let response = if mode_str == "register" {
            runtime.block_on(zann_client::auth_password::password_register(
                server_url,
                email.to_string(),
                password.to_string(),
                if full_name.to_string().trim().is_empty() {
                    None
                } else {
                    Some(full_name.to_string())
                },
                &client_state,
            ))
        } else {
            runtime.block_on(zann_client::auth_password::password_login(
                server_url,
                email.to_string(),
                password.to_string(),
                &client_state,
            ))
        };

        match response {
            Ok(payload) => {
                if payload.ok {
                    if let Some(data) = payload.data {
                        if data.status == "fingerprint_changed" {
                            let rust = self.as_mut().rust_mut().get_mut();
                            rust.connect_login_id = QString::from(data.login_id.unwrap_or_default().as_str());
                            rust.connect_status = QString::from("fingerprint");
                            rust.connect_old_fp = QString::from(data.old_fingerprint.unwrap_or_default().as_str());
                            rust.connect_new_fp = QString::from(data.new_fingerprint.unwrap_or_default().as_str());
                            rust.connect_busy = false;
                            self.as_mut().connect_login_id_changed();
                            self.as_mut().connect_state_changed();
                            self.as_mut().connect_old_fp_changed();
                            self.as_mut().connect_new_fp_changed();
                            self.as_mut().connect_busy_changed();
                            return;
                        }

                        if data.status == "success" {
                            self.handle_connect_success(
                                data.storage_id.unwrap_or_default(),
                                data.personal_key_envelopes_present.unwrap_or(false),
                            );
                            return;
                        }
                    }
                }

                let message = payload
                    .error
                    .as_ref()
                    .map(|err| err.message.clone())
                    .unwrap_or_else(|| "Authentication failed".to_string());
                let rust = self.as_mut().rust_mut().get_mut();
                rust.connect_error = QString::from(message);
                rust.connect_busy = false;
                self.as_mut().connect_error_changed();
                self.as_mut().connect_busy_changed();
            }
            Err(err) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.connect_error = QString::from(err);
                rust.connect_busy = false;
                self.as_mut().connect_error_changed();
                self.as_mut().connect_busy_changed();
            }
        }
    }

    fn trust_fingerprint(mut self: std::pin::Pin<&mut Self>) {
        let (login_id, client_state) = {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_error = QString::from("");
            rust.connect_busy = true;
            let state = ensure_client_state(rust);
            (rust.connect_login_id.to_string(), state)
        };
        self.as_mut().connect_error_changed();
        self.as_mut().connect_busy_changed();

        let Some(client_state) = client_state else {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_error = QString::from("Client state not initialized");
            rust.connect_busy = false;
            self.as_mut().connect_error_changed();
            self.as_mut().connect_busy_changed();
            return;
        };

        let runtime = match Runtime::new() {
            Ok(rt) => rt,
            Err(err) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.connect_error = QString::from(err.to_string());
                rust.connect_busy = false;
                self.as_mut().connect_error_changed();
                self.as_mut().connect_busy_changed();
                return;
            }
        };

        let (tx, rx) = mpsc::channel::<OidcLoginStatusResponse>();
        let response = runtime.block_on(zann_client::auth_oidc::trust_fingerprint(
            login_id,
            &client_state,
            tx,
        ));
        match response {
            Ok(_) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.oidc_rx = Some(rx);
                rust.connect_status = QString::from("waiting");
                rust.connect_busy = false;
                rust.connect_old_fp = QString::from("");
                rust.connect_new_fp = QString::from("");
                self.as_mut().connect_state_changed();
                self.as_mut().connect_busy_changed();
                self.as_mut().connect_old_fp_changed();
                self.as_mut().connect_new_fp_changed();
            }
            Err(err) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.connect_error = QString::from(err);
                rust.connect_busy = false;
                self.as_mut().connect_error_changed();
                self.as_mut().connect_busy_changed();
            }
        }
    }

    fn poll_oidc_status(mut self: std::pin::Pin<&mut Self>) {
        let payloads: Vec<OidcLoginStatusResponse> = {
            let rust = self.as_mut().rust_mut().get_mut();
            let Some(rx) = rust.oidc_rx.as_ref() else {
                return;
            };
            let mut events = Vec::new();
            while let Ok(payload) = rx.try_recv() {
                events.push(payload);
            }
            events
        };

        for payload in payloads {
            self.as_mut().apply_oidc_status(payload);
        }
    }

    fn apply_oidc_status(mut self: std::pin::Pin<&mut Self>, payload: OidcLoginStatusResponse) {
        if payload.status == "fingerprint_changed" {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_status = QString::from("fingerprint");
            rust.connect_old_fp = QString::from(payload.old_fingerprint.unwrap_or_default().as_str());
            rust.connect_new_fp = QString::from(payload.new_fingerprint.unwrap_or_default().as_str());
            rust.connect_busy = false;
            self.as_mut().connect_state_changed();
            self.as_mut().connect_old_fp_changed();
            self.as_mut().connect_new_fp_changed();
            self.as_mut().connect_busy_changed();
            return;
        }

        if payload.status == "success" {
            self.handle_connect_success(
                payload.storage_id.unwrap_or_default(),
                payload.personal_key_envelopes_present.unwrap_or(false),
            );
            return;
        }

        if payload.status == "pending" {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_status = QString::from("waiting");
            rust.connect_busy = false;
            self.as_mut().connect_state_changed();
            self.as_mut().connect_busy_changed();
            return;
        }

        if payload.status == "error" {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.connect_error = QString::from(payload.message.unwrap_or_else(|| "Authentication failed".to_string()));
            rust.connect_busy = false;
            self.as_mut().connect_error_changed();
            self.as_mut().connect_busy_changed();
        }
    }

    fn handle_connect_success(
        mut self: std::pin::Pin<&mut Self>,
        storage_id: String,
        personal_key_envelopes_present: bool,
    ) {
        let rust = self.as_mut().rust_mut().get_mut();
        rust.connect_busy = false;
        rust.connect_status = QString::from("success");
        rust.connect_error = QString::from("");
        rust.oidc_rx = None;
        rust.connect_methods = QStringList::default();
        rust.connect_login_id = QString::from("");
        rust.connect_verification = QString::from("");
        rust.connect_old_fp = QString::from("");
        rust.connect_new_fp = QString::from("");
        rust.setup_flow = QString::from("remote");
        rust.setup_password_mode = if personal_key_envelopes_present {
            QString::from("unlock")
        } else {
            QString::from("create")
        };
        rust.setup_storage_id = QString::from(storage_id.as_str());
        rust.app_state = QString::from("password");
        reload_core_from_config(rust);

        self.as_mut().connect_busy_changed();
        self.as_mut().connect_state_changed();
        self.as_mut().connect_error_changed();
        self.as_mut().connect_methods_changed();
        self.as_mut().connect_login_id_changed();
        self.as_mut().connect_verification_changed();
        self.as_mut().connect_old_fp_changed();
        self.as_mut().connect_new_fp_changed();
        self.as_mut().setup_flow_changed();
        self.as_mut().setup_password_mode_changed();
        self.as_mut().app_state_changed();
    }

    fn debug_force_remote_setup(
        mut self: std::pin::Pin<&mut Self>,
        storage_id: QString,
        has_personal_keys: bool,
    ) {
        if std::env::var("ZANN_TEST_ENABLE").is_err() {
            return;
        }
        self.handle_connect_success(storage_id.to_string(), has_personal_keys);
    }

    fn debug_reset_core(mut self: std::pin::Pin<&mut Self>, db_url: QString) {
        if std::env::var("ZANN_TEST_ENABLE").is_err() {
            return;
        }
        let url = db_url.to_string();
        if !url.trim().is_empty() {
            std::env::set_var("ZANN_DB_URL", url);
        }
        {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.core = None;
            rust.client_state = None;
            rust.unlocked = false;
            rust.status = QString::from("Locked");
            rust.app_state = QString::from("loading");
        }
        self.as_mut().unlocked_changed();
        self.as_mut().status_changed();
        self.as_mut().app_state_changed();
        self.check_app_status();
    }

    fn debug_cleanup_db(self: std::pin::Pin<&mut Self>, db_url: QString) {
        if std::env::var("ZANN_TEST_ENABLE").is_err() {
            return;
        }
        let url = db_url.to_string();
        let Some(path) = url.strip_prefix("sqlite://") else {
            return;
        };
        let path = std::path::PathBuf::from(path);
        let allow = path.to_string_lossy().contains("/tmp/")
            || std::env::var("ZANN_TEST_ALLOW_CLEANUP").is_ok();
        if !allow {
            return;
        }
        let _ = std::fs::remove_file(&path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_file(parent.join("config.json"));
        }
    }

    fn debug_make_temp_db_url(self: std::pin::Pin<&mut Self>, prefix: QString) -> QString {
        if std::env::var("ZANN_TEST_ENABLE").is_err() {
            return QString::from("");
        }
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "zann-kde-{}-{}-{}",
            prefix.to_string(),
            std::process::id(),
            suffix
        ));
        if std::fs::create_dir_all(&dir).is_err() {
            return QString::from("");
        }
        let db_path = dir.join("zann.sqlite");
        QString::from(format!("sqlite://{}", db_path.display()))
    }

    fn debug_get_env(self: std::pin::Pin<&mut Self>, key: QString) -> QString {
        if std::env::var("ZANN_TEST_ENABLE").is_err() {
            return QString::from("");
        }
        std::env::var(key.to_string())
            .ok()
            .map(QString::from)
            .unwrap_or_else(|| QString::from(""))
    }

    fn debug_create_kv_item(
        mut self: std::pin::Pin<&mut Self>,
        path: QString,
        key: QString,
        value: QString,
    ) {
        if std::env::var("ZANN_TEST_ENABLE").is_err() {
            return;
        }
        let core = {
            let rust = self.as_mut().rust_mut().get_mut();
            rust.core.as_ref().cloned()
        };
        let Some(core) = core else {
            return;
        };
        let result = core.debug_create_kv_item(path.to_string(), key.to_string(), value.to_string());
        match result {
            Ok(_) => {
                let rust = self.as_mut().rust_mut().get_mut();
                refresh_vaults_and_items(rust, core.as_ref());
                self.as_mut().vaults_changed();
                self.as_mut().current_vault_index_changed();
                self.as_mut().items_has_more_changed();
                self.as_mut().filtered_items_count_changed();
                self.as_mut().categories_json_changed();
                self.as_mut().folders_json_changed();
            }
            Err(err) => {
                let rust = self.as_mut().rust_mut().get_mut();
                rust.status = QString::from(err.to_string());
                self.as_mut().status_changed();
            }
        }
    }
}

impl cxx_qt::Initialize for ffi::AppModel {
    fn initialize(mut self: std::pin::Pin<&mut Self>) {
        self.as_mut().storages_changed();
        self.as_mut().vaults_changed();
        self.as_mut().app_state_changed();
        self.as_mut().setup_flow_changed();
        self.as_mut().setup_error_changed();
        self.as_mut().setup_busy_changed();
        self.as_mut().setup_password_mode_changed();
        self.as_mut().connect_server_url_changed();
        self.as_mut().connect_state_changed();
        self.as_mut().connect_error_changed();
        self.as_mut().connect_busy_changed();
        self.as_mut().connect_login_id_changed();
        self.as_mut().connect_verification_changed();
        self.as_mut().connect_old_fp_changed();
        self.as_mut().connect_new_fp_changed();
        self.as_mut().connect_methods_changed();
        self.as_mut().connect_password_mode_changed();
        // Check app status on initialization
        self.check_app_status();
    }
}

fn local_root_path() -> Result<std::path::PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "HOME is not set".to_string())?;
    Ok(home.join(".zann"))
}

fn default_db_url() -> String {
    if let Ok(value) = std::env::var("ZANN_DB_URL") {
        if value.starts_with("sqlite://") {
            return value;
        }
        return format!("sqlite://{}", value);
    }
    let root = local_root_path().unwrap_or_else(|_| std::path::PathBuf::from("."));
    format!("sqlite://{}", root.join(LOCAL_DB_FILENAME).display())
}

fn client_root_from_db_url(db_url: &str) -> std::path::PathBuf {
    if let Some(path) = db_url.strip_prefix("sqlite://") {
        if let Some(parent) = std::path::Path::new(path).parent() {
            return parent.to_path_buf();
        }
    }
    local_root_path().unwrap_or_else(|_| std::path::PathBuf::from("."))
}

fn ensure_app_data_dir() {
    if let Ok(root) = local_root_path() {
        let _ = std::fs::create_dir_all(&root);
    } else {
        eprintln!("[DIAG] HOME is not set; cannot create app data dir");
    }
}

fn build_client_state(db_url: &str) -> Result<zann_client::ClientState, String> {
    ensure_app_data_dir();
    let runtime = Runtime::new().map_err(|err| err.to_string())?;
    let pool = runtime
        .block_on(connect_sqlite_with_max(db_url, 5))
        .map_err(|err| err.to_string())?;
    runtime
        .block_on(migrate_local(&pool))
        .map_err(|err| err.to_string())?;
    let root = client_root_from_db_url(db_url);
    Ok(zann_client::ClientState::new(pool, root))
}

fn ensure_client_state(rust: &mut AppModelRust) -> Option<zann_client::ClientState> {
    if rust.client_state.is_none() {
        let db_url = default_db_url();
        match build_client_state(&db_url) {
            Ok(state) => {
                rust.client_state = Some(state);
            }
            Err(err) => {
                eprintln!("[DIAG] Failed to build client state: {}", err);
            }
        }
    }
    rust.client_state.clone()
}

fn reload_core_from_config(rust: &mut AppModelRust) {
    match create_core(default_db_url()) {
        Ok(core) => {
            rust.core = Some(core);
        }
        Err(err) => {
            eprintln!("[DIAG] Failed to reload core: {}", err);
        }
    }
}

fn normalize_server_url(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    format!("https://{}", trimmed)
}

fn build_storages_list(storages: &[StorageRow]) -> QStringList {
    let mut list = QStringList::default();
    for storage in storages {
        list.append_clone(&QString::from(storage.name.as_str()));
    }
    list
}

fn build_vaults_list(vaults_raw: &[VaultRow]) -> QStringList {
    let mut list = QStringList::default();
    for vault in vaults_raw {
        list.append_clone(&QString::from(vault.name.as_str()));
    }
    list
}

/// Default page size for browsing (without search)
const BROWSE_PAGE_LIMIT: u32 = 100;
/// Page size for search results (larger to get all matches)
const SEARCH_PAGE_LIMIT: u32 = 500;

fn refresh_items(model: &mut AppModelRust, core: &CoreFacade) {
    refresh_items_with_query(model, core, None);
}

fn refresh_items_with_query(model: &mut AppModelRust, core: &CoreFacade, query: Option<String>) {
    let is_search = query.is_some();
    let filter = ItemsFilter {
        query,
        include_deleted: false,
    };
    // Use larger limit for search to get all matching results
    let limit = if is_search { SEARCH_PAGE_LIMIT } else { BROWSE_PAGE_LIMIT };
    let page = Page {
        limit,
        cursor: None,
    };
    match core.items_list(filter, page) {
        Ok(page) => {
            eprintln!("[DIAG] Loaded {} items (search={})", page.items.len(), is_search);

            model.items = page.items;
            model.items_next_cursor = page.next_cursor;
            model.items_has_more = model.items_next_cursor.is_some();

            let categories_json = serialize_categories(&page.counts);
            let folders_json = serialize_folders(&model.items);

            model.categories_json = QString::from(categories_json);
            model.folders_json = QString::from(folders_json);
            rebuild_filtered_items(model);
        }
        Err(err) => {
            eprintln!("[DIAG] Error loading items: {}", err);
            model.status = QString::from(err.to_string());
        }
    }
}

fn refresh_vaults_and_items(model: &mut AppModelRust, core: &CoreFacade) {
    // Log current storage
    eprintln!("[DIAG] Current storage: {}", core.current_storage_id());

    match core.list_vaults() {
        Ok(vaults) => {
            // Log all vaults
            eprintln!("[DIAG] Vaults ({}):", vaults.len());
            for v in &vaults {
                eprintln!(
                    "[DIAG]   - {} (id={}, items={}, default={})",
                    v.name, v.id, v.item_count, v.is_default
                );
            }

            model.vaults_raw = vaults
                .into_iter()
                .map(|v| VaultRow {
                    id: v.id,
                    name: v.name,
                    is_default: v.is_default,
                    item_count: v.item_count,
                })
                .collect();
            model.vaults = build_vaults_list(&model.vaults_raw);
            // Select vault with MOST items (same logic as FFI unlock)
            model.current_vault_index = model
                .vaults_raw
                .iter()
                .enumerate()
                .max_by_key(|(_, v)| v.item_count)
                .map(|(i, _)| i)
                .unwrap_or(0) as i32;

            // Log selected vault
            if let Some(vault) = model.vaults_raw.get(model.current_vault_index as usize) {
                eprintln!(
                    "[DIAG] Selected vault: {} (id={}, items={})",
                    vault.name, vault.id, vault.item_count
                );
                let _ = core.set_current_vault(vault.id.clone());
            }

            refresh_items(model, core);
        }
        Err(err) => {
            eprintln!("[DIAG] Error listing vaults: {}", err);
            model.status = QString::from(err.to_string());
        }
    }
}

fn serialize_item_summary(item: &zann_ffi::ItemSummary) -> String {
    serde_json::to_string(&serde_json::json!({
        "id": item.id,
        "title": item.title,
        "type_id": item.type_id,
        "path": item.path,
        "deleted": item.deleted,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

fn serialize_item_detail(item: &zann_ffi::ItemDetail) -> String {
    serde_json::to_string(&serde_json::json!({
        "id": item.id,
        "title": item.title,
        "path": item.path,
        "type_id": item.type_id,
        "payload_json": item.payload_json,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

fn serialize_categories(counts: &ItemCountsFfi) -> String {
    let schema: UiCategoriesSchema = match serde_json::from_str(UI_CATEGORIES_SCHEMA) {
        Ok(schema) => schema,
        Err(_) => return "[]".to_string(),
    };

    // Build a lookup map for type_id -> count
    let type_counts: std::collections::HashMap<&str, u64> = counts
        .by_type
        .iter()
        .map(|entry| (entry.type_id.as_str(), entry.count))
        .collect();

    let mut categories: Vec<_> = schema
        .categories
        .iter()
        .map(|cat| {
            // Compute count based on filter
            let count = match &cat.filter {
                None => {
                    // Special case for trash (no filter in schema means use trash count)
                    if cat.id == "trash" {
                        counts.trash
                    } else {
                        0
                    }
                }
                Some(filter) => {
                    match &filter.type_ids {
                        None => {
                            // No type_ids filter means "all" category
                            counts.all
                        }
                        Some(type_ids) => {
                            // Sum counts for all type_ids in the filter
                            type_ids
                                .iter()
                                .map(|tid| type_counts.get(tid.as_str()).copied().unwrap_or(0u64))
                                .sum::<u64>()
                        }
                    }
                }
            };

            // Get label from first label entry
            let label = cat
                .labels
                .first()
                .map(|l| translate_label_key(&l.key))
                .unwrap_or("Unknown");

            // Map icon to Kirigami
            let icon = map_icon_to_kirigami(&cat.icon);

            // Build filter for QML
            let filter_json = cat.filter.as_ref().map(|f| {
                serde_json::json!({
                    "type_ids": f.type_ids,
                    "is_deleted": f.is_deleted,
                })
            });

            (
                cat.order,
                serde_json::json!({
                    "id": cat.id,
                    "label": label,
                    "icon": icon,
                    "order": cat.order,
                    "count": count,
                    "filter": filter_json,
                }),
            )
        })
        .collect();

    // Sort by order
    categories.sort_by_key(|(order, _)| *order);

    let result: Vec<_> = categories.into_iter().map(|(_, json)| json).collect();
    serde_json::to_string(&result).unwrap_or_else(|_| "[]".to_string())
}

fn serialize_folders(items: &[zann_ffi::ItemSummary]) -> String {
    use std::collections::{BTreeSet, HashMap};

    #[derive(Default)]
    struct FolderNode {
        name: String,
        path: String,
        item_count: usize,
        total_count: usize,
        children: BTreeSet<String>,
    }

    let mut folder_paths = BTreeSet::<String>::new();
    let mut item_counts = HashMap::<String, usize>::new();
    let mut items_without_folder = 0usize;

    for item in items {
        let path = item.path.trim();
        if path.is_empty() {
            continue;
        }
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() < 2 {
            items_without_folder += 1;
            continue;
        }

        let folder_segments = &segments[..segments.len().saturating_sub(1)];
        let mut current = String::new();
        for segment in folder_segments {
            if !current.is_empty() {
                current.push('/');
            }
            current.push_str(segment);
            folder_paths.insert(current.clone());
        }
        let folder_path = folder_segments.join("/");
        *item_counts.entry(folder_path).or_insert(0) += 1;
    }

    let mut nodes = HashMap::<String, FolderNode>::new();
    let mut roots = BTreeSet::<String>::new();

    for path in &folder_paths {
        let name = path.split('/').last().unwrap_or(path).to_string();
        nodes.insert(
            path.clone(),
            FolderNode {
                name,
                path: path.clone(),
                item_count: *item_counts.get(path).unwrap_or(&0),
                total_count: 0,
                children: BTreeSet::new(),
            },
        );
    }

    for path in &folder_paths {
        if let Some((parent, _)) = path.rsplit_once('/') {
            if let Some(parent_node) = nodes.get_mut(parent) {
                parent_node.children.insert(path.clone());
            }
        } else {
            roots.insert(path.clone());
        }
    }

    fn compute_total(path: &str, nodes: &mut HashMap<String, FolderNode>) -> usize {
        let child_paths = nodes
            .get(path)
            .map(|node| node.children.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let mut total = nodes.get(path).map(|node| node.item_count).unwrap_or(0);
        for child in child_paths {
            total += compute_total(&child, nodes);
        }
        if let Some(node) = nodes.get_mut(path) {
            node.total_count = total;
        }
        total
    }

    for root in roots.clone() {
        compute_total(&root, &mut nodes);
    }

    fn node_to_json(path: &str, nodes: &HashMap<String, FolderNode>) -> serde_json::Value {
        let node = match nodes.get(path) {
            Some(node) => node,
            None => return serde_json::json!({}),
        };
        let children: Vec<_> = node
            .children
            .iter()
            .map(|child| node_to_json(child, nodes))
            .collect();
        serde_json::json!({
            "name": node.name,
            "path": node.path,
            "item_count": node.item_count,
            "total_count": node.total_count,
            "children": children,
        })
    }

    let tree: Vec<_> = roots.iter().map(|path| node_to_json(path, &nodes)).collect();
    serde_json::to_string(&serde_json::json!({
        "items_without_folder": items_without_folder,
        "tree": tree,
    }))
    .unwrap_or_else(|_| "{\"items_without_folder\":0,\"tree\":[]}".to_string())
}

fn rebuild_filtered_items(model: &mut AppModelRust) {
    let category = model.current_category.to_string();
    let filter = category_filter_for(&category);
    let selected_folder = model.selected_folder.to_string();
    model.filtered_indices.clear();
    for (idx, item) in model.items.iter().enumerate() {
        if item_matches_filters(item, &category, filter.as_ref(), &selected_folder) {
            model.filtered_indices.push(idx);
        }
    }
    model.filtered_items_count = model.filtered_indices.len() as i32;
}

fn category_filter_for(category_id: &str) -> Option<CategoryFilter> {
    ui_categories_schema()
        .categories
        .iter()
        .cloned()
        .find(|cat| cat.id == category_id)
        .and_then(|cat| cat.filter)
}

fn item_matches_filters(
    item: &zann_ffi::ItemSummary,
    category_id: &str,
    filter: Option<&CategoryFilter>,
    selected_folder: &str,
) -> bool {
    if let Some(filter) = filter {
        if let Some(is_deleted) = filter.is_deleted {
            if is_deleted != item.deleted {
                return false;
            }
        }
        if let Some(type_ids) = &filter.type_ids {
            if !type_ids.iter().any(|tid| tid == &item.type_id) {
                return false;
            }
        }
    } else if category_id == "trash" && !item.deleted {
        return false;
    }

    if selected_folder.is_empty() {
        return true;
    }
    if selected_folder == "__no_folder__" {
        return !item.path.contains('/');
    }
    let Some((folder_path, _)) = item.path.rsplit_once('/') else {
        return false;
    };
    folder_path == selected_folder || folder_path.starts_with(&format!("{}/", selected_folder))
}

fn ui_categories_schema() -> &'static UiCategoriesSchema {
    static SCHEMA: OnceLock<UiCategoriesSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| serde_json::from_str(UI_CATEGORIES_SCHEMA).unwrap_or(UiCategoriesSchema {
        categories: Vec::new(),
        fallback_category_id: "all".to_string(),
    }))
}

fn generate_totp_internal(
    secret: &str,
    algorithm: &str,
    digits: i32,
    period: i32,
) -> Result<String, String> {
    let algorithm = parse_totp_algorithm(algorithm)?;
    let digits = parse_totp_digits(digits)?;
    let period = parse_totp_period(period)?;
    let secret_bytes = decode_totp_secret(secret)?;

    let totp = TOTP::new(algorithm, digits as usize, 1, period as u64, secret_bytes)
        .map_err(|err| err.to_string())?;

    let code = totp.generate_current().map_err(|err| err.to_string())?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "invalid system time".to_string())?
        .as_secs();

    let remaining = period as u64 - (now % period as u64);

    Ok(serde_json::json!({
        "code": code,
        "remaining": remaining,
        "period": period
    })
    .to_string())
}

fn parse_totp_algorithm(value: &str) -> Result<Algorithm, String> {
    let normalized = if value.is_empty() {
        "SHA1"
    } else {
        value.trim()
    }
    .to_uppercase();

    match normalized.as_str() {
        "SHA1" => Ok(Algorithm::SHA1),
        "SHA256" => Ok(Algorithm::SHA256),
        "SHA512" => Ok(Algorithm::SHA512),
        _ => Err("unsupported otp algorithm".to_string()),
    }
}

fn parse_totp_digits(value: i32) -> Result<u32, String> {
    let digits = if value <= 0 { 6 } else { value as u32 };
    match digits {
        6 | 8 => Ok(digits),
        _ => Err("unsupported otp digits".to_string()),
    }
}

fn parse_totp_period(value: i32) -> Result<u32, String> {
    let period = if value <= 0 { 30 } else { value as u32 };
    Ok(period)
}

fn decode_totp_secret(secret: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = secret
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .collect::<String>()
        .to_uppercase();

    BASE32
        .decode(cleaned.as_bytes())
        .map_err(|_| "invalid otp secret".to_string())
}
