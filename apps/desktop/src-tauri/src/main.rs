#![allow(clippy::missing_errors_doc)]

mod commands;
mod constants;
mod crypto;
mod infra;
mod services;
mod state;
mod types;
mod util;

use tauri::Emitter;
use tauri::Manager;
use tauri::menu::{Menu, MenuBuilder, MenuItem, SubmenuBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

use crate::infra::config::save_settings;
use commands::auth::{
    get_server_info, password_login, password_register, remote_begin_login, remote_trust_fingerprint,
};
use commands::items::{
    items_delete, items_empty_trash, items_get, items_list, items_purge, items_purge_trash,
    items_put, items_resolve_conflict, items_restore, items_update,
};
use commands::items_history::{
    items_history_get, items_history_list, items_history_restore,
};
use commands::session::{
    app_status, bootstrap, get_settings, initialize_local_identity, initialize_master_password,
    keystore_disable, keystore_enable, keystore_status, session_autolock_config, session_lock,
    session_rebind_biometrics, session_status, session_unlock_with_biometrics,
    session_unlock_with_password, status, system_locale, unlock, update_settings,
};
use commands::storage::{
    app_version, local_clear_data, local_factory_reset, open_data_folder, open_logs, storage_delete,
    storage_disconnect, storage_info, storage_reveal, storage_sign_out, storages_list,
};
use commands::sync::{remote_reset, remote_sync, sync_reset_cursor};
use commands::types::{publish_list, publish_trigger, types_list, types_show};
use commands::vaults::{vault_create, vault_list, vault_reset_personal};
use state::{AppState, build_state};

fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("[tauri] panic: {info}");
    }));

    let state = build_state().expect("failed to initialize local store");
    tauri::Builder::default()
        .manage(state)
        .plugin(tauri_plugin_biometry::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            bootstrap,
            status,
            session_status,
            session_unlock_with_password,
            initialize_master_password,
            initialize_local_identity,
            session_unlock_with_biometrics,
            session_rebind_biometrics,
            session_lock,
            app_status,
            system_locale,
            keystore_status,
            keystore_enable,
            keystore_disable,
            session_autolock_config,
            remote_begin_login,
            remote_trust_fingerprint,
            password_login,
            password_register,
            get_server_info,
            remote_sync,
            remote_reset,
            sync_reset_cursor,
            storages_list,
            storage_info,
            storage_delete,
            storage_disconnect,
            storage_reveal,
            storage_sign_out,
            local_clear_data,
            local_factory_reset,
            app_version,
            open_data_folder,
            open_logs,
            vault_list,
            items_list,
            items_get,
            items_history_list,
            items_history_get,
            items_history_restore,
            items_put,
            items_delete,
            items_restore,
            items_purge,
            items_empty_trash,
            items_purge_trash,
            items_update,
            items_resolve_conflict,
            vault_create,
            vault_reset_personal,
            types_list,
            types_show,
            publish_list,
            publish_trigger,
            get_settings,
            update_settings,
            unlock
        ])
        .setup(|app| {
            let app_handle = app.app_handle();

            let open_settings = |app: &tauri::AppHandle| {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                    let _ = window.emit("zann:open-settings", ());
                }
            };

            app.set_menu(MenuBuilder::new(app).build()?)?;

            // Create tray menu
            let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
            let settings = MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &settings, &quit])?;

            // Create tray icon
            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                            #[cfg(target_os = "macos")]
                            let _ = app.set_dock_visibility(true);
                        }
                    }
                    "settings" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                            let _ = window.emit("zann:open-settings", ());
                            #[cfg(target_os = "macos")]
                            let _ = app.set_dock_visibility(true);
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                            #[cfg(target_os = "macos")]
                            let _ = app.set_dock_visibility(true);
                        }
                    }
                })
                .build(app)?;

            app_handle.emit("zann:ready", ())?;
            Ok(())
    })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let app_handle = window.app_handle();
                let state = app_handle.state::<AppState>();
                let settings = tauri::async_runtime::block_on(async {
                    state.settings.read().await.clone()
                });

                if !settings.close_to_tray {
                    return;
                }

                api.prevent_close();
                if !settings.close_to_tray_notice_shown {
                    let _ = window.emit("zann:close-to-tray", ());
                    let app_handle = app_handle.clone();
                    tauri::async_runtime::spawn(async move {
                        let state = app_handle.state::<AppState>();
                        let mut next = state.settings.read().await.clone();
                        next.close_to_tray_notice_shown = true;
                        if save_settings(&state.root, next.clone()).is_ok() {
                            *state.settings.write().await = next;
                        }
                    });
                    return;
                }

                // Hide instead of close
                let _ = window.hide();
                #[cfg(target_os = "macos")]
                let _ = window.app_handle().set_dock_visibility(false);
            }
        })
        .run(tauri::generate_context!())
        .expect("failed to run tauri app");
}
