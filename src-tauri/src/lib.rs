mod app_control;
mod app_traffic;
mod filters;
mod privileged;
mod runtime;
mod settings;
mod traffic;
mod tray;

use runtime::{AppState, LifecycleState, RuntimeStatus};
use settings::{BackgroundSettings, PersistedSettings};
use tauri::{Manager, State, WindowEvent};
use tauri_plugin_autostart::ManagerExt;

#[tauri::command(async)]
fn scan_network_exposure(app: tauri::AppHandle) -> dissimulation_core::NetworkSnapshot {
    runtime::scan(&app)
}

#[tauri::command(async)]
fn get_initial_network_exposure(app: tauri::AppHandle) -> dissimulation_core::NetworkSnapshot {
    runtime::latest_or_scan(&app)
}

#[tauri::command]
fn get_background_settings(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> BackgroundSettings {
    let mut settings = state.settings();
    if let Ok(enabled) = app.autolaunch().is_enabled() {
        settings.autostart_enabled = enabled;
    }
    settings
}

#[tauri::command]
fn update_background_settings(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    settings: BackgroundSettings,
) -> Result<BackgroundSettings, String> {
    let requested = settings.sanitized();
    let previous = state.settings();

    if requested.autostart_enabled != previous.autostart_enabled {
        if requested.autostart_enabled {
            app.autolaunch()
                .enable()
                .map_err(|_| "Impossible d'activer le lancement automatique.".to_string())?;
        } else {
            app.autolaunch()
                .disable()
                .map_err(|_| "Impossible de désactiver le lancement automatique.".to_string())?;
        }
    }

    let persisted = PersistedSettings {
        background: requested.clone(),
        first_launch_completed: true,
    };
    if let Err(error) = settings::save(&app, &persisted) {
        if requested.autostart_enabled != previous.autostart_enabled {
            if previous.autostart_enabled {
                let _ = app.autolaunch().enable();
            } else {
                let _ = app.autolaunch().disable();
            }
        }
        return Err(error);
    }

    state.replace_settings(requested.clone());
    Ok(requested)
}

#[tauri::command]
fn get_runtime_status(state: State<'_, AppState>) -> RuntimeStatus {
    state.status()
}

#[tauri::command]
fn quit_completely(app: tauri::AppHandle) {
    tray::quit_completely(&app);
}

pub fn run_privileged_helper() -> i32 {
    privileged::run_from_arguments()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tray::show_main_window(app);
        }))
        .plugin(
            tauri_plugin_autostart::Builder::new()
                .arg("--hidden")
                .build(),
        )
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let mut persisted = settings::load(app.handle());
            if let Ok(enabled) = app.autolaunch().is_enabled() {
                persisted.background.autostart_enabled = enabled;
            }

            app.manage(AppState::new(persisted.background.clone()));
            runtime::set_lifecycle(app.handle(), LifecycleState::Initializing);
            tray::create(app.handle())?;

            let starts_hidden = std::env::args().any(|argument| argument == "--hidden");
            if !starts_hidden && !persisted.first_launch_completed {
                tray::show_main_window(app.handle());
                persisted.first_launch_completed = true;
                let _ = settings::save(app.handle(), &persisted);
            } else {
                tray::hide_main_window(app.handle());
            }

            runtime::start_monitor(app.handle().clone())?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                tray::hide_main_window(window.app_handle());
            }
        })
        .invoke_handler(tauri::generate_handler![
            scan_network_exposure,
            get_initial_network_exposure,
            get_background_settings,
            update_background_settings,
            get_runtime_status,
            traffic::get_traffic_sessions,
            traffic::capture_packet_sample,
            app_traffic::get_application_traffic_history,
            app_traffic::sample_application_traffic,
            app_control::get_network_applications,
            app_control::block_application_network,
            app_control::unblock_application_network,
            privileged::execute_system_action,
            privileged::inspect_firewall_with_authorization,
            filters::get_block_rules,
            filters::resolve_filter_target,
            filters::add_block_rule,
            filters::remove_block_rule,
            quit_completely
        ]);

    let app = builder
        .build(tauri::generate_context!())
        .expect("impossible de préparer Dissimulation");
    app.run(|app, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
            if let Some(state) = app.try_state::<AppState>() {
                if !state.quit_requested() {
                    state.set_lifecycle(LifecycleState::ShuttingDown);
                }
            }
        }
        if matches!(event, tauri::RunEvent::Exit) {
            runtime::signal_shutdown(app);
        }
    });
}
