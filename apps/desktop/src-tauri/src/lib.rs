//! Network Intelligence desktop application (Tauri 2).
//!
//! The UI runs without elevation. Commands are a fixed set: there is no
//! command that runs shell code, writes arbitrary files other than an
//! export chosen in the native save dialog, or changes system settings.

mod commands;
mod state;

use tauri::Manager;

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_local_data_dir()?;
            let st = state::AppState::open(&dir)
                .map_err(|e| format!("cannot open database in {}: {e}", dir.display()))?;
            app.manage(st);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::list_processes,
            commands::process_icon,
            commands::start_session,
            commands::stop_session,
            commands::live_status,
            commands::add_marker,
            commands::set_note,
            commands::rename_session,
            commands::list_sessions,
            commands::get_session,
            commands::delete_session,
            commands::delete_all_history,
            commands::session_groups,
            commands::session_endpoints,
            commands::session_events,
            commands::session_snapshots,
            commands::session_processes,
            commands::session_probes,
            commands::run_probe,
            commands::analyze_session,
            commands::session_findings,
            commands::rule_catalog,
            commands::export_session,
            commands::get_settings,
            commands::set_settings,
        ])
        .build(tauri::generate_context!())
        .expect("error while building Network Intelligence");

    app.run(|handle, event| {
        if let tauri::RunEvent::Exit = event {
            if let Some(st) = handle.try_state::<state::AppState>() {
                st.stop_active("app exit");
            }
        }
    });
}
