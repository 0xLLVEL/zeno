mod commands;

#[cfg(windows)]
mod apc;
#[cfg(windows)]
mod injector;
#[cfg(windows)]
mod manualmap;
#[cfg(windows)]
mod nt;
#[cfg(windows)]
mod pipe;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod section;

use std::sync::Mutex;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .manage(commands::AppState {
            attach: Mutex::new(commands::AttachStatus::default()),
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_roblox_processes,
            commands::attach_status,
            commands::attach,
            commands::detach,
            commands::execute_script,
            commands::drain_output,
            commands::inject_custom_dll,
        ])
        .setup(|_app| {
            #[cfg(windows)]
            pipe::start();
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("failed to launch zeno");
}
