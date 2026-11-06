use std::sync::Mutex;

use serde::Serialize;
use tauri::State;

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AttachStatus {
    pub attached: bool,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub injected: bool,
    pub message: String,
}

pub struct AppState {
    pub attach: Mutex<AttachStatus>,
}

#[derive(Serialize)]
pub struct ExecResult {
    pub ok: bool,
    pub error: Option<String>,
}

#[cfg(windows)]
fn payload_dll() -> Result<std::path::PathBuf, String> {
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            roots.push(dir.to_path_buf());
            roots.push(dir.join("resources"));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd.join("zeno-core").join("build").join("Release"));
        roots.push(cwd.join("zeno-core").join("build"));
        roots.push(cwd.join("src-tauri").join("resources"));
    }
    for root in roots {
        let candidate = root.join("zeno_inject.dll");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err("zeno_inject.dll not found — build zeno-core first".into())
}

#[tauri::command]
pub fn list_roblox_processes() -> Vec<ProcessInfo> {
    #[cfg(windows)]
    {
        crate::process::list_roblox()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[tauri::command]
pub fn attach_status(state: State<'_, AppState>) -> AttachStatus {
    let mut status = state.attach.lock().unwrap().clone();
    #[cfg(windows)]
    if status.attached {
        let linked = crate::pipe::is_linked();
        status.injected = linked;
        if linked {
            status.message = format!("bridge live (pid {})", status.pid.unwrap_or(0));
        }
    }
    status
}

#[tauri::command]
pub fn attach(state: State<'_, AppState>, pid: u32, method: String) -> Result<AttachStatus, String> {
    #[cfg(windows)]
    {
        let dll = payload_dll()?;
        let manual = method.eq_ignore_ascii_case("manualmap");

        crate::pipe::start();
        crate::injector::inject(pid, &dll, &method)?;

        let mut linked = false;
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if crate::pipe::is_linked() {
                linked = true;
                break;
            }
        }

        let proc_name = crate::process::list_roblox()
            .into_iter()
            .find(|p| p.pid == pid)
            .map(|p| p.name)
            .unwrap_or_else(|| "RobloxPlayerBeta.exe".into());

        let label = if manual {
            "manual-map"
        } else if method.eq_ignore_ascii_case("section") {
            "section-image"
        } else if method.eq_ignore_ascii_case("apc") {
            "apc-queue"
        } else {
            "loadlibrary"
        };
        let status = AttachStatus {
            attached: true,
            pid: Some(pid),
            process: Some(proc_name),
            injected: linked,
            message: if linked {
                format!("injected via {label} · bridge live (pid {pid})")
            } else {
                format!("injected via {label} · waiting for bridge (pid {pid})")
            },
        };
        *state.attach.lock().unwrap() = status.clone();
        Ok(status)
    }
    #[cfg(not(windows))]
    {
        let _ = (state, pid, method);
        Err("windows only".into())
    }
}

#[tauri::command]
pub fn detach(state: State<'_, AppState>) -> AttachStatus {
    let status = AttachStatus {
        attached: false,
        message: "detached".into(),
        ..Default::default()
    };
    *state.attach.lock().unwrap() = status.clone();
    status
}

#[tauri::command]
pub fn execute_script(state: State<'_, AppState>, script: String) -> ExecResult {
    if !state.attach.lock().unwrap().attached {
        return ExecResult { ok: false, error: Some("not attached".into()) };
    }
    if script.trim().is_empty() {
        return ExecResult { ok: false, error: Some("empty script".into()) };
    }

    #[cfg(windows)]
    {
        match crate::pipe::send_script(&script) {
            Ok(_) => ExecResult { ok: true, error: None },
            Err(e) => ExecResult { ok: false, error: Some(e) },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = script;
        ExecResult { ok: false, error: Some("windows only".into()) }
    }
}

#[tauri::command]
pub fn drain_output() -> Vec<String> {
    #[cfg(windows)]
    {
        crate::pipe::drain()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[tauri::command]
pub fn inject_custom_dll(state: State<'_, AppState>, path: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        let pid = state
            .attach
            .lock()
            .unwrap()
            .pid
            .ok_or_else(|| "not attached".to_string())?;
        crate::injector::inject(pid, std::path::Path::new(&path), "loadlibrary")
    }
    #[cfg(not(windows))]
    {
        let _ = (state, path);
        Err("windows only".into())
    }
}
