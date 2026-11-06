#![cfg(windows)]

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::commands::ProcessInfo;

const TARGETS: &[&str] = &["RobloxPlayerBeta.exe", "Windows10Universal.exe"];

pub fn list_roblox() -> Vec<ProcessInfo> {
    let mut out = Vec::new();

    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) if !h.is_invalid() => h,
        _ => return out,
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut ok = unsafe { Process32FirstW(snap, &mut entry) }.is_ok();
    while ok {
        let name = wchar_to_string(&entry.szExeFile);
        if TARGETS.iter().any(|t| t.eq_ignore_ascii_case(&name)) {
            let path = process_path(entry.th32ProcessID).unwrap_or_default();
            out.push(ProcessInfo {
                pid: entry.th32ProcessID,
                version: extract_version(&path),
                name,
                path,
            });
        }
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        ok = unsafe { Process32NextW(snap, &mut entry) }.is_ok();
    }

    unsafe {
        let _ = CloseHandle(snap);
    }
    out
}

fn process_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let res = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(handle);
        res.ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

fn extract_version(path: &str) -> String {
    path.split(['\\', '/'])
        .find(|seg| seg.starts_with("version-"))
        .map(|s| s.trim_start_matches("version-").to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn wchar_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

pub fn open_for_injection(pid: u32) -> windows::core::Result<HANDLE> {    use windows::Win32::System::Threading::{
        PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE,
    };
    unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_QUERY_INFORMATION,
            false,
            pid,
        )
    }
}

/// Cheap probe: can a plain process even get a write handle?
/// A negative answer means a kernel-level filter is in the way.
pub fn probe_write(pid: u32) -> bool {
    use windows::Win32::System::Threading::{PROCESS_VM_OPERATION, PROCESS_VM_WRITE};
    unsafe {
        match OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid) {
            Ok(handle) => {
                let _ = CloseHandle(handle);
                true
            }
            Err(_) => false,
        }
    }
}
