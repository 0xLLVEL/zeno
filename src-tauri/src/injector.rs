#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, WaitForSingleObject, LPTHREAD_START_ROUTINE,
};

pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

pub fn inject(pid: u32, dll: &Path, method: &str) -> Result<(), String> {
    let dll = dll.canonicalize().map_err(|e| format!("payload not found: {e}"))?;
    if method.eq_ignore_ascii_case("manualmap") {
        crate::manualmap::map(pid, &dll)
    } else if method.eq_ignore_ascii_case("section") {
        crate::section::map(pid, &dll)
    } else if method.eq_ignore_ascii_case("apc") {
        crate::apc::inject(pid, &dll).map(|_| ())
    } else {
        load_library(pid, &dll)
    }
}

fn load_library(pid: u32, dll: &Path) -> Result<(), String> {
    let wide_path = wide(dll.as_os_str());
    let bytes = wide_path.len() * 2;

    unsafe {
        let process = crate::process::open_for_injection(pid)
            .map_err(|e| format!("OpenProcess failed: {e}"))?;

        let remote = VirtualAllocEx(process, None, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if remote.is_null() {
            let _ = CloseHandle(process);
            return Err("VirtualAllocEx failed".into());
        }

        let mut written = 0usize;
        let write = WriteProcessMemory(
            process,
            remote,
            wide_path.as_ptr() as *const _,
            bytes,
            Some(&mut written),
        );
        if let Err(e) = write {
            let _ = VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            let _ = CloseHandle(process);
            return Err(format!("WriteProcessMemory failed: {e}"));
        }

        let kernel32 = GetModuleHandleW(PCWSTR(wide("kernel32.dll").as_ptr()))
            .map_err(|e| format!("kernel32: {e}"))?;
        let proc = GetProcAddress(kernel32, PCSTR(b"LoadLibraryW\0".as_ptr()))
            .ok_or_else(|| "LoadLibraryW not found".to_string())?;
        let start: LPTHREAD_START_ROUTINE = std::mem::transmute(proc);

        let thread = CreateRemoteThread(
            process,
            None,
            0,
            start,
            Some(remote as *const _),
            Default::default(),
            None,
        );

        let thread = match thread {
            Ok(t) => t,
            Err(e) => {
                let _ = VirtualFreeEx(process, remote, 0, MEM_RELEASE);
                let _ = CloseHandle(process);
                return Err(format!("CreateRemoteThread failed: {e}"));
            }
        };

        let waited = WaitForSingleObject(thread, 8000);
        let mut exit: u32 = 0;
        let _ = GetExitCodeThread(thread, &mut exit);
        let _ = CloseHandle(thread);
        let _ = VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        let _ = CloseHandle(process);

        if waited != WAIT_OBJECT_0 {
            return Err("injection thread timed out".into());
        }
        if exit == 0 {
            return Err("LoadLibraryW returned NULL — module rejected".into());
        }
        Ok(())
    }
}

#[allow(dead_code)]
pub(crate) fn resolve_module(name: &str) -> Option<usize> {
    unsafe {
        let wide_name = wide(name);
        match GetModuleHandleW(PCWSTR(wide_name.as_ptr())) {
            Ok(h) if !h.is_invalid() => Some(h.0 as usize),
            _ => LoadLibraryW(PCWSTR(wide_name.as_ptr()))
                .ok()
                .map(|h| h.0 as usize),
        }
    }
}

#[allow(dead_code)]
pub(crate) fn resolve_export(module: usize, name: &[u8]) -> Option<usize> {
    unsafe {
        let mut full = name.to_vec();
        full.push(0);
        GetProcAddress(
            windows::Win32::Foundation::HMODULE(module as *mut _),
            PCSTR(full.as_ptr()),
        )
        .map(|f| std::mem::transmute::<_, usize>(f))
    }
}
