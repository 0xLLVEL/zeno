#![cfg(windows)]

//! Section-backed image mapping.
//!
//! The payload is mapped as a real image section: the kernel applies base
//! relocations and resolves the import table, and the resulting VAD entry is
//! file-backed, so it does not look like unbacked executable memory.
//!
//! Every ntdll call goes through `crate::nt` (direct syscalls). If the SSN
//! table cannot be recovered we fall back to resolved ntdll exports.
//!
//! Not covered: handle filtering, thread-creation notification, image-load
//! notification, and `.text` integrity checks — those live in the kernel
//! component and in the pre-initialisation window.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::WaitForSingleObject;

use crate::nt;

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

pub(crate) fn entry_rva(dll: &Path) -> Result<u32, String> {
    let data = std::fs::read(dll).map_err(|e| format!("read payload: {e}"))?;
    if data.len() < 0x100 {
        return Err("payload too small".into());
    }
    let lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if data.len() < lfanew + 0x40 {
        return Err("truncated PE".into());
    }
    let sig = u32::from_le_bytes([
        data[lfanew],
        data[lfanew + 1],
        data[lfanew + 2],
        data[lfanew + 3],
    ]);
    if sig != 0x0000_4550 {
        return Err("bad PE signature".into());
    }
    let opt = lfanew + 24;
    if u16::from_le_bytes([data[opt], data[opt + 1]]) != 0x020B {
        return Err("only x64 payloads supported".into());
    }
    Ok(u32::from_le_bytes([
        data[opt + 16],
        data[opt + 17],
        data[opt + 18],
        data[opt + 19],
    ]))
}

pub(crate) fn open_payload(dll: &Path) -> Result<HANDLE, String> {
    let path = dll.canonicalize().map_err(|e| format!("payload not found: {e}"))?;
    let name = wide(path.as_os_str());
    unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| format!("CreateFileW: {e}"))
    }
}

pub fn map(pid: u32, dll: &Path) -> Result<(), String> {
    let entry = entry_rva(dll)?;
    let file = open_payload(dll)?;

    if nt::available() {
        let result = via_syscall(pid, file, entry);
        unsafe {
            let _ = CloseHandle(file);
        }
        result
    } else {
        let result = via_ntdll(pid, file, entry);
        unsafe {
            let _ = CloseHandle(file);
        }
        result
    }
}

fn via_syscall(pid: u32, file: HANDLE, entry: u32) -> Result<(), String> {
    if !crate::process::probe_write(pid) {
        return Err("handle rejected — kernel filter (Hyperion) is active".into());
    }

    let section = nt::create_section(file.0 as usize, nt::PAGE_RO, nt::SEC_IMAGE)?;
    let process = nt::open_process(pid, nt::PROCESS_ALL)?;

    let result = (|| -> Result<(), String> {
        let base = nt::map_view(process, section, nt::PAGE_RO)?;
        let start = base + entry as usize;

        let thread = nt::create_thread_ex(process, start, 1, 0)?;
        let waited = unsafe { WaitForSingleObject(HANDLE(thread as *mut _), 6000) };
        unsafe {
            let _ = CloseHandle(HANDLE(thread as *mut _));
        }
        if waited != WAIT_OBJECT_0 {
            return Err("DllMain thread timed out".into());
        }
        Ok(())
    })();

    unsafe {
        let _ = CloseHandle(HANDLE(section as *mut _));
        let _ = CloseHandle(HANDLE(process as *mut _));
    }
    result
}

// ---------------------------------------------------------------- fallback

type NtCreateSectionFn =
    unsafe extern "system" fn(*mut HANDLE, u32, usize, usize, u32, u32, HANDLE) -> i32;
type NtMapViewOfSectionFn =
    unsafe extern "system" fn(HANDLE, HANDLE, *mut usize, usize, usize, usize, *mut usize, u32, u32, u32)
        -> i32;
type NtCreateThreadExFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    usize,
    HANDLE,
    usize,
    usize,
    u32,
    usize,
    usize,
    usize,
    usize,
) -> i32;

fn ntdll_export(name: &[u8]) -> Result<usize, String> {
    unsafe {
        let ntdll = GetModuleHandleW(PCWSTR(wide("ntdll.dll").as_ptr()))
            .map_err(|e| format!("ntdll: {e}"))?;
        let mut full = name.to_vec();
        full.push(0);
        GetProcAddress(ntdll, PCSTR(full.as_ptr()))
            .map(|f| std::mem::transmute::<_, usize>(f))
            .ok_or_else(|| format!("missing ntdll export {}", String::from_utf8_lossy(name)))
    }
}

fn via_ntdll(pid: u32, file: HANDLE, entry: u32) -> Result<(), String> {
    let create_section: NtCreateSectionFn =
        unsafe { std::mem::transmute(ntdll_export(b"NtCreateSection")?) };
    let map_view: NtMapViewOfSectionFn =
        unsafe { std::mem::transmute(ntdll_export(b"NtMapViewOfSection")?) };
    let create_thread: NtCreateThreadExFn =
        unsafe { std::mem::transmute(ntdll_export(b"NtCreateThreadEx")?) };

    if !crate::process::probe_write(pid) {
        return Err("handle rejected — kernel filter (Hyperion) is active".into());
    }

    unsafe {
        let mut section = HANDLE::default();
        let status = create_section(&mut section, nt::SECTION_ALL_ACCESS, 0, 0, nt::PAGE_RO, nt::SEC_IMAGE, file);
        if status < 0 {
            return Err(format!("NtCreateSection failed: {status:#x}"));
        }

        let process = crate::process::open_for_injection(pid)
            .map_err(|e| format!("OpenProcess failed: {e}"))?;

        let mut base = 0usize;
        let mut view_size = 0usize;
        let status = map_view(
            section,
            process,
            &mut base,
            0,
            0,
            0,
            &mut view_size,
            nt::VIEW_UNMAP,
            0,
            nt::PAGE_RO,
        );
        let _ = CloseHandle(section);
        if status < 0 || base == 0 {
            let _ = CloseHandle(process);
            return Err(format!("NtMapViewOfSection failed: {status:#x}"));
        }

        let mut thread = HANDLE::default();
        let status = create_thread(
            &mut thread,
            nt::THREAD_ALL,
            0,
            process,
            base + entry as usize,
            1,
            0,
            0,
            0,
            0,
            0,
        );
        if status < 0 {
            let _ = CloseHandle(process);
            return Err(format!("NtCreateThreadEx failed: {status:#x}"));
        }

        let waited = WaitForSingleObject(thread, 6000);
        let _ = CloseHandle(thread);
        let _ = CloseHandle(process);
        if waited != WAIT_OBJECT_0 {
            return Err("DllMain thread timed out".into());
        }
    }

    Ok(())
}
