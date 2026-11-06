#![cfg(windows)]

//! Section-backed image mapping.
//!
//! Unlike `VirtualAllocEx` + `WriteProcessMemory`, this maps the payload as a
//! real image section. The kernel applies base relocations and resolves the
//! import table for us, and the resulting VAD entry is file-backed — so the
//! allocation does not look like unbacked executable memory.
//!
//! What this does NOT defeat: handle filtering, thread-creation notification,
//! image-load notification, or .text integrity checks. Those live in the
//! kernel component and in the pre-initialisation window respectively.

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

type NtStatus = i32;

type NtCreateSectionFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *const core::ffi::c_void,
    *const i64,
    u32,
    u32,
    HANDLE,
) -> NtStatus;

type NtMapViewOfSectionFn = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    *mut *mut core::ffi::c_void,
    usize,
    usize,
    *const i64,
    *mut usize,
    u32,
    u32,
    u32,
) -> NtStatus;

type NtCreateThreadExFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *const core::ffi::c_void,
    HANDLE,
    *const core::ffi::c_void,
    *const core::ffi::c_void,
    u32,
    usize,
    usize,
    usize,
    *const core::ffi::c_void,
) -> NtStatus;

const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const SEC_IMAGE: u32 = 0x0100_0000;
const PAGE_READONLY: u32 = 0x02;
const VIEW_UNMAP: u32 = 2;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

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

fn entry_rva(dll: &Path) -> Result<(u32, u32), String> {
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
    let magic = u16::from_le_bytes([data[opt], data[opt + 1]]);
    if magic != 0x020B {
        return Err("only x64 payloads supported".into());
    }
    let entry = u32::from_le_bytes([
        data[opt + 16],
        data[opt + 17],
        data[opt + 18],
        data[opt + 19],
    ]);
    Ok((entry, 0))
}

pub fn map(pid: u32, dll: &Path) -> Result<(), String> {
    let (entry, _) = entry_rva(dll)?;
    let path = dll.canonicalize().map_err(|e| format!("payload not found: {e}"))?;
    let wide_path = wide(path.as_os_str());

    let create_section: NtCreateSectionFn =
        unsafe { std::mem::transmute(ntdll_export(b"NtCreateSection")?) };
    let map_view: NtMapViewOfSectionFn =
        unsafe { std::mem::transmute(ntdll_export(b"NtMapViewOfSection")?) };
    let create_thread: NtCreateThreadExFn =
        unsafe { std::mem::transmute(ntdll_export(b"NtCreateThreadEx")?) };

    unsafe {
        let file = CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| format!("CreateFileW: {e}"))?;

        let mut section = HANDLE::default();
        let status = create_section(
            &mut section,
            SECTION_ALL_ACCESS,
            std::ptr::null(),
            std::ptr::null(),
            PAGE_READONLY,
            SEC_IMAGE,
            file,
        );
        let _ = CloseHandle(file);
        if status < 0 {
            return Err(format!("NtCreateSection failed: {status:#x}"));
        }

        if !crate::process::probe_write(pid) {
            let _ = CloseHandle(section);
            return Err("handle rejected — kernel filter (Hyperion) is active".into());
        }

        let process = crate::process::open_for_injection(pid)
            .map_err(|e| format!("OpenProcess failed: {e}"))?;

        let mut base: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;
        let status = map_view(
            section,
            process,
            &mut base,
            0,
            0,
            std::ptr::null(),
            &mut view_size,
            VIEW_UNMAP,
            0,
            PAGE_READONLY,
        );
        let _ = CloseHandle(section);
        if status < 0 || base.is_null() {
            let _ = CloseHandle(process);
            return Err(format!("NtMapViewOfSection failed: {status:#x}"));
        }

        let start = base as usize + entry as usize;

        let mut thread = HANDLE::default();
        let status = create_thread(
            &mut thread,
            THREAD_ALL_ACCESS,
            std::ptr::null(),
            process,
            start as *const core::ffi::c_void,
            1 as *const core::ffi::c_void, // DLL_PROCESS_ATTACH
            0,
            0,
            0,
            0,
            std::ptr::null(),
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
