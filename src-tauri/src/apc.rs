#![cfg(windows)]

//! APC injection.
//!
//! The image is mapped the same way as `section` (file-backed, kernel-applied
//! relocations), but nothing is created to run it. Instead a 33-byte call stub
//! is written into the target and queued as a user-mode APC on threads that
//! already exist. No `NtCreateThreadEx`, so thread-creation notification never
//! fires; the work happens on a thread Roblox itself created.
//!
//! The stub is small but it is still unbacked executable memory. That is the
//! trade: fewer threads, one more RWX region.

use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
};
use windows::Win32::System::Threading::{
    OpenThread, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT,
};

use crate::nt;

fn threads_of(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) } {
        Ok(h) if !h.is_invalid() => h,
        _ => return out,
    };

    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    let mut ok = unsafe { Thread32First(snapshot, &mut entry) }.is_ok();
    while ok {
        if entry.th32OwnerProcessID == pid {
            out.push(entry.th32ThreadID);
        }
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        ok = unsafe { Thread32Next(snapshot, &mut entry) }.is_ok();
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }
    out
}

/// mov rcx, base / mov rdx, 1 / xor r8d, r8d / mov rax, entry / call rax / ret
fn build_stub(base: usize, entry: usize) -> Vec<u8> {
    let mut code = Vec::with_capacity(33);
    code.extend_from_slice(&[0x48, 0xB9]);
    code.extend_from_slice(&(base as u64).to_le_bytes());
    code.extend_from_slice(&[0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0x45, 0x31, 0xC0]);
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&(entry as u64).to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0, 0xC3]);
    code
}

pub fn inject(pid: u32, dll: &Path) -> Result<String, String> {
    if !nt::available() {
        return Err("APC injection needs the direct-syscall layer; SSN table unresolved".into());
    }
    if !crate::process::probe_write(pid) {
        return Err("handle rejected — kernel filter (Hyperion) is active".into());
    }

    let entry_rva = crate::section::entry_rva(dll)?;
    let file = crate::section::open_payload(dll)?;

    let outcome = (|| -> Result<String, String> {
        let section = nt::create_section(file.0 as usize, nt::PAGE_RO, nt::SEC_IMAGE)?;
        let process = nt::open_process(pid, nt::PROCESS_ALL)?;

        let inner = (|| -> Result<String, String> {
            let base = nt::map_view(process, section, nt::PAGE_RO)?;
            let entry = base + entry_rva as usize;

            let stub_mem = nt::allocate(process, 64)?;
            nt::write(process, stub_mem, &build_stub(base, entry))?;
            nt::protect(process, stub_mem, 64, nt::PAGE_RX)?;

            let targets = threads_of(pid);
            if targets.is_empty() {
                return Err("no thread to queue onto".into());
            }

            let mut queued = 0usize;
            for tid in targets.iter().take(16) {
                let handle = unsafe {
                    OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, *tid)
                };
                let Ok(thread) = handle else { continue };
                if nt::queue_apc(thread.0 as usize, stub_mem, 0).is_ok() {
                    queued += 1;
                }
                unsafe {
                    let _ = CloseHandle(thread);
                }
            }

            if queued == 0 {
                return Err("NtQueueApcThread rejected on every thread".into());
            }
            Ok(format!("queued on {queued}/{} threads", targets.len()))
        })();

        unsafe {
            let _ = CloseHandle(HANDLE(section as *mut _));
            let _ = CloseHandle(HANDLE(process as *mut _));
        }
        inner
    })();

    unsafe {
        let _ = CloseHandle(file);
    }

    outcome
}
