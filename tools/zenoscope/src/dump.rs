//! `--dump`: reconstruct a readable copy of the live client.
//!
//! Hyperion keeps `.text` encrypted on disk and decrypts each page on demand,
//! just before it is executed. `NtFlushInstructionCache` over a range walks the
//! pages of another process, and the encrypted-page fault that walk raises is
//! serviced by the anti-tamper's own decryptor. The page comes back in the
//! clear, and `ReadProcessMemory` can take it from there.
//!
//! Every page is flushed on its own so each gets its own fault and its own
//! decrypt. The bytes are then written over the matching file offset of the
//! on-disk image, which gives a PE whose section table is still intact and
//! whose code is real.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

use crate::image::{PeImage, Section};
use crate::live;
use crate::scan;

type Handle = *mut c_void;

const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;

const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const EXECUTE_MASK: u32 = PAGE_EXECUTE
    | PAGE_EXECUTE_READ
    | PAGE_EXECUTE_READWRITE
    | PAGE_EXECUTE_WRITECOPY;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const TOKEN_QUERY: u32 = 0x0008;
const SE_PRIVILEGE_ENABLED: u32 = 0x0002;
const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;

#[repr(C)]
struct Luid {
    low: u32,
    high: i32,
}

#[repr(C)]
struct TokenPrivileges {
    count: u32,
    luid: Luid,
    attributes: u32,
}

#[repr(C)]
struct MemoryBasicInformation64 {
    base_address: u64,
    allocation_base: u64,
    allocation_protect: u32,
    _alignment1: u32,
    region_size: u64,
    state: u32,
    protect: u32,
    kind: u32,
    _alignment2: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
    fn GetCurrentProcess() -> Handle;
    fn VirtualProtectEx(
        process: Handle,
        address: *mut c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;
    fn VirtualAllocEx(
        process: Handle,
        address: *mut c_void,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut c_void;
    fn VirtualFreeEx(process: Handle, address: *mut c_void, size: usize, free_type: u32) -> i32;
    fn WriteProcessMemory(
        process: Handle,
        address: *mut c_void,
        buffer: *const c_void,
        size: usize,
        written: *mut usize,
    ) -> i32;
    fn CreateRemoteThread(
        process: Handle,
        attributes: *const c_void,
        stack_size: usize,
        start: *const c_void,
        parameter: *mut c_void,
        flags: u32,
        thread_id: *mut u32,
    ) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn GetExitCodeThread(thread: Handle, exit_code: *mut u32) -> i32;
    fn ReadProcessMemory(
        process: Handle,
        address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;
    fn VirtualQueryEx(
        process: Handle,
        address: *const c_void,
        info: *mut MemoryBasicInformation64,
        length: usize,
    ) -> usize;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtFlushInstructionCache(process: Handle, base: *const c_void, size: usize) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut Luid) -> i32;
    fn AdjustTokenPrivileges(
        token: Handle,
        disable_all: i32,
        new_state: *const TokenPrivileges,
        buffer_length: u32,
        previous: *mut TokenPrivileges,
        return_length: *mut u32,
    ) -> i32;
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// SeDebugPrivilege is what turns an administrator token into a handle the
/// protected client will answer. Without it even an elevated process is refused.
pub fn enable_debug_privilege() -> Result<bool, String> {
    unsafe {
        let mut token: Handle = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(format!(
                "OpenProcessToken failed ({})",
                GetLastError()
            ));
        }

        let name = wide("SeDebugPrivilege");
        let mut luid = Luid { low: 0, high: 0 };
        if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return Err("LookupPrivilegeValueW failed".into());
        }

        let state = TokenPrivileges {
            count: 1,
            luid,
            attributes: SE_PRIVILEGE_ENABLED,
        };
        if AdjustTokenPrivileges(token, 0, &state, 0, std::ptr::null_mut(), std::ptr::null_mut()) == 0
        {
            let error = GetLastError();
            CloseHandle(token);
            return Err(format!("AdjustTokenPrivileges failed ({error})"));
        }

        // AdjustTokenPrivileges reports success for a privilege it did not
        // grant; the error code is the only honest answer.
        let error = GetLastError();
        CloseHandle(token);
        if error == ERROR_NOT_ALL_ASSIGNED {
            return Ok(false);
        }
        Ok(true)
    }
}

pub struct SectionStats {
    pub name: String,
    pub span: u64,
    pub flushed: u64,
    pub flush_errors: u64,
    pub first_flush_status: Option<i32>,
    pub read: u64,
    pub unreadable: u64,
    pub first_read_error: Option<u32>,
    pub denied_protect: Vec<(u32, u64)>,
    pub changed_bytes: u64,
    pub runtime_executable: bool,
}

pub struct Report {
    pub pid: u32,
    pub base: u64,
    pub size: u32,
    pub module_path: String,
    pub sections: Vec<SectionStats>,
    pub image_bytes: u64,
    pub prologues_before: Vec<usize>,
    pub prologues_after: Vec<usize>,
    pub output: PathBuf,
    pub output_bytes: u64,
    pub rebuilt: Option<PathBuf>,
    pub notes: Vec<String>,
}

impl Report {
    pub fn totals(&self) -> (u64, u64, u64, u64) {
        let mut flushed = 0;
        let mut read = 0;
        let mut unreadable = 0;
        let mut changed = 0;
        for section in &self.sections {
            flushed += section.flushed;
            read += section.read;
            unreadable += section.unreadable;
            changed += section.changed_bytes;
        }
        (flushed, read, unreadable, changed)
    }
}

fn runtime_executable(handle: Handle, address: u64) -> Option<bool> {
    let (protect, state) = protection(handle, address)?;
    // Guard pages and reserved ranges are not execution targets.
    let execute = protect & 0xFF;
    Some(state == 0x1000 && execute & EXECUTE_MASK != 0)
}

fn read_page(handle: Handle, address: u64, size: usize) -> Result<Vec<u8>, u32> {
    let mut buffer = vec![0u8; size];
    let mut got = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            &mut got,
        )
    };
    if ok == 0 || got == 0 {
        return Err(unsafe { GetLastError() });
    }
    buffer.truncate(got);
    Ok(buffer)
}

fn protection(handle: Handle, address: u64) -> Option<(u32, u32)> {
    let mut info: MemoryBasicInformation64 = unsafe { std::mem::zeroed() };
    let asked = unsafe {
        VirtualQueryEx(
            handle,
            address as *const c_void,
            &mut info,
            std::mem::size_of::<MemoryBasicInformation64>(),
        )
    };
    (asked != 0).then_some((info.protect, info.state))
}

fn flush_page(handle: Handle, address: u64, size: usize) -> i32 {
    unsafe { NtFlushInstructionCache(handle, address as *const c_void, size) }
}

/// Section table offset for the on-disk image, so the characteristics of code
/// sections can be repaired in place.
fn section_table(image: &[u8]) -> Option<usize> {
    let pe = u32::from_le_bytes(image.get(0x3C..0x40)?.try_into().ok()?) as usize;
    let coff = pe.checked_add(4)?;
    let optional_size = u16::from_le_bytes(image.get(coff + 16..coff + 18)?.try_into().ok()?) as usize;
    Some(coff + 20 + optional_size)
}

fn mark_code(image: &mut [u8], sections: &[Section], executable: &[bool]) -> usize {
    let Some(table) = section_table(image) else {
        return 0;
    };

    let mut repaired = 0usize;
    for (index, section) in sections.iter().enumerate() {
        if !executable.get(index).copied().unwrap_or(false) {
            continue;
        }
        if section.has_execute_flag() {
            continue;
        }
        let flags_at = table + index * 40 + 36;
        if flags_at + 4 > image.len() {
            continue;
        }
        let characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        image[flags_at..flags_at + 4].copy_from_slice(&characteristics.to_le_bytes());
        repaired += 1;
    }
    repaired
}

fn counts(image: &PeImage) -> Vec<usize> {
    scan::count_patterns(image, &scan::PROLOGUES)
}

/// What one protected page looks like when the protection is lifted from the
/// outside: same bytes as disk (ciphertext) or real code (already decrypted).
pub struct PageProbe {
    pub rva: u64,
    pub protect_before: u32,
    pub lifted: bool,
    pub read_ok: bool,
    pub error: Option<u32>,
    pub same_as_disk: bool,
    pub head: String,
    pub prologue: Option<&'static str>,
}

pub fn inspect(pid: Option<u32>, module: &str, count: usize) -> Result<Vec<PageProbe>, String> {
    match enable_debug_privilege() {
        Ok(true) => {}
        Ok(false) => {
            return Err("SeDebugPrivilege was not granted — run from an elevated shell".into())
        }
        Err(because) => return Err(format!("privilege: {because}")),
    }

    let pid = match pid {
        Some(pid) => pid,
        None => live::find_pid(crate::CLIENT_EXE)
            .ok_or_else(|| format!("{} is not running; pass --pid <n>", crate::CLIENT_EXE))?,
    };

    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "OpenProcess({pid}) with PROCESS_ALL_ACCESS failed ({}); elevation is required",
            unsafe { GetLastError() }
        ));
    }

    let result = inspect_with(handle, pid, module, count);
    unsafe { CloseHandle(handle) };
    result
}

fn inspect_with(
    handle: Handle,
    pid: u32,
    module: &str,
    count: usize,
) -> Result<Vec<PageProbe>, String> {
    let (base, _size, module_path) = live::module_info(pid, module)
        .ok_or_else(|| format!("module {module} is not loaded in pid {pid}"))?;
    let disk = std::fs::read(&module_path)
        .map_err(|e| format!("cannot read {module_path}: {e}"))?;
    let parsed = PeImage::parse(disk.clone())?;

    let section = parsed
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .or_else(|| parsed.sections.iter().find(|s| s.span() > 0x100_000))
        .ok_or("no code section to inspect")?;

    let span = section.span() as u64;
    let count = count.max(1);
    let step = ((span / count as u64) & !0xFFF).max(0x1000);

    let mut probes = Vec::new();
    for index in 0..count as u64 {
        let rva = index * step;
        if rva + 0x1000 > span {
            break;
        }
        let address = base + section.virtual_address as u64 + rva;
        let protect_before = protection(handle, address).map(|(p, _)| p).unwrap_or(0);

        let mut previous = 0u32;
        let lifted = unsafe {
            VirtualProtectEx(
                handle,
                address as *mut c_void,
                0x1000,
                PAGE_READONLY,
                &mut previous,
            )
        } != 0;

        let mut probe = PageProbe {
            rva,
            protect_before,
            lifted,
            read_ok: false,
            error: None,
            same_as_disk: false,
            head: String::new(),
            prologue: None,
        };

        match read_page(handle, address, 0x1000) {
            Ok(bytes) => {
                probe.read_ok = true;
                probe.head = bytes[..16]
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                probe.prologue = crate::scan::PROLOGUES
                    .iter()
                    .take(2)
                    .position(|pattern| bytes.starts_with(pattern))
                    .map(|i| if i == 0 { "48 89 5C 24" } else { "48 83 EC" });

                let file_offset = section.raw_pointer as u64 + rva;
                let end = file_offset + 0x1000;
                if end <= disk.len() as u64 {
                    probe.same_as_disk =
                        disk[file_offset as usize..end as usize] == bytes[..];
                }
            }
            Err(error) => probe.error = Some(error),
        }

        if lifted {
            let mut ignored = 0u32;
            unsafe {
                VirtualProtectEx(handle, address as *mut c_void, 0x1000, previous, &mut ignored)
            };
        }

        probes.push(probe);
    }

    Ok(probes)
}

// ------------------------------------------------------------- forced dump

const MEM_COMMIT_RESERVE: u32 = 0x3000;
const MEM_RELEASE: u32 = 0x8000;
const WAIT_TIMEOUT: u32 = 0x102;

/// `mov rbx, rcx / mov rsi, [rbx] / mov rdi, [rbx+8] / mov rcx, [rbx+16] /
/// rep movsb / ret` — copies `len` bytes inside the target. Every source page
/// it touches faults, and the target's own handler is what decrypts it.
const STUB: [u8; 18] = [
    0x48, 0x89, 0xCB, 0x48, 0x8B, 0x33, 0x48, 0x8B, 0x7B, 0x08, 0x48, 0x8B, 0x4B, 0x10, 0xF3, 0xA4,
    0xC3, 0x90,
];

pub struct ChunkResult {
    pub rva: u64,
    pub len: u64,
    pub ran: bool,
    pub waited: u32,
    pub exit_code: u32,
    pub changed_bytes: u64,
}

pub struct ForcedReport {
    pub pid: u32,
    pub base: u64,
    pub module_path: String,
    pub chunks: Vec<ChunkResult>,
    pub prologues_before: Vec<usize>,
    pub prologues_after: Vec<usize>,
    pub output: PathBuf,
    pub output_bytes: u64,
    pub notes: Vec<String>,
}

fn write_remote(handle: Handle, address: *mut c_void, bytes: &[u8]) -> bool {
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(
            handle,
            address,
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            &mut written,
        ) != 0
            && written == bytes.len()
    }
}

/// Run the copy stub once inside the target over `[address, address+len)`.
fn run_stub(
    handle: Handle,
    stub: *mut c_void,
    param: *mut c_void,
    source: u64,
    destination: u64,
    len: u64,
) -> (bool, u32, u32) {
    let mut block = [0u8; 0x18];
    block[0..8].copy_from_slice(&source.to_le_bytes());
    block[8..0x10].copy_from_slice(&destination.to_le_bytes());
    block[0x10..0x18].copy_from_slice(&len.to_le_bytes());
    if !write_remote(handle, param, &block) {
        return (false, 0, 0);
    }

    let thread = unsafe {
        CreateRemoteThread(
            handle,
            std::ptr::null(),
            0,
            stub as *const c_void,
            param,
            0,
            std::ptr::null_mut(),
        )
    };
    if thread.is_null() || thread == INVALID_HANDLE_VALUE {
        return (false, 0, 0);
    }

    let waited = unsafe { WaitForSingleObject(thread, 30_000) };
    let mut exit_code = 0u32;
    unsafe { GetExitCodeThread(thread, &mut exit_code) };
    unsafe { CloseHandle(thread) };

    (waited == 0, waited, exit_code)
}

pub fn force(pid: Option<u32>, module: &str, out: Option<PathBuf>) -> Result<ForcedReport, String> {
    match enable_debug_privilege() {
        Ok(true) => {}
        Ok(false) => {
            return Err("SeDebugPrivilege was not granted — run from an elevated shell".into())
        }
        Err(because) => return Err(format!("privilege: {because}")),
    }

    let pid = match pid {
        Some(pid) => pid,
        None => live::find_pid(crate::CLIENT_EXE)
            .ok_or_else(|| format!("{} is not running; pass --pid <n>", crate::CLIENT_EXE))?,
    };

    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "OpenProcess({pid}) with PROCESS_ALL_ACCESS failed ({}); elevation is required",
            unsafe { GetLastError() }
        ));
    }

    let result = force_with(handle, pid, module, out, Vec::new());
    unsafe { CloseHandle(handle) };
    result
}

fn force_with(
    handle: Handle,
    pid: u32,
    module: &str,
    out: Option<PathBuf>,
    mut notes: Vec<String>,
) -> Result<ForcedReport, String> {
    let (base, _size, module_path) = live::module_info(pid, module)
        .ok_or_else(|| format!("module {module} is not loaded in pid {pid}"))?;

    let source = Path::new(&module_path);
    let mut image =
        std::fs::read(source).map_err(|e| format!("cannot read {}: {e}", source.display()))?;
    let parsed = PeImage::parse(image.clone())?;
    let before = counts(&parsed);

    let section = parsed
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .cloned()
        .ok_or("no .text section in this image")?;

    let span = section.span() as u64;
    let raw = section.raw_size as u64;
    let chunk_size = 8usize * 1024 * 1024;

    let buffer = unsafe {
        VirtualAllocEx(
            handle,
            std::ptr::null_mut(),
            chunk_size,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        )
    };
    if buffer.is_null() {
        return Err(format!("VirtualAllocEx failed ({})", unsafe { GetLastError() }));
    }

    let param = unsafe {
        VirtualAllocEx(
            handle,
            std::ptr::null_mut(),
            0x1000,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        )
    };
    let stub = unsafe {
        VirtualAllocEx(
            handle,
            std::ptr::null_mut(),
            0x1000,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        )
    };
    if param.is_null() || stub.is_null() {
        unsafe {
            VirtualFreeEx(handle, buffer, 0, MEM_RELEASE);
        }
        return Err("cannot allocate parameter or stub memory in the target".into());
    }

    let mut ok = write_remote(handle, stub, &STUB);
    let mut previous = 0u32;
    if ok {
        ok = unsafe {
            VirtualProtectEx(handle, stub, 0x1000, PAGE_EXECUTE_READ, &mut previous)
        } != 0;
    }
    if !ok {
        notes.push("the target refused to let the stub become executable".into());
    }

    let mut chunks = Vec::new();
    let mut cursor = 0u64;

    while ok && cursor < span {
        let len = (span - cursor).min(chunk_size as u64);
        let address = base + section.virtual_address as u64 + cursor;

        let (ran, waited, exit_code) =
            run_stub(handle, stub, param, address, buffer as u64, len);
        if !ran {
            notes.push(format!(
                "the copy thread did not finish at rva 0x{cursor:X} (wait 0x{waited:X}{})",
                if waited == WAIT_TIMEOUT { ", timed out" } else { "" }
            ));
        }

        let mut changed = 0u64;
        if let Ok(bytes) = read_page(handle, buffer as u64, len as usize) {
            let file_bytes = raw.saturating_sub(cursor).min(bytes.len() as u64);
            if file_bytes > 0 {
                let file_offset = section.raw_pointer as u64 + cursor;
                let end = file_offset + file_bytes;
                if end <= image.len() as u64 {
                    let live = &bytes[..file_bytes as usize];
                    let disk = &mut image[file_offset as usize..end as usize];
                    changed = disk.iter().zip(live).filter(|(a, b)| a != b).count() as u64;
                    disk.copy_from_slice(live);
                }
            }
        } else {
            notes.push(format!(
                "cannot read the staging buffer after rva 0x{cursor:X}"
            ));
        }

        chunks.push(ChunkResult {
            rva: cursor,
            len,
            ran,
            waited,
            exit_code,
            changed_bytes: changed,
        });

        if !ran {
            break;
        }
        cursor += len;
    }

    let output = out.unwrap_or_else(|| {
        let mut path = source.to_path_buf();
        let name = path
            .file_stem()
            .map(|n| format!("{}.forced.exe", n.to_string_lossy()))
            .unwrap_or_else(|| "forced.exe".into());
        path.set_file_name(name);
        path
    });
    std::fs::write(&output, &image)
        .map_err(|e| format!("cannot write {}: {e}", output.display()))?;

    unsafe {
        VirtualFreeEx(handle, param, 0, MEM_RELEASE);
        VirtualFreeEx(handle, stub, 0, MEM_RELEASE);
        VirtualFreeEx(handle, buffer, 0, MEM_RELEASE);
    }

    let after_parsed = PeImage::parse(image)?;
    let after = counts(&after_parsed);

    Ok(ForcedReport {
        pid,
        base,
        module_path,
        chunks,
        prologues_before: before,
        prologues_after: after,
        output_bytes: std::fs::metadata(&output).map(|m| m.len()).unwrap_or(0),
        output,
        notes,
    })
}

// ------------------------------------------------------------ watch mode

pub struct WatchReport {
    pub pid: u32,
    pub base: u64,
    pub module_path: String,
    pub pages_total: u64,
    pub pages_readable: u64,
    pub new_pages: u64,
    pub seconds: u64,
    pub prologues_before: Vec<usize>,
    pub prologues_after: Vec<usize>,
    pub output: PathBuf,
    pub output_bytes: u64,
    pub rebuilt: Option<PathBuf>,
    pub notes: Vec<String>,
}

/// Sample `.text` continuously and keep every page the client has decrypted.
/// Hyperion only keeps the pages it is currently executing in the clear, so a
/// single snapshot is a slice; sampling over a session accumulates the rest.
pub fn watch(
    pid: Option<u32>,
    module: &str,
    base_image: Option<PathBuf>,
    seconds: u64,
    out: Option<PathBuf>,
    rebuild: bool,
    follow: bool,
) -> Result<WatchReport, String> {
    match enable_debug_privilege() {
        Ok(true) => {}
        Ok(false) => {
            return Err("SeDebugPrivilege was not granted — run from an elevated shell".into())
        }
        Err(because) => return Err(format!("privilege: {because}")),
    }

    if follow {
        return harvest(pid, module, base_image, seconds, out, rebuild);
    }

    let pid = match pid {
        Some(pid) => pid,
        None => live::find_pid(crate::CLIENT_EXE)
            .ok_or_else(|| format!("{} is not running; pass --pid <n>", crate::CLIENT_EXE))?,
    };

    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "OpenProcess({pid}) with PROCESS_ALL_ACCESS failed ({}); elevation is required",
            unsafe { GetLastError() }
        ));
    }

    let result = watch_with(handle, pid, module, base_image, seconds, out, rebuild);
    unsafe { CloseHandle(handle) };
    result
}

struct Target {
    handle: Handle,
    pid: u32,
    base: u64,
    path: String,
}

/// First live client that has `module` loaded. With `follow`, a dead `--pid`
/// hint falls back to whatever the newest matching process is, which is what
/// happens when the client restarts on a game switch.
fn attach_target(hint: Option<u32>, module: &str, follow: bool) -> Result<Option<Target>, String> {
    let candidates: Vec<Option<u32>> = match (follow, hint) {
        (true, Some(h)) => vec![Some(h), None],
        (true, None) | (false, None) => vec![None],
        (false, Some(h)) => vec![Some(h)],
    };

    for candidate in candidates {
        let pid = match candidate {
            Some(pid) => pid,
            None => match live::find_pid(crate::CLIENT_EXE) {
                Some(pid) => pid,
                None => continue,
            },
        };
        if live::module_info(pid, module).is_none() {
            continue;
        }

        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "OpenProcess({pid}) with PROCESS_ALL_ACCESS failed ({}); elevation is required",
                unsafe { GetLastError() }
            ));
        }

        let Some((base, _size, path)) = live::module_info(pid, module) else {
            unsafe { CloseHandle(handle) };
            continue;
        };

        return Ok(Some(Target {
            handle,
            pid,
            base,
            path,
        }));
    }

    Ok(None)
}

/// Pages already harvested show up as bytes that differ from the on-disk
/// ciphertext. Seeding the bitmap from that difference keeps a resumed pass
/// from re-reading them and makes the coverage count the merged total.
fn seed_captured(
    image: &[u8],
    disk: &[u8],
    section: &Section,
    raw: u64,
    pages: usize,
) -> Vec<bool> {
    let mut captured = vec![false; pages];
    if disk.len() != image.len() {
        return captured;
    }
    for index in 0..pages as u64 {
        let offset = index * 0x1000;
        if offset >= raw {
            break;
        }
        let start = section.raw_pointer as usize + offset as usize;
        let end = (start + (raw - offset).min(0x1000) as usize).min(image.len());
        if start >= end {
            continue;
        }
        captured[index as usize] = image[start..end] != disk[start..end];
    }
    captured
}

/// Sample one pass over `.text` and copy every page the client has decrypted.
/// Returns `(newly captured, readable this pass)`.
fn scan_once(
    handle: Handle,
    base: u64,
    section: &Section,
    raw: u64,
    image: &mut [u8],
    captured: &mut [bool],
) -> (u64, u64) {
    let mut new_pages = 0u64;
    let mut readable_total = 0u64;

    for index in 0..captured.len() as u64 {
        if captured[index as usize] {
            continue;
        }
        let offset = index * 0x1000;
        if offset >= raw {
            break;
        }
        let address = base + section.virtual_address as u64 + offset;
        let Some((protect, state)) = protection(handle, address) else {
            continue;
        };
        if state != 0x1000 {
            continue;
        }
        let access = protect & 0xFF;
        if !matches!(access, 0x02 | 0x04 | 0x20 | 0x40 | 0x80) {
            continue;
        }
        readable_total += 1;

        let len = (raw - offset).min(0x1000);
        let Ok(bytes) = read_page(handle, address, len as usize) else {
            continue;
        };

        let file_offset = section.raw_pointer as u64 + offset;
        let end = file_offset + len;
        if end <= image.len() as u64 {
            image[file_offset as usize..end as usize].copy_from_slice(&bytes[..len as usize]);
            captured[index as usize] = true;
            new_pages += 1;
        }
    }

    (new_pages, readable_total)
}

/// Sampling that survives a client restart. The client spawns a fresh process
/// on most game switches; pages already harvested stay in the in-memory image,
/// so coverage is cumulative across every process the session touches.
fn harvest(
    pid_hint: Option<u32>,
    module: &str,
    base_image: Option<PathBuf>,
    seconds: u64,
    out: Option<PathBuf>,
    rebuild: bool,
) -> Result<WatchReport, String> {
    let started = std::time::Instant::now();
    let mut target: Option<Target> = None;
    let mut notes: Vec<String> = Vec::new();
    let mut pids: Vec<u32> = Vec::new();

    let mut image: Option<Vec<u8>> = None;
    let mut section: Option<Section> = None;
    let mut captured: Vec<bool> = Vec::new();
    let mut raw = 0u64;
    let mut base = 0u64;
    let mut module_path = String::new();
    let mut source = PathBuf::new();
    let mut out_path: Option<PathBuf> = None;
    let mut before: Vec<usize> = Vec::new();
    let mut new_pages = 0u64;
    let mut readable_total = 0u64;
    let mut last_report = 0u64;
    let mut last_checkpoint = 0u64;

    loop {
        let elapsed = started.elapsed().as_secs();
        if elapsed >= seconds {
            break;
        }

        let alive = target
            .as_ref()
            .map(|t| live::module_info(t.pid, module).is_some())
            .unwrap_or(false);

        if !alive {
            if let Some(dead) = target.take() {
                unsafe { CloseHandle(dead.handle) };
                notes.push(format!("pid {} exited at {}s", dead.pid, elapsed));
                println!("  detach       pid {} at {}s", dead.pid, elapsed);
            }

            match attach_target(pid_hint, module, true)? {
                Some(next) => {
                    println!("  attach       pid {}  base 0x{:X}", next.pid, next.base);

                    if image.is_none() {
                        let src = Path::new(&next.path).to_path_buf();
                        source = src.clone();
                        let origin = base_image.clone().unwrap_or_else(|| src.clone());
                        let bytes = std::fs::read(&origin)
                            .map_err(|e| format!("cannot read {}: {e}", origin.display()))?;
                        let parsed = PeImage::parse(bytes.clone())?;
                        before = counts(&parsed);
                        let text = parsed
                            .sections
                            .iter()
                            .find(|s| s.name == ".text")
                            .cloned()
                            .ok_or("no .text section in this image")?;
                        raw = text.raw_size as u64;
                        let pages = text.span().div_ceil(0x1000) as usize;
                        let disk = std::fs::read(&next.path)
                            .map_err(|e| format!("cannot read {}: {e}", next.path))?;
                        captured = seed_captured(&bytes, &disk, &text, raw, pages);
                        let resumed = captured.iter().filter(|c| **c).count() as u64;
                        if resumed > 0 {
                            notes.push(format!("resumed with {resumed} pages already harvested"));
                            println!(
                                "  resume       {} pages already in the base image",
                                crate::thousands(resumed)
                            );
                        }
                        module_path = next.path.clone();
                        out_path = Some(out.clone().unwrap_or_else(|| {
                            let mut path = src.clone();
                            let name = path
                                .file_stem()
                                .map(|n| format!("{}.watched.exe", n.to_string_lossy()))
                                .unwrap_or_else(|| "watched.exe".into());
                            path.set_file_name(name);
                            path
                        }));
                        section = Some(text);
                        image = Some(bytes);
                        if origin != source {
                            notes.push(format!("started from {}", origin.display()));
                        }
                    } else if next.path != module_path {
                        unsafe { CloseHandle(next.handle) };
                        return Err(format!(
                            "client switched to a different build ({}); refusing to merge two layouts",
                            next.path
                        ));
                    }

                    base = next.base;
                    pids.push(next.pid);
                    target = Some(next);
                }
                None => {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    continue;
                }
            }
        }

        if let (Some(t), Some(sec), Some(img)) = (&target, &section, image.as_mut()) {
            base = t.base;
            let (new, _readable) = scan_once(t.handle, base, sec, raw, img, &mut captured);
            new_pages += new;
        }

        let elapsed = started.elapsed().as_secs();
        if elapsed >= last_report + 5 {
            last_report = elapsed;
            let pid = target.as_ref().map(|t| t.pid).unwrap_or(0);
            println!(
                "  {:>4}s  pid {:>6}  {} / {} pages captured",
                elapsed,
                pid,
                crate::thousands(captured.iter().filter(|c| **c).count() as u64),
                crate::thousands(captured.len() as u64)
            );
        }

        if elapsed >= last_checkpoint + 60 {
            last_checkpoint = elapsed;
            if let (Some(path), Some(img)) = (&out_path, image.as_ref()) {
                if std::fs::write(path, img).is_ok() {
                    println!(
                        "  checkpoint   {} pages -> {}",
                        crate::thousands(captured.iter().filter(|c| **c).count() as u64),
                        path.display()
                    );
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(400));
    }

    let Some(image) = image else {
        return Err(format!("{module} was never attached for pid {pid_hint:?}"));
    };
    let Some(output) = out_path else {
        return Err("harvest finished without an output path".into());
    };

    std::fs::write(&output, &image)
        .map_err(|e| format!("cannot write {}: {e}", output.display()))?;

    let after = counts(&PeImage::parse(image.clone())?);

    let mut rebuilt_path = None;
    if rebuild {
        match &target {
            Some(t) => {
                let parsed = PeImage::parse(image.clone())?;
                let mut blocks = Vec::with_capacity(parsed.sections.len());
                for sec in &parsed.sections {
                    let mut block = seed_block(&image, sec);
                    if sec.name != ".text" {
                        fill_block(t.handle, t.base, sec, &mut block);
                    }
                    blocks.push(block);
                }
                let rebuilt = rebuild_image(&image, &parsed.sections, &blocks)?;
                let mut path = output.clone();
                path.set_file_name(format!(
                    "{}.rebuilt.exe",
                    path.file_stem().map(|n| n.to_string_lossy()).unwrap_or_default()
                ));
                std::fs::write(&path, &rebuilt)
                    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                rebuilt_path = Some(path);
            }
            None => notes.push("rebuild skipped: the client is no longer running".into()),
        }
    }

    if pids.len() > 1 {
        let listed: Vec<String> = pids.iter().map(|p| p.to_string()).collect();
        notes.push(format!("merged {} processes: {}", pids.len(), listed.join(", ")));
    }

    let pid = target.as_ref().map(|t| t.pid).unwrap_or(*pids.last().unwrap_or(&0));
    let module_path = if module_path.is_empty() {
        source.display().to_string()
    } else {
        module_path
    };

    if let Some(t) = target.take() {
        unsafe { CloseHandle(t.handle) };
    }

    Ok(WatchReport {
        pid,
        base,
        module_path,
        pages_total: captured.len() as u64,
        pages_readable: captured.iter().filter(|c| **c).count() as u64,
        new_pages,
        seconds,
        prologues_before: before,
        prologues_after: after,
        output_bytes: std::fs::metadata(&output).map(|m| m.len()).unwrap_or(0),
        output,
        rebuilt: rebuilt_path,
        notes,
    })
}

fn watch_with(
    handle: Handle,
    pid: u32,
    module: &str,
    base_image: Option<PathBuf>,
    seconds: u64,
    out: Option<PathBuf>,
    rebuild: bool,
) -> Result<WatchReport, String> {
    let (base, _size, module_path) = live::module_info(pid, module)
        .ok_or_else(|| format!("module {module} is not loaded in pid {pid}"))?;

    let source = Path::new(&module_path);
    let origin = base_image.clone().unwrap_or_else(|| source.to_path_buf());
    let mut image = std::fs::read(&origin)
        .map_err(|e| format!("cannot read {}: {e}", origin.display()))?;

    let parsed = PeImage::parse(image.clone())?;
    let before = counts(&parsed);

    let section = parsed
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .cloned()
        .ok_or("no .text section in this image")?;

    let span = section.span() as u64;
    let raw = section.raw_size as u64;
    let pages = span.div_ceil(0x1000);
    let disk = std::fs::read(&module_path).unwrap_or_default();
    let mut captured = seed_captured(&image, &disk, &section, raw, pages as usize);
    let mut new_pages = 0u64;

    let started = std::time::Instant::now();
    let mut last_report = 0u64;

    loop {
        let (new, _readable) = scan_once(handle, base, &section, raw, &mut image, &mut captured);
        new_pages += new;

        let elapsed = started.elapsed().as_secs();
        if elapsed >= seconds {
            break;
        }
        if elapsed >= last_report + 5 {
            last_report = elapsed;
            println!(
                "  {:>3}s  {} / {} pages captured",
                elapsed,
                crate::thousands(captured.iter().filter(|c| **c).count() as u64),
                crate::thousands(pages)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }

    let output = out.unwrap_or_else(|| {
        let mut path = source.to_path_buf();
        let name = path
            .file_stem()
            .map(|n| format!("{}.watched.exe", n.to_string_lossy()))
            .unwrap_or_else(|| "watched.exe".into());
        path.set_file_name(name);
        path
    });
    std::fs::write(&output, &image)
        .map_err(|e| format!("cannot write {}: {e}", output.display()))?;

    let after_parsed = PeImage::parse(image.clone())?;
    let after = counts(&after_parsed);

    let mut notes = Vec::new();
    if origin != source {
        notes.push(format!("started from {}", origin.display()));
    }

    let mut rebuilt_path = None;
    if rebuild {
        let mut blocks = Vec::with_capacity(parsed.sections.len());
        for section in &parsed.sections {
            let mut block = seed_block(&image, section);
            if section.name != ".text" {
                fill_block(handle, base, section, &mut block);
            }
            blocks.push(block);
        }
        let rebuilt = rebuild_image(&image, &parsed.sections, &blocks)?;
        let mut path = output.clone();
        path.set_file_name(format!(
            "{}.rebuilt.exe",
            path.file_stem().map(|n| n.to_string_lossy()).unwrap_or_default()
        ));
        std::fs::write(&path, &rebuilt)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        rebuilt_path = Some(path);
    }

    Ok(WatchReport {
        pid,
        base,
        module_path,
        pages_total: pages,
        pages_readable: captured.iter().filter(|c| **c).count() as u64,
        new_pages,
        seconds,
        prologues_before: before,
        prologues_after: after,
        output_bytes: std::fs::metadata(&output).map(|m| m.len()).unwrap_or(0),
        output,
        rebuilt: rebuilt_path,
        notes,
    })
}

fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        value
    } else {
        value.div_ceil(alignment) * alignment
    }
}

fn read_u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u32_at(data: &mut [u8], offset: usize, value: u32) {
    if offset + 4 <= data.len() {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}

/// Section contents as the file would hold them: disk bytes where they exist,
/// zeroes where the loader fills at runtime, overwritten by live pages.
fn seed_block(image: &[u8], section: &Section) -> Vec<u8> {
    let span = section.span() as usize;
    let mut block = vec![0u8; span];
    let raw = (section.raw_size as usize).min(span);
    let start = section.raw_pointer as usize;
    if raw > 0 && start < image.len() {
        let copy = raw.min(image.len() - start);
        block[..copy].copy_from_slice(&image[start..start + copy]);
    }
    block
}

/// Rewrite the layout so every section's raw size covers its whole virtual
/// span. The loader's zero-fill region is where most of the engine's globals
/// live, so a faithful image keeps them out of reach of every reader.
fn rebuild_image(image: &[u8], sections: &[Section], blocks: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let pe = read_u32_at(image, 0x3C).ok_or("truncated PE header")? as usize;
    let coff = pe + 4;
    let optional = coff + 20;
    let optional_size = image
        .get(coff + 16..coff + 18)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
        .ok_or("truncated COFF header")?;
    let table = optional + optional_size;

    let file_alignment = read_u32_at(image, optional + 36).unwrap_or(0x200).max(0x200) as u64;
    let section_alignment = read_u32_at(image, optional + 32).unwrap_or(0x1000).max(0x1000) as u64;
    let size_of_headers = read_u32_at(image, optional + 60).unwrap_or(0x400) as u64;

    let header_end = align_up(size_of_headers, file_alignment);
    let mut out = vec![0u8; header_end as usize];
    let copy = image.len().min(header_end as usize);
    out[..copy].copy_from_slice(&image[..copy]);

    let mut cursor = header_end;
    for (index, _section) in sections.iter().enumerate() {
        let data = &blocks[index];
        let raw_size = align_up(data.len() as u64, file_alignment);
        let offset = align_up(cursor, file_alignment);

        out.resize((offset + raw_size) as usize, 0);
        out[offset as usize..offset as usize + data.len()].copy_from_slice(data);

        let header = table + index * 40;
        write_u32_at(&mut out, header + 16, raw_size as u32);
        write_u32_at(&mut out, header + 20, offset as u32);

        cursor = offset + raw_size;
    }

    let mut end = 0u64;
    for section in sections {
        end = end.max(section.virtual_address as u64 + section.span() as u64);
    }
    write_u32_at(&mut out, optional + 56, align_up(end, section_alignment) as u32);

    Ok(out)
}

fn fill_block(handle: Handle, base: u64, section: &Section, block: &mut [u8]) -> u64 {
    let span = section.span() as u64;
    let start = base + section.virtual_address as u64;
    let mut rva = 0u64;
    let mut read = 0u64;
    while rva < span {
        let page = (span - rva).min(0x1000);
        if let Ok(bytes) = read_page(handle, start + rva, page as usize) {
            let length = bytes.len().min(page as usize);
            block[rva as usize..rva as usize + length].copy_from_slice(&bytes[..length]);
            read += 1;
        }
        rva += page;
    }
    read
}

// ------------------------------------------------------------ chain walk

pub struct Hop {
    pub label: String,
    pub address: u64,
    pub value: u64,
    pub name: String,
    pub class: String,
}

fn read_u64_live(handle: Handle, address: u64) -> Option<u64> {
    if address < 0x10000 {
        return None;
    }
    let bytes = read_page(handle, address, 8).ok()?;
    if bytes.len() < 8 {
        return None;
    }
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// MSVC `std::string`: 16 inline bytes, length at +0x10, heap pointer when long.
fn read_string_live(handle: Handle, address: u64) -> String {
    if address < 0x10000 {
        return String::new();
    }
    let Some(head) = read_page(handle, address, 0x20).ok() else {
        return String::new();
    };
    if head.len() < 0x18 {
        return String::new();
    }

    let length = i32::from_le_bytes([head[0x10], head[0x11], head[0x12], head[0x13]]);
    if length <= 0 || length > 4096 {
        return String::new();
    }

    let data = if length >= 16 {
        let pointer = u64::from_le_bytes([
            head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7],
        ]);
        match read_page(handle, pointer, length as usize) {
            Ok(bytes) => bytes,
            Err(_) => return String::new(),
        }
    } else {
        head[..length as usize].to_vec()
    };

    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn describe(handle: Handle, instance: u64, offsets: &HashMap<String, u64>) -> (String, String) {
    let name_offset = offsets.get("Instance::NameContainer").copied().unwrap_or(0);
    let class_offset = offsets.get("Instance::ClassDescriptor").copied().unwrap_or(0);
    let class_name_offset = offsets.get("Instance::ClassName").copied().unwrap_or(0);

    let name = if name_offset != 0 {
        read_u64_live(handle, instance + name_offset)
            .map(|base| {
                read_string_live(
                    handle,
                    base + offsets.get("Instance::Name").copied().unwrap_or(0),
                )
            })
            .unwrap_or_default()
    } else {
        String::new()
    };

    let class = if class_offset != 0 {
        read_u64_live(handle, instance + class_offset)
            .and_then(|descriptor| read_u64_live(handle, descriptor + class_name_offset))
            .map(|text| read_string_live(handle, text))
            .unwrap_or_default()
    } else {
        String::new()
    };

    (name, class)
}

/// Follow the pack's globals through the live client: VisualEngine ->
/// FakeDataModel -> DataModel -> Workspace / ScriptContext, with each object's
/// name and class read straight out of the engine's own layout.
pub fn chain(
    pid: Option<u32>,
    module: &str,
    offsets: &HashMap<String, u64>,
) -> Result<Vec<Hop>, String> {
    match enable_debug_privilege() {
        Ok(true) => {}
        Ok(false) => {
            return Err("SeDebugPrivilege was not granted — run from an elevated shell".into())
        }
        Err(because) => return Err(format!("privilege: {because}")),
    }

    let pid = match pid {
        Some(pid) => pid,
        None => live::find_pid(crate::CLIENT_EXE)
            .ok_or_else(|| format!("{} is not running; pass --pid <n>", crate::CLIENT_EXE))?,
    };

    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "OpenProcess({pid}) with PROCESS_ALL_ACCESS failed ({}); elevation is required",
            unsafe { GetLastError() }
        ));
    }

    let result = chain_with(handle, pid, module, offsets);
    unsafe { CloseHandle(handle) };
    result
}

fn chain_with(
    handle: Handle,
    pid: u32,
    module: &str,
    offsets: &HashMap<String, u64>,
) -> Result<Vec<Hop>, String> {
    let (base, _size, _path) = live::module_info(pid, module)
        .ok_or_else(|| format!("module {module} is not loaded in pid {pid}"))?;

    let mut hops = Vec::new();
    let mut push = |label: &str, address: u64, value: u64| {
        let (name, class) = describe(handle, address, offsets);
        hops.push(Hop {
            label: label.to_string(),
            address,
            value,
            name,
            class,
        });
    };

    let slot = |key: &str| offsets.get(key).copied().unwrap_or(0) as u64;

    let visual_slot = base + slot("VisualEngine::Pointer");
    let visual = read_u64_live(handle, visual_slot).unwrap_or(0);
    push("VisualEngine::Pointer", visual_slot, visual);

    let fake_offset = offsets.get("VisualEngine::FakeDataModel").copied().unwrap_or(0) as u64;
    let fake = read_u64_live(handle, visual + fake_offset).unwrap_or(0);
    push("VisualEngine -> FakeDataModel", visual + fake_offset, fake);

    let real_offset = offsets.get("FakeDataModel::RealDataModel").copied().unwrap_or(0) as u64;
    let datamodel = read_u64_live(handle, fake + real_offset).unwrap_or(0);
    push("FakeDataModel -> RealDataModel", fake + real_offset, datamodel);

    let fake_slot = base + slot("FakeDataModel::Pointer");
    let datamodel_direct = read_u64_live(handle, fake_slot).unwrap_or(0);
    push("FakeDataModel::Pointer", fake_slot, datamodel_direct);

    if datamodel != 0 {
        for (name, key, label) in [
            ("Workspace", "DataModel::Workspace", "DataModel -> Workspace"),
            ("ScriptContext", "DataModel::ScriptContext", "DataModel -> ScriptContext"),
        ] {
            let delta = offsets.get(key).copied().unwrap_or(0) as u64;
            let child = read_u64_live(handle, datamodel + delta).unwrap_or(0);
            push(label, datamodel + delta, child);
            let _ = name;
        }
    }

    Ok(hops)
}

/// Names and classes of an instance's direct children, in order.
pub fn children_of(
    pid: Option<u32>,
    module: &str,
    offsets: &HashMap<String, u64>,
    instance: u64,
    limit: usize,
) -> Result<Vec<(String, String, u64)>, String> {
    let pid = match pid {
        Some(pid) => pid,
        None => live::find_pid(crate::CLIENT_EXE)
            .ok_or_else(|| format!("{} is not running; pass --pid <n>", crate::CLIENT_EXE))?,
    };
    let _ = module;

    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "OpenProcess({pid}) with PROCESS_ALL_ACCESS failed ({}); elevation is required",
            unsafe { GetLastError() }
        ));
    }

    let listing = children(handle, instance, offsets, limit);
    unsafe { CloseHandle(handle) };
    Ok(listing)
}

/// Names and classes of the data model's direct children, in order.
pub fn children(
    handle: Handle,
    instance: u64,
    offsets: &HashMap<String, u64>,
    limit: usize,
) -> Vec<(String, String, u64)> {
    let children_offset = offsets.get("Instance::ChildrenStart").copied().unwrap_or(0) as u64;
    if instance == 0 || children_offset == 0 {
        return Vec::new();
    }

    let holder = read_u64_live(handle, instance + children_offset).unwrap_or(0);
    let begin = read_u64_live(handle, holder).unwrap_or(0);
    let end = read_u64_live(handle, holder + 8).unwrap_or(0);
    if begin == 0 || end <= begin {
        return Vec::new();
    }

    // `Children` is a vector of `shared_ptr<Instance>`: 8-byte pointer plus an
    // 8-byte control block, so entries sit 0x10 apart.
    const STRIDE: u64 = 0x10;
    let count = ((end - begin) / STRIDE).min(limit as u64);
    let mut out = Vec::new();
    for index in 0..count {
        let child = read_u64_live(handle, begin + index * STRIDE).unwrap_or(0);
        if child < 0x10000 {
            continue;
        }
        let (name, class) = describe(handle, child, offsets);
        out.push((name, class, child));
    }
    out
}

/// Flush, read and rejoin every page of a loaded module.
pub fn dump(
    pid: Option<u32>,
    module: &str,
    out: Option<PathBuf>,
    rebuild: bool,
) -> Result<Report, String> {
    let mut notes = Vec::new();

    match enable_debug_privilege() {
        Ok(true) => {}
        Ok(false) => {
            notes.push("SeDebugPrivilege was not granted — run from an elevated shell".into())
        }
        Err(because) => notes.push(format!("privilege: {because}")),
    }

    let pid = match pid {
        Some(pid) => pid,
        None => live::find_pid(crate::CLIENT_EXE)
            .ok_or_else(|| format!("{} is not running; pass --pid <n>", crate::CLIENT_EXE))?,
    };

    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "OpenProcess({pid}) with PROCESS_ALL_ACCESS failed ({}); elevation is required",
            unsafe { GetLastError() }
        ));
    }

    let result = dump_with(handle, pid, module, out, rebuild, notes);
    unsafe { CloseHandle(handle) };
    result
}

fn dump_with(
    handle: Handle,
    pid: u32,
    module: &str,
    out: Option<PathBuf>,
    rebuild: bool,
    mut notes: Vec<String>,
) -> Result<Report, String> {
    let (base, size, module_path) = live::module_info(pid, module)
        .ok_or_else(|| format!("module {module} is not loaded in pid {pid}"))?;

    let source = Path::new(&module_path);
    let mut image = std::fs::read(source)
        .map_err(|e| format!("cannot read {}: {e}", source.display()))?;
    let image_bytes = image.len() as u64;

    let parsed = PeImage::parse(image.clone())?;
    let sections = parsed.sections.clone();
    let base_of_code = parsed.base_of_code;
    let before = counts(&parsed);

    let mut stats = Vec::with_capacity(sections.len());
    let mut executable_flags = Vec::with_capacity(sections.len());
    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(sections.len());

    for section in &sections {
        let span = section.span() as u64;
        let start = base + section.virtual_address as u64;
        let mut block = seed_block(&image, section);

        let executable = runtime_executable(handle, start)
            .unwrap_or_else(|| section.has_execute_flag() || section.contains_rva(base_of_code));
        executable_flags.push(executable);

        let mut entry = SectionStats {
            name: section.name.clone(),
            span,
            flushed: 0,
            flush_errors: 0,
            first_flush_status: None,
            read: 0,
            unreadable: 0,
            first_read_error: None,
            denied_protect: Vec::new(),
            changed_bytes: 0,
            runtime_executable: executable,
        };

        // One wide flush before the per-page walk. The decryptor is reached
        // through the flush path, so it is worth asking for the whole section
        // in large strides as well as page by page.
        let mut wide = 0u64;
        while wide < span {
            let chunk = (span - wide).min(8 * 1024 * 1024);
            let status = flush_page(handle, start + wide, chunk as usize);
            if status < 0 {
                entry.flush_errors += 1;
                entry.first_flush_status.get_or_insert(status);
            }
            wide += chunk;
        }

        let mut rva = 0u64;
        while rva < span {
            let page = (span - rva).min(0x1000);
            let address = start + rva;

            let status = flush_page(handle, address, page as usize);
            if status >= 0 {
                entry.flushed += 1;
            } else {
                entry.flush_errors += 1;
                entry.first_flush_status.get_or_insert(status);
            }

            match read_page(handle, address, page as usize) {
                Ok(bytes) => {
                    entry.read += 1;

                    let length = (bytes.len() as u64).min(span - rva);
                    if length > 0 {
                        let live = &bytes[..length as usize];
                        let region = &mut block[rva as usize..(rva + length) as usize];
                        let differing = region.iter().zip(live).filter(|(a, b)| a != b).count();
                        if differing > 0 {
                            entry.changed_bytes += differing as u64;
                            region.copy_from_slice(live);
                        }
                    }
                }
                Err(error) => {
                    entry.unreadable += 1;
                    entry.first_read_error.get_or_insert(error);

                    if let Some((protect, state)) = protection(handle, address) {
                        let key = (protect & 0xFF) | (state << 16);
                        let existing = entry.denied_protect.iter().position(|(p, _)| *p == key);
                        match existing {
                            Some(index) => entry.denied_protect[index].1 += 1,
                            None if entry.denied_protect.len() < 6 => {
                                entry.denied_protect.push((key, 1))
                            }
                            None => {}
                        }
                    }
                }
            }

            rva += page;
        }

        stats.push(entry);
        blocks.push(block);
    }

    // Faithful image: only the file-backed bytes change, so the layout stays
    // exactly as shipped and any reader sees the same offsets.
    for (index, section) in sections.iter().enumerate() {
        let raw = (section.raw_size as u64).min(section.span() as u64);
        let offset = section.raw_pointer as u64;
        if raw == 0 || offset + raw > image.len() as u64 {
            continue;
        }
        image[offset as usize..(offset + raw) as usize]
            .copy_from_slice(&blocks[index][..raw as usize]);
    }

    let repaired = mark_code(&mut image, &sections, &executable_flags);
    if repaired > 0 {
        notes.push(format!("{repaired} section headers marked CODE|EXECUTE|READ"));
    }

    let output = out.unwrap_or_else(|| {
        let mut path = source.to_path_buf();
        let name = path
            .file_stem()
            .map(|n| format!("{}.dumped.exe", n.to_string_lossy()))
            .unwrap_or_else(|| "dumped.exe".into());
        path.set_file_name(name);
        path
    });

    std::fs::write(&output, &image)
        .map_err(|e| format!("cannot write {}: {e}", output.display()))?;

    let mut rebuilt_path = None;
    if rebuild {
        let rebuilt = rebuild_image(&image, &sections, &blocks)?;
        let mut path = output.clone();
        path.set_file_name(format!(
            "{}.rebuilt.exe",
            path.file_stem().map(|n| n.to_string_lossy()).unwrap_or_default()
        ));
        std::fs::write(&path, &rebuilt)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        notes.push(format!(
            "rebuilt layout written: every section's raw size now covers its virtual span"
        ));
        rebuilt_path = Some(path);
    }

    let dumped = PeImage::parse(image)?;
    let after = counts(&dumped);

    Ok(Report {
        pid,
        base,
        size,
        module_path,
        sections: stats,
        image_bytes,
        prologues_before: before,
        prologues_after: after,
        output_bytes: std::fs::metadata(&output).map(|m| m.len()).unwrap_or(0),
        output,
        rebuilt: rebuilt_path,
        notes,
    })
}
