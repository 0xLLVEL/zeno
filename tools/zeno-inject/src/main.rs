//! Loads `zeno-payload.dll` into the live client and waits for its thread.
//!
//! The injector only writes the DLL path and starts `LoadLibraryW`; everything
//! after that runs inside the target, where its own memory is ordinary memory.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::PathBuf;

mod map;

type Handle = *mut c_void;

const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;
const MEM_COMMIT_RESERVE: u32 = 0x0000_3000;
const PAGE_READWRITE: u32 = 0x04;
const INFINITE: u32 = 0xFFFF_FFFF;
const EXE: &str = "RobloxPlayerBeta.exe";
const SENTINEL: u64 = 0x5EED_0000_0000_0001;
const ENTERED: u64 = 0x5EED_0000_0000_0002;

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn VirtualAllocEx(handle: Handle, address: *mut c_void, size: usize, kind: u32, protect: u32)
        -> *mut c_void;
    fn VirtualFreeEx(handle: Handle, address: *mut c_void, size: usize, kind: u32) -> i32;
    fn WriteProcessMemory(
        handle: Handle,
        address: *mut c_void,
        buffer: *const c_void,
        size: usize,
        written: *mut usize,
    ) -> i32;
    fn CreateRemoteThread(
        handle: Handle,
        attributes: *mut c_void,
        stack: usize,
        start: *mut c_void,
        parameter: *mut c_void,
        flags: u32,
        id: *mut u32,
    ) -> Handle;
    fn WaitForSingleObject(handle: Handle, millis: u32) -> u32;
    fn TerminateThread(thread: Handle, code: u32) -> i32;
    fn ReadProcessMemory(
        handle: Handle,
        address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;
    fn GetExitCodeThread(handle: Handle, code: *mut u32) -> i32;
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn LoadLibraryW(name: *const u16) -> Handle;
    fn VirtualProtectEx(
        handle: Handle,
        address: *mut c_void,
        size: usize,
        protect: u32,
        previous: *mut u32,
    ) -> i32;
    fn GetLastError() -> u32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
}

#[repr(C)]
struct ThreadEntry32 {
    dw_size: u32,
    cnt_usage: u32,
    th32_thread_id: u32,
    th32_owner_process_id: u32,
    tp_base_pri: i32,
    tp_delta_pri: i32,
    dw_flags: u32,
}

#[repr(C)]
struct ModuleEntry32 {
    dw_size: u32,
    th32_module_id: u32,
    th32_process_id: u32,
    glblcnt_usage: u32,
    proccnt_usage: u32,
    _pad: u32,
    mod_base: *mut u8,
    mod_base_size: u32,
    _pad2: u32,
    h_module: *mut c_void,
    sz_module: [u8; 256],
    sz_exe_path: [u8; 260],
}

const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const TH32CS_SNAPMODULE: u32 = 0x0000_0008 | 0x0000_0010;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const CONTEXT_FULL: u32 = 0x0010_000B;
const CONTEXT_SIZE: usize = 0x4D0;
const CONTEXT_FLAGS_OFFSET: usize = 0x30;
const CONTEXT_RIP_OFFSET: usize = 0xF8;

#[link(name = "kernel32")]
extern "system" {
    fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn Module32FirstW(snapshot: Handle, entry: *mut ModuleEntry32) -> i32;
    fn Module32NextW(snapshot: Handle, entry: *mut ModuleEntry32) -> i32;
    fn OpenThread(access: u32, inherit: i32, id: u32) -> Handle;
    fn SuspendThread(thread: Handle) -> u32;
    fn ResumeThread(thread: Handle) -> u32;
    fn GetThreadContext(thread: Handle, context: *mut c_void) -> i32;
    fn SetThreadContext(thread: Handle, context: *const c_void) -> i32;
}

const PROCESS_QUERY_LIMITED: u32 = 0x1000;
const PROCESS_VM_READ: u32 = 0x0010;

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        handle: Handle,
        class: u32,
        info: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtCreateSection(
        section: *mut Handle,
        access: u32,
        attributes: *mut c_void,
        max_size: *mut i64,
        page_protect: u32,
        allocation: u32,
        file: Handle,
    ) -> i32;
    fn NtMapViewOfSection(
        section: Handle,
        process: Handle,
        base: *mut *mut c_void,
        zero_bits: usize,
        commit: usize,
        offset: *mut i64,
        size: *mut usize,
        inherit: u32,
        allocation: u32,
        protect: u32,
    ) -> i32;
    fn NtClose(handle: Handle) -> i32;
    fn NtUnmapViewOfSection(process: Handle, base: *mut c_void) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        attributes: *mut c_void,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn VirtualQueryEx(
        process: Handle,
        address: *const c_void,
        buffer: *mut c_void,
        length: usize,
    ) -> usize;
}

struct Module {
    name: String,
    base: u64,
    size: u64,
}

fn modules_of(pid: u32) -> Vec<Module> {
    // Toolhelp is refused for this process, so the loader list is read straight
    // out of the target's PEB: PEB -> Ldr -> InMemoryOrderModuleList.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED | PROCESS_VM_READ, 0, pid) };
    if handle.is_null() {
        return Vec::new();
    }
    let mut info = [0u8; 0x30];
    let mut returned = 0u32;
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            0,
            info.as_mut_ptr() as *mut c_void,
            info.len() as u32,
            &mut returned,
        )
    };
    if status < 0 {
        unsafe { CloseHandle(handle) };
        return Vec::new();
    }
    let peb = u64::from_le_bytes(info[8..16].try_into().unwrap());
    let ldr = read_u64(handle, peb + 0x18);
    if ldr == 0 {
        unsafe { CloseHandle(handle) };
        return Vec::new();
    }

    let mut out = Vec::new();
    let list_head = ldr + 0x20;
    let mut link = read_u64(handle, list_head);
    for _ in 0..256 {
        if link == 0 || link == list_head {
            break;
        }
        let entry = link.wrapping_sub(0x10);
        let base = read_u64(handle, entry + 0x30);
        // SizeOfImage is a ULONG at +0x40; +0x38 is EntryPoint.
        let size = read_u64(handle, entry + 0x40) & 0xFFFF_FFFF;
        let name_len = read_u64(handle, entry + 0x58) & 0xFFFF;
        let name_ptr = read_u64(handle, entry + 0x60);
        let mut name = String::new();
        if name_len > 0 && name_len < 0x200 && name_ptr != 0 {
            let mut raw = vec![0u8; name_len as usize];
            let mut got = 0usize;
            let ok = unsafe {
                ReadProcessMemory(
                    handle,
                    name_ptr as *const c_void,
                    raw.as_mut_ptr() as *mut c_void,
                    raw.len(),
                    &mut got,
                )
            };
            if ok != 0 {
                let units: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect();
                name = String::from_utf16_lossy(&units).to_lowercase();
            }
        }
        if base != 0 && size != 0 {
            // The loader entry for this client reports a base that is a few
            // allocation granules below where the PE header actually sits, so
            // trust the header, not the arithmetic.
            let mut image = base;
            if read_u16_at(handle, image) != Some(0x5A4D) {
                for step in 1..16u64 {
                    let candidate = base + step * 0x10000;
                    if read_u16_at(handle, candidate) == Some(0x5A4D) {
                        image = candidate;
                        break;
                    }
                }
            }
            out.push(Module {
                name,
                base: image,
                size,
            });
        }
        link = read_u64(handle, link);
    }
    unsafe { CloseHandle(handle) };
    out
}

/// Where a thread is parked. A thread that is sitting inside a wait is the
/// safest thing to hijack: it holds no Roblox allocator lock, so the payload
/// can call `malloc` without deadlocking the client. Threads caught inside the
/// game module are the opposite and are tried last.
fn thread_rip(handle: Handle, id: u32) -> Option<u64> {
    let thread = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, id) };
    if thread.is_null() {
        return None;
    }
    unsafe { SuspendThread(thread) };
    let mut context = vec![0u8; CONTEXT_SIZE];
    unsafe { *(context.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL };
    let ok = unsafe { GetThreadContext(thread, context.as_mut_ptr() as *mut c_void) } != 0;
    unsafe {
        ResumeThread(thread);
        CloseHandle(thread);
    }
    if !ok {
        return None;
    }
    Some(unsafe { *(context.as_ptr().add(CONTEXT_RIP_OFFSET) as *const u64) })
}

fn hijack_rank(rip: u64, modules: &[Module]) -> u8 {
    for module in modules {
        if rip >= module.base && rip < module.base + module.size {
            if module.name.ends_with(".exe") {
                return 2;
            }
            if module.name.starts_with("ntdll")
                || module.name.starts_with("kernelbase")
                || module.name.starts_with("win32u")
                || module.name.starts_with("user32")
                || module.name.starts_with("kernel32")
                || module.name.starts_with("msvcrt")
                || module.name.starts_with("ucrtbase")
            {
                return 0;
            }
            return 1;
        }
    }
    1
}

fn threads_of(pid: u32) -> Vec<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot.is_null() || snapshot == -1isize as Handle {
        return Vec::new();
    }
    let mut entry: ThreadEntry32 = unsafe { std::mem::zeroed() };
    entry.dw_size = std::mem::size_of::<ThreadEntry32>() as u32;

    let mut out = Vec::new();
    let mut ok = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    while ok {
        if entry.th32_owner_process_id == pid {
            out.push(entry.th32_thread_id);
        }
        ok = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };
    out
}

fn read_u64(handle: Handle, address: u64) -> u64 {
    read_u64_checked(handle, address).unwrap_or(0)
}

/// Distinguishes "the value is zero" from "the process is gone".
fn read_u64_checked(handle: Handle, address: u64) -> Option<u64> {
    let mut value = 0u64;
    let mut got = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            &mut value as *mut u64 as *mut c_void,
            8,
            &mut got,
        )
    };
    if ok != 0 && got == 8 {
        Some(value)
    } else {
        None
    }
}

/// Point a suspended thread at `stub`, wait for it to publish a result at
/// `marker`, then put the thread back exactly where it was.
fn run_stub(
    handle: Handle,
    threads: &[u32],
    modules: &[Module],
    stub: u64,
    marker: u64,
) -> Option<(u32, u64)> {
    let mut ordered: Vec<(u8, u32)> = threads
        .iter()
        .take(64)
        .map(|id| (thread_rip(handle, *id).map(|rip| hijack_rank(rip, modules)).unwrap_or(3), *id))
        .collect();
    ordered.sort_by_key(|entry| entry.0);
    let parked: Vec<u32> = ordered
        .iter()
        .filter(|entry| entry.0 <= 1)
        .map(|entry| entry.1)
        .collect();
    let ranked: Vec<u32> = if parked.len() >= 3 {
        parked
    } else {
        ordered.into_iter().map(|entry| entry.1).collect()
    };

    let mut stuck = 0usize;
    for id in ranked.iter().take(24) {
        let thread = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, *id) };
        if thread.is_null() {
            continue;
        }
        unsafe { SuspendThread(thread) };

        let mut original = vec![0u8; CONTEXT_SIZE];
        unsafe {
            *(original.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL;
        }
        if unsafe { GetThreadContext(thread, original.as_mut_ptr() as *mut c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            }
            continue;
        }

        let mut patched = original.clone();
        unsafe { *(patched.as_mut_ptr().add(0xF8) as *mut u64) = stub };
        if unsafe { SetThreadContext(thread, patched.as_ptr() as *const c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            }
            continue;
        }
        unsafe { ResumeThread(thread) };

        let mut value = 0u64;
        let mut alive = true;
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            match read_u64_checked(handle, marker) {
                Some(seen) => value = seen,
                None => {
                    alive = false;
                    break;
                }
            }
            if value != 0 && value != SENTINEL && value != ENTERED {
                break;
            }
        }

        if !alive {
            println!("hijack      thread {id}: the process died while the payload ran");
            return None;
        }

        unsafe {
            SuspendThread(thread);
            SetThreadContext(thread, original.as_ptr() as *const c_void);
            ResumeThread(thread);
            CloseHandle(thread);
        }

        if value != 0 && value != SENTINEL && value != ENTERED {
            return Some((*id, value));
        }
        if value == SENTINEL {
            println!("hijack      thread {id} never reached the stub");
        } else if value == ENTERED {
            println!("hijack      thread {id} entered the payload and never came back");
            stuck += 1;
            if stuck >= 2 {
                println!("hijack      payload is stuck; stopping after {stuck} threads");
                break;
            }
        } else {
            println!("hijack      thread {id} ran the stub, result 0");
        }
    }
    None
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateThreadEx(
        thread: *mut Handle,
        access: u32,
        attributes: *mut c_void,
        process: Handle,
        start: *mut c_void,
        parameter: *mut c_void,
        flags: u32,
        zero_bits: usize,
        stack_size: usize,
        max_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> i32;
}

#[link(name = "user32")]
extern "system" {
    fn EnumWindows(callback: extern "system" fn(Handle, isize) -> i32, param: isize) -> i32;
    fn GetWindowThreadProcessId(window: Handle, pid: *mut u32) -> u32;
    fn SetWindowsHookExW(id: i32, proc: *const c_void, module: Handle, thread: u32) -> Handle;
    fn UnhookWindowsHookEx(hook: Handle) -> i32;
}

const WH_CALLWNDPROC: i32 = 4;

struct FindThread {
    wanted: u32,
    thread: u32,
}

extern "system" fn window_callback(window: Handle, param: isize) -> i32 {
    let state = unsafe { &mut *(param as *mut FindThread) };
    let mut pid = 0u32;
    let thread = unsafe { GetWindowThreadProcessId(window, &mut pid) };
    if pid == state.wanted && thread != 0 {
        state.thread = thread;
        return 0;
    }
    1
}

fn ui_thread(pid: u32) -> Option<u32> {
    let mut state = FindThread {
        wanted: pid,
        thread: 0,
    };
    unsafe { EnumWindows(window_callback, &mut state as *mut FindThread as isize) };
    if state.thread == 0 {
        None
    } else {
        Some(state.thread)
    }
}

#[repr(C)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn find_pid(name: &str) -> Option<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() || snapshot == -1isize as Handle {
        return None;
    }
    let mut entry: ProcessEntry32W = unsafe { std::mem::zeroed() };
    entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;

    let mut found = None;
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while ok {
        let end = entry
            .sz_exe_file
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(entry.sz_exe_file.len());
        let exe = String::from_utf16_lossy(&entry.sz_exe_file[..end]);
        if exe.eq_ignore_ascii_case(name) {
            found = Some(entry.th32_process_id);
        }
        ok = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };
    found
}

fn write_config(pack: &PathBuf, dir: &PathBuf) -> Result<usize, String> {
    let text =
        std::fs::read_to_string(pack).map_err(|e| format!("cannot read {}: {e}", pack.display()))?;

    let mut lines: Vec<String> = Vec::new();
    let mut scope: Vec<String> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("namespace ") {
            if let Some(name) = rest.split_whitespace().next() {
                scope.push(name.to_string());
            }
            continue;
        }
        if line.starts_with('}') {
            for _ in 0..line.matches('}').count() {
                scope.pop();
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("inline constexpr uintptr_t ") {
            let Some((name, value)) = rest.split_once('=') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim().trim_end_matches(';').trim();
            if value.starts_with("0x") || value.starts_with("0X") {
                if let Some(namespace) = scope.last() {
                    lines.push(format!("{namespace}::{name}={value}"));
                }
            }
        }
    }

    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    std::fs::write(dir.join("offsets.txt"), lines.join("\n"))
        .map_err(|e| format!("cannot write config: {e}"))?;
    Ok(lines.len())
}

/// Points a parked thread's RIP at `kernel32!Sleep` and lets it sit there.
///
/// Nothing private runs, so this separates "this client tolerates a thread
/// context rewrite at all" from "this client tolerates code in a private page".
fn context_test(pid: u32) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let list = threads_of(pid);
    let modules = modules_of(pid);
    println!("target      pid {pid}, {} threads, {} modules", list.len(), modules.len());

    let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
    let sleep_fn = unsafe { GetProcAddress(kernel32, b"Sleep\0".as_ptr()) } as u64;
    if sleep_fn == 0 {
        unsafe { CloseHandle(handle) };
        return Err("kernel32!Sleep not found".into());
    }

    let mut ordered: Vec<(u8, u32)> = list
        .iter()
        .take(64)
        .map(|id| {
            (
                thread_rip(handle, *id)
                    .map(|rip| hijack_rank(rip, &modules))
                    .unwrap_or(3),
                *id,
            )
        })
        .collect();
    ordered.sort_by_key(|entry| entry.0);

    let mut tried = 0;
    for (rank, id) in ordered.iter() {
        if *rank > 2 || tried >= 3 {
            break;
        }
        tried += 1;
        let thread = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, *id) };
        if thread.is_null() {
            continue;
        }
        unsafe { SuspendThread(thread) };
        let mut original = vec![0u8; CONTEXT_SIZE];
        unsafe {
            *(original.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL;
        }
        if unsafe { GetThreadContext(thread, original.as_mut_ptr() as *mut c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            }
            continue;
        }

        let mut patched = original.clone();
        unsafe {
            *(patched.as_mut_ptr().add(0xF8) as *mut u64) = sleep_fn;
            *(patched.as_mut_ptr().add(0x80) as *mut u64) = 0x7FFF_FFFF;
        }
        if unsafe { SetThreadContext(thread, patched.as_ptr() as *const c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            }
            continue;
        }
        unsafe { ResumeThread(thread) };

        std::thread::sleep(std::time::Duration::from_secs(3));
        let alive = unsafe { WaitForSingleObject(handle, 0) } != 0;
        println!(
            "ctxtest     thread {id} (rank {rank}) redirected to kernel32!Sleep: client {}",
            if alive { "alive" } else { "DIED" }
        );
        if !alive {
            unsafe { CloseHandle(handle) };
            return Ok(());
        }

        unsafe {
            SuspendThread(thread);
            SetThreadContext(thread, original.as_ptr() as *const c_void);
            ResumeThread(thread);
            CloseHandle(thread);
        }
    }

    println!("ctxtest     contexts restored, watching");
    for step in 1..=12 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let alive = unsafe { WaitForSingleObject(handle, 0) } != 0;
        println!(
            "ctxtest     t+{}s client {}",
            step * 5,
            if alive { "alive" } else { "DIED" }
        );
        if !alive {
            break;
        }
    }

    unsafe { CloseHandle(handle) };
    Ok(())
}

/// Hijacks a parked thread straight into `kernel32!LoadLibraryW` — no stub, no
/// private code executed. `rcx` gets the DLL path from a plain RW page and
/// `rsp` points at a fake frame whose return address is `kernel32!SleepEx`, so
/// the thread parks itself instead of returning into whatever it was doing.
fn lib_test(pid: u32, dll: &std::path::Path) -> Result<(), String> {
    let absolute = std::fs::canonicalize(dll).map_err(|e| format!("{}: {e}", dll.display()))?;
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let list = threads_of(pid);
    let modules = modules_of(pid);
    println!("target      pid {pid}, {} threads, {} modules", list.len(), modules.len());

    let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
    let load = unsafe { GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr()) } as u64;
    let park = unsafe { GetProcAddress(kernel32, b"SleepEx\0".as_ptr()) } as u64;
    if load == 0 || park == 0 {
        unsafe { CloseHandle(handle) };
        return Err("kernel32 exports missing".into());
    }

    // One plain data page: path string at +0, fake stack (16-aligned) at +0x1000.
    let block = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x2000, MEM_COMMIT_RESERVE, 0x04)
    };
    if block.is_null() {
        unsafe { CloseHandle(handle) };
        return Err(format!("VirtualAllocEx failed ({})", unsafe { GetLastError() }));
    }
    let block_address = block as u64;
    let path = wide(&absolute.to_string_lossy());
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(
            handle,
            block_address as *mut c_void,
            path.as_ptr() as *const c_void,
            path.len() * 2,
            &mut written,
        )
    };
    // rsp % 16 == 8 at function entry means the callee sees a normal frame.
    let stack_top = block_address + 0x2000 - 0x10;
    unsafe {
        WriteProcessMemory(
            handle,
            (stack_top - 8) as *mut c_void,
            &park as *const u64 as *const c_void,
            8,
            &mut written,
        )
    };
    println!(
        "libtest     path 0x{block_address:X} stack 0x{stack_top:X} LoadLibraryW 0x{load:X} park 0x{park:X}"
    );

    let mut ordered: Vec<(u8, u32)> = list
        .iter()
        .take(64)
        .map(|id| {
            (
                thread_rip(handle, *id)
                    .map(|rip| hijack_rank(rip, &modules))
                    .unwrap_or(3),
                *id,
            )
        })
        .collect();
    ordered.sort_by_key(|entry| entry.0);

    let mut tried = 0;
    for (rank, id) in ordered.iter() {
        if *rank > 2 || tried >= 3 {
            break;
        }
        tried += 1;
        let thread = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, *id) };
        if thread.is_null() {
            continue;
        }
        unsafe { SuspendThread(thread) };
        let mut original = vec![0u8; CONTEXT_SIZE];
        unsafe {
            *(original.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL;
        }
        if unsafe { GetThreadContext(thread, original.as_mut_ptr() as *mut c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            }
            continue;
        }
        let mut patched = original.clone();
        unsafe {
            *(patched.as_mut_ptr().add(0xF8) as *mut u64) = load; // Rip
            *(patched.as_mut_ptr().add(0x80) as *mut u64) = block_address; // Rcx = path
            *(patched.as_mut_ptr().add(0x98) as *mut u64) = stack_top - 8; // Rsp
        }
        if unsafe { SetThreadContext(thread, patched.as_ptr() as *const c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            }
            continue;
        }
        unsafe { ResumeThread(thread) };
        println!("libtest     thread {id} (rank {rank}) sent into LoadLibraryW");

        let mut settled = modules.len();
        for step in 0..10 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let after = modules_of(pid);
            if after.len() != settled {
                println!("libtest     t+{step}s modules {settled} -> {}", after.len());
                settled = after.len();
            }
            if unsafe { WaitForSingleObject(handle, 0) } == 0 {
                println!("libtest     t+{step}s client DIED");
                unsafe { CloseHandle(thread) };
                unsafe { CloseHandle(handle) };
                return Ok(());
            }
        }

        let mut now = vec![0u8; CONTEXT_SIZE];
        unsafe {
            *(now.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL;
        }
        let alive = unsafe { WaitForSingleObject(handle, 0) } != 0;
        let after = modules_of(pid);
        println!(
            "libtest     client {}, modules {} -> {}",
            if alive { "alive" } else { "DIED" },
            modules.len(),
            after.len()
        );
        if unsafe { GetThreadContext(thread, now.as_mut_ptr() as *mut c_void) } != 0 {
            let rip = unsafe { *(now.as_ptr().add(0xF8) as *const u64) };
            let rcx = unsafe { *(now.as_ptr().add(0x80) as *const u64) };
            let parked = modules.iter().any(|m| {
                rip >= m.base && rip < m.base + 0x800_0000
            });
            println!("libtest     thread now rip=0x{rip:X} rcx=0x{rcx:X} in-module={parked}");
        }
        for module in &after {
            if module.name.to_lowercase().contains("zeno") {
                println!("libtest     loaded {} at 0x{:X}", module.name, module.base);
            }
        }
        unsafe { CloseHandle(thread) };
        if !alive {
            break;
        }
    }

    unsafe { CloseHandle(handle) };
    Ok(())
}

/// Maps the payload as a real image section (`SEC_IMAGE`) with no loader
/// involvement, then jumps a parked thread into its `zeno_ping` export.
///
/// `LoadLibraryW` answers with NULL for this DLL — the client logs it as
/// `[DFLog::ClientBlockedImage] Blocked DLL` — so the loader path is closed.
/// This asks the next question: does the client tolerate executing from a
/// memory-mapped image that is absent from the PEB module list?
/// Splices a `LDR_DATA_TABLE_ENTRY` for the mapped view into the loader's
/// three module lists (load order, memory order, init order).
///
/// The client maps the view itself, never calls the loader, and therefore the
/// view is invisible to `LdrEnumerateLoadedModules` while still being a real
/// `MEM_IMAGE` at a real image address. That gap is what gets found: the
/// mapping-only run died at t+30s with no code executed at all, so detection
/// is scanning for exactly this discrepancy.
fn link_module(
    handle: Handle,
    base: u64,
    image_size: u32,
    entry_point: u32,
    dll_path: &str,
) -> Result<(), String> {
    const PROCESS_BASIC_INFORMATION: u32 = 0;
    let mut info = [0u8; 0x30];
    let mut returned = 0u32;
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_BASIC_INFORMATION,
            info.as_mut_ptr() as *mut c_void,
            0x30,
            &mut returned,
        )
    };
    if status != 0 {
        return Err(format!("NtQueryInformationProcess failed 0x{:X}", status as u32));
    }
    let peb = u64::from_le_bytes(info[8..16].try_into().unwrap());
    if peb == 0 {
        return Err("PEB address is zero".into());
    }
    let ldr = read_u64_checked(handle, peb + 0x18).ok_or("cannot read PEB->Ldr")?;
    if ldr == 0 {
        return Err("PEB->Ldr is zero".into());
    }

    let entry = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x200, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    };
    if entry.is_null() {
        return Err("VirtualAllocEx for LDR entry failed".into());
    }
    let strings = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x800, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    };
    if strings.is_null() {
        return Err("VirtualAllocEx for module names failed".into());
    }

    let full: Vec<u16> = dll_path.encode_utf16().collect();
    let base_name: Vec<u16> = dll_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(dll_path)
        .encode_utf16()
        .collect();

    let write = |address: u64, bytes: &[u8]| -> bool {
        let mut written = 0usize;
        unsafe {
            WriteProcessMemory(
                handle,
                address as *mut c_void,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                &mut written,
            ) == 1
                && written == bytes.len()
        }
    };

    // UNICODE_STRING: Length, MaximumLength, padding, Buffer.
    let build_string = |address: u64, buffer: u64, units: &[u16]| {
        let mut raw = [0u8; 16];
        let bytes = units.len() * 2;
        raw[0..2].copy_from_slice(&(bytes as u16).to_le_bytes());
        raw[2..4].copy_from_slice(&(bytes as u16).to_le_bytes());
        raw[8..16].copy_from_slice(&buffer.to_le_bytes());
        write(address, &raw);
        write(buffer, &units.iter().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>())
    };

    let names = strings as u64;
    build_string(names, names + 0x400, &full);
    build_string(names + 0x200, names + 0x600, &base_name);

    let mut block = [0u8; 0xA0];
    block[0x30..0x38].copy_from_slice(&base.to_le_bytes()); // DllBase
    block[0x38..0x40].copy_from_slice(&(base + entry_point as u64).to_le_bytes());
    block[0x40..0x44].copy_from_slice(&image_size.to_le_bytes());
    block[0x48..0x50].copy_from_slice(&(names as u64).to_le_bytes()); // FullDllName
    block[0x58..0x60].copy_from_slice(&((names + 0x200) as u64).to_le_bytes()); // BaseDllName
    // Flags: in-memory, image, loader-owned, entry processed.
    block[0x68..0x6C].copy_from_slice(&0x0008_5040u32.to_le_bytes());
    block[0x6C..0x6E].copy_from_slice(&1u16.to_le_bytes()); // LoadCount
    if !write(entry as u64, &block) {
        return Err("WriteProcessMemory for LDR entry failed".into());
    }

    let entry_address = entry as u64;
    let mut linked = 0;
    for (link_offset, head_offset) in [(0x00usize, 0x10u64), (0x10, 0x20), (0x20, 0x30)] {
        let head = ldr + head_offset;
        let Some(first) = read_u64_checked(handle, head) else {
            continue;
        };
        if first == 0 {
            continue;
        }
        let node = entry_address + link_offset as u64;
        if !write(node, &first.to_le_bytes())
            || !write(node + 8, &head.to_le_bytes())
            || !write(first + 8, &node.to_le_bytes())
            || !write(head, &node.to_le_bytes())
        {
            return Err(format!("splicing list at +0x{head_offset:X} failed"));
        }
        linked += 1;
    }
    if linked == 0 {
        return Err("no loader list accepted the entry".into());
    }
    println!("imagetest   linked into {linked} loader lists, entry at 0x{entry_address:X}");
    Ok(())
}

/// What the image test should do with the mapped view.
#[derive(Clone, Copy, Default)]
struct ImageOpts {
    /// Resolve and patch the IAT from this process.
    load: bool,
    /// Hijack a thread into the payload. Without it the view is only mapped.
    exec: bool,
    /// Splice an `LDR_DATA_TABLE_ENTRY` into the loader lists.
    link: bool,
    /// Unmap the view once the call returns, before the next scan can see it.
    unmap: bool,
}

/// Does nothing but name what it did, then watch the process for a minute.
///
/// Every injection shape tried so far has ended the client, and they all share
/// three syscalls: `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`. The
/// mapping-only run proves the mapped view is not what dies at t+30s — it dies
/// without a byte of it ever running. This isolates which syscall the client
/// objects to.
fn touch_test(pid: u32, alloc: bool, write: bool, execute: bool) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let mut notes = String::from("open");
    let mut block = std::ptr::null_mut();

    if alloc {
        block = unsafe {
            VirtualAllocEx(handle, std::ptr::null_mut(), 0x1000, MEM_COMMIT_RESERVE, 0x04)
        };
        if block.is_null() {
            unsafe { CloseHandle(handle) };
            return Err(format!("VirtualAllocEx failed ({})", unsafe { GetLastError() }));
        }
        notes.push_str(&format!(" alloc 0x{:X}", block as u64));
    }

    if write {
        if alloc {
            let mut written = 0usize;
            let ok = unsafe {
                WriteProcessMemory(
                    handle,
                    block,
                    &0x5EED_5EEDu64 as *const u64 as *const c_void,
                    8,
                    &mut written,
                )
            };
            notes.push_str(&format!(" write {ok} at 0x{:X}", block as u64));
        } else {
            // Nothing allocated: a read is the only safe probe.
            let peb = read_u64_checked(handle, 0x7FFF_FFFF_FFFF).unwrap_or(0);
            notes.push_str(&format!(" read-probe {peb:X}"));
        }
    }

    if execute && alloc {
        let mut old = 0u32;
        let ok = unsafe { VirtualProtectEx(handle, block, 0x1000, 0x40, &mut old) };
        notes.push_str(&format!(" protect-rwx {ok} (was 0x{old:X})"));
    }

    println!("touch       {notes}");

    for step in 1..=12 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let alive = unsafe { WaitForSingleObject(handle, 0) } != 0;
        println!(
            "touch       t+{}s client {}",
            step * 5,
            if alive { "alive" } else { "DIED" }
        );
        if !alive {
            break;
        }
    }
    unsafe { CloseHandle(handle) };
    Ok(())
}

/// Hijacks one thread into `target(arg)` and leaves it parked in `SleepEx`.
///
/// Returns the thread's original context so the caller can put it back; a
/// thread left at a foreign RIP is an anomaly the client can see.
struct Parked {
    id: u32,
    context: Vec<u8>,
}

fn hijack(
    handle: Handle,
    pid: u32,
    modules: &[Module],
    target: u64,
    arg: u64,
    stack_top: u64,
    park: u64,
) -> Option<Parked> {
    let mut ordered: Vec<(u8, u32)> = threads_of(pid)
        .into_iter()
        .take(64)
        .map(|id| {
            (
                thread_rip(handle, id)
                    .map(|rip| hijack_rank(rip, modules))
                    .unwrap_or(3),
                id,
            )
        })
        .collect();
    ordered.sort_by_key(|entry| entry.0);

    for (rank, id) in ordered {
        if rank > 2 {
            break;
        }
        let thread = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, id) };
        if thread.is_null() {
            continue;
        }
        unsafe { SuspendThread(thread) };
        let mut original = vec![0u8; CONTEXT_SIZE];
        unsafe {
            *(original.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL;
        }
        if unsafe { GetThreadContext(thread, original.as_mut_ptr() as *mut c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            }
            continue;
        }
        let mut patched = original.clone();
        unsafe {
            *(patched.as_mut_ptr().add(0xF8) as *mut u64) = target;
            *(patched.as_mut_ptr().add(0x98) as *mut u64) = stack_top;
            // Win64 ABI: first argument is RCX (0x80), second RDX (0x88). RAX
            // carries nothing on entry.
            *(patched.as_mut_ptr().add(0x80) as *mut u64) = arg;
            *(patched.as_mut_ptr().add(0x88) as *mut u64) = 0;
        }
        if unsafe { SetThreadContext(thread, patched.as_ptr() as *const c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            }
            continue;
        }
        unsafe { ResumeThread(thread) };
        unsafe { CloseHandle(thread) };
        let _ = park;
        return Some(Parked { id, context: original });
    }
    None
}

fn unpark(handle: Handle, parked: &Parked) {
    let thread = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, parked.id) };
    if thread.is_null() {
        return;
    }
    unsafe {
        SuspendThread(thread);
        SetThreadContext(thread, parked.context.as_ptr() as *const c_void);
        ResumeThread(thread);
        CloseHandle(thread);
    }
}

fn threads_of_unchecked(_handle: Handle) -> Vec<u32> {
    Vec::new()
}


/// Maps the payload over a registered module's image instead of creating a new
/// section.
///
/// Every unregistered `SEC_IMAGE` view has been killed — mapping alone, no code
/// run, payload or signed Microsoft DLL alike — while `OpenProcess`,
/// `VirtualAllocEx` and `WriteProcessMemory` all survive a full minute. So the
/// check is "image view that no loader entry points at", and the only way past
/// it is to live inside a module the loader already knows.
fn hollow_test(
    pid: u32,
    payload: &std::path::Path,
    carrier: Option<&str>,
    use_existing: bool,
) -> Result<(), String> {
    let file = std::fs::read(payload).map_err(|e| format!("{}: {e}", payload.display()))?;
    let image_size = map::image_size(&file)?;
    let ping_rva = map::export_rva(&file, "zeno_ping").ok_or("zeno_ping export missing")?;
    println!("hollow      payload {image_size} bytes, ping rva 0x{ping_rva:X}");

    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }

    let stack = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x8000, MEM_COMMIT_RESERVE, 0x04)
    };
    if stack.is_null() {
        unsafe { CloseHandle(handle) };
        return Err("stack allocation failed".into());
    }
    let stack_top = stack as u64 + 0x8000 - 0x10;
    let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
    let park = unsafe { GetProcAddress(kernel32, b"SleepEx\0".as_ptr()) } as u64;
    let load_library = unsafe { GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr()) } as u64;
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(
            handle,
            (stack_top - 8) as *mut c_void,
            &park as *const u64 as *const c_void,
            8,
            &mut written,
        )
    };

    let candidates: Vec<String> = match carrier {
        Some(name) => vec![name.to_string()],
        None => [
            r"C:\Windows\System32\NaturalLanguage6.dll",
            r"C:\Windows\System32\msmpeg2vdec.dll",
            r"C:\Windows\System32\wmvdspa.dll",
            r"C:\Windows\System32\mfc42.dll",
            r"C:\Windows\System32\mscms.dll",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
    };

    let mut chosen: Option<(String, u64, u64)> = None;
    for candidate in candidates {
        let short = candidate.rsplit('\\').next().unwrap_or(&candidate).to_string();
        let before = modules_of(pid);
        let present = before.iter().find(|module| module.name.eq_ignore_ascii_case(&short));
        if present.is_some() && !use_existing {
            // Already in the process: something else owns it and hollowing it
            // out would break a live consumer.
            println!("hollow      {short} already loaded, skipping");
            continue;
        }
        if present.is_none() {
            let text = wide(&candidate);
            let buffer = unsafe {
                VirtualAllocEx(
                    handle,
                    std::ptr::null_mut(),
                    text.len() * 2 + 0x10,
                    MEM_COMMIT_RESERVE,
                    0x04,
                )
            };
            if buffer.is_null() {
                continue;
            }
            unsafe {
                WriteProcessMemory(
                    handle,
                    buffer,
                    text.as_ptr() as *const c_void,
                    text.len() * 2,
                    &mut written,
                )
            };
            let Some(parked) = hijack(handle, pid, &before, load_library, buffer as u64, stack_top - 8, park)
            else {
                continue;
            };
            std::thread::sleep(std::time::Duration::from_millis(3000));
            unpark(handle, &parked);
            println!("hollow      asked for {short}");
        }

        let after = modules_of(pid);
        if let Some(module) = after.iter().find(|m| m.name.eq_ignore_ascii_case(&short)) {
            println!(
                "hollow      carrier {short} base 0x{:X} size 0x{:X}",
                module.base, module.size
            );
            if module.size >= image_size as u64 {
                chosen = Some((short, module.base, module.size));
                break;
            }
            println!("hollow      too small for the payload, next");
        }
    }

    let Some((name, base, size)) = chosen else {
        unsafe { CloseHandle(handle) };
        return Err("no carrier large enough".into());
    };
    println!("hollow      hollowing {name} at 0x{base:X}");

    let prepared = map::prepare(&file, base)?;
    let mut old = 0u32;
    unsafe { VirtualProtectEx(handle, base as *mut c_void, image_size as usize, 0x40, &mut old) };
    let ok = unsafe {
        WriteProcessMemory(
            handle,
            base as *mut c_void,
            prepared.image.as_ptr() as *const c_void,
            prepared.image.len(),
            &mut written,
        )
    };
    println!(
        "hollow      wrote {written}/{} bytes (ok {ok}), region 0x{size:X}",
        prepared.image.len()
    );
    if ok == 0 {
        unsafe { CloseHandle(handle) };
        return Err("hollow write failed".into());
    }

    let modules = modules_of(pid);
    let parked = hijack(handle, pid, &modules, base + ping_rva as u64, base, stack_top - 8, park);
    let Some(parked) = parked else {
        unsafe { CloseHandle(handle) };
        return Err("no thread available for the call".into());
    };
    std::thread::sleep(std::time::Duration::from_millis(800));
    unpark(handle, &parked);
    println!("hollow      zeno_ping called, thread restored");

    for step in 1..=12 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let alive = unsafe { WaitForSingleObject(handle, 0) } != 0;
        println!(
            "hollow      t+{}s client {}",
            step * 5,
            if alive { "alive" } else { "DIED" }
        );
        if !alive {
            break;
        }
    }

    unsafe { CloseHandle(handle) };
    Ok(())
}

/// Loads one signed DLL through `LoadLibraryW` and then only watches.
///
/// Every test so far that ended the client also added something to the module
/// list. This is the one variable left: does a module the loader *did* create
/// survive the client's own scan?
fn load_watch(pid: u32, library: &str) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let modules = modules_of(pid);
    let stack = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x8000, MEM_COMMIT_RESERVE, 0x04)
    };
    if stack.is_null() {
        unsafe { CloseHandle(handle) };
        return Err("stack allocation failed".into());
    }
    let stack_top = stack as u64 + 0x8000 - 0x10;
    let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
    let park = unsafe { GetProcAddress(kernel32, b"SleepEx\0".as_ptr()) } as u64;
    let load_library = unsafe { GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr()) } as u64;

    let text = wide(library);
    let mut written = 0usize;
    let buffer = unsafe {
        VirtualAllocEx(
            handle,
            std::ptr::null_mut(),
            text.len() * 2 + 0x10,
            MEM_COMMIT_RESERVE,
            0x04,
        )
    };
    if buffer.is_null() {
        unsafe { CloseHandle(handle) };
        return Err("path allocation failed".into());
    }
    unsafe {
        WriteProcessMemory(
            handle,
            buffer,
            text.as_ptr() as *const c_void,
            text.len() * 2,
            &mut written,
        );
        WriteProcessMemory(
            handle,
            (stack_top - 8) as *mut c_void,
            &park as *const u64 as *const c_void,
            8,
            &mut written,
        );
    }

    let short = library.rsplit('\\').next().unwrap_or(library);
    let Some(parked) = hijack(handle, pid, &modules, load_library, buffer as u64, stack_top - 8, park)
    else {
        unsafe { CloseHandle(handle) };
        return Err("no thread available".into());
    };
    std::thread::sleep(std::time::Duration::from_millis(3000));
    unpark(handle, &parked);

    let after = modules_of(pid);
    let hit = after.iter().find(|m| m.name.eq_ignore_ascii_case(short));
    println!(
        "loadwatch   modules {} -> {}, {}",
        modules.len(),
        after.len(),
        match hit {
            Some(m) => format!("{short} base 0x{:X} size 0x{:X}", m.base, m.size),
            None => format!("{short} absent"),
        }
    );

    for step in 1..=12 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let alive = unsafe { WaitForSingleObject(handle, 0) } != 0;
        println!(
            "loadwatch   t+{}s client {}",
            step * 5,
            if alive { "alive" } else { "DIED" }
        );
        if !alive {
            break;
        }
    }
    unsafe { CloseHandle(handle) };
    Ok(())
}

/// Writes a five-byte `mov eax, 0x5EED0001; ret` into a private RWX page and
/// jumps a thread at it.
///
/// The earlier manual-map attempts died instantly and were read as "the client
/// kills private executable pages". A private RWX page by itself survives a
/// full minute, so instant death was most likely our own fault — bad imports,
/// missing TLS, a stub returning into junk. This isolates it: five bytes of
/// known-good code, one call, one restore.
fn exec_ping(pid: u32) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let code = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x2000, MEM_COMMIT_RESERVE, 0x04)
    };
    if code.is_null() {
        unsafe { CloseHandle(handle) };
        return Err("code allocation failed".into());
    }
    let mut written = 0usize;
    let bytes: [u8; 6] = [0xB8, 0x01, 0x00, 0xED, 0x5E, 0xC3];
    unsafe {
        WriteProcessMemory(
            handle,
            code,
            bytes.as_ptr() as *const c_void,
            6,
            &mut written,
        )
    };
    let mut old = 0u32;
    unsafe { VirtualProtectEx(handle, code, 0x1000, 0x40, &mut old) };

    let stack_top = code as u64 + 0x2000 - 0x10;
    let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
    let park = unsafe { GetProcAddress(kernel32, b"SleepEx\0".as_ptr()) } as u64;
    unsafe {
        WriteProcessMemory(
            handle,
            (stack_top - 8) as *mut c_void,
            &park as *const u64 as *const c_void,
            8,
            &mut written,
        )
    };

    let modules = modules_of(pid);
    let Some(parked) = hijack(handle, pid, &modules, code as u64, 0, stack_top - 8, park) else {
        unsafe { CloseHandle(handle) };
        return Err("no thread available".into());
    };
    std::thread::sleep(std::time::Duration::from_millis(800));
    unpark(handle, &parked);
    println!("execping    called 0x{:X}, thread restored", code as u64);

    for step in 1..=12 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let alive = unsafe { WaitForSingleObject(handle, 0) } != 0;
        println!(
            "execping    t+{}s client {}",
            step * 5,
            if alive { "alive" } else { "DIED" }
        );
        if !alive {
            break;
        }
    }
    unsafe { CloseHandle(handle) };
    Ok(())
}

/// Touches one 13-byte window inside the client's own `.text`.
///
/// `identical` rewrites the exact bytes that were read, so a content hash is
/// unchanged and only the page's private/shared state differs. Otherwise it
/// writes `0x90`, then puts the original bytes back immediately — the shape a
/// real detour would have if it were armed and disarmed inside one burst.
fn patch_test(pid: u32, rva: u32, identical: bool) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let modules = modules_of(pid);
    let client = modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(EXE))
        .ok_or("client module not found")?;
    let address = client.base + rva as u64;

    let mut original = [0u8; 13];
    let mut got = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            original.as_mut_ptr() as *mut c_void,
            13,
            &mut got,
        )
    };
    if ok == 0 || got != 13 {
        unsafe { CloseHandle(handle) };
        return Err("cannot read target bytes".into());
    }
    println!("patchtest   {EXE}+0x{rva:X} = {:02X?}", original);

    let page = address & !0xFFF;
    let mut old = 0u32;
    // Image pages here refuse PAGE_EXECUTE_READWRITE (87), so walk down the
    // legal set. PAGE_EXECUTE_WRITECOPY is the one that belongs to images: the
    // write goes to a private copy and the shared view stays clean.
    let mut protected = 0;
    for want in [0x40u32, 0x80, 0x04] {
        protected = unsafe { VirtualProtectEx(handle, page as *mut c_void, 0x1000, want, &mut old) };
        if protected != 0 {
            println!("patchtest   protection 0x{want:X} ok (was 0x{old:X})");
            break;
        }
    }
    if protected == 0 {
        unsafe { CloseHandle(handle) };
        return Err(format!("VirtualProtectEx failed ({})", unsafe { GetLastError() }));
    }

    let mut written = 0usize;
    let replacement: [u8; 13] = if identical { original } else { [0x90; 13] };
    unsafe {
        WriteProcessMemory(
            handle,
            address as *mut c_void,
            replacement.as_ptr() as *const c_void,
            13,
            &mut written,
        )
    };
    if !identical {
        unsafe {
            WriteProcessMemory(
                handle,
                address as *mut c_void,
                original.as_ptr() as *const c_void,
                13,
                &mut written,
            )
        };
    }
    unsafe { VirtualProtectEx(handle, page as *mut c_void, 0x1000, old, &mut old) };
    println!(
        "patchtest   {}{}, protection back to 0x{old:X}",
        if identical { "rewrote identical bytes" } else { "flipped to nops and restored" },
        ""
    );

    for step in 1..=12 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let alive = unsafe { WaitForSingleObject(handle, 0) } != 0;
        println!(
            "patchtest   t+{}s client {}",
            step * 5,
            if alive { "alive" } else { "DIED" }
        );
        if !alive {
            break;
        }
    }
    unsafe { CloseHandle(handle) };
    Ok(())
}

/// Reports the things a scanner could object to in a target process: image
/// regions that no loader entry owns, and private regions that are executable.
///
/// Not an emulator of Hyperion — an emulator would need its predicate, and the
/// predicate is compiled into a 100 MB `.text` with no symbol we can name. This
/// encodes the three rules the client has already enforced on us, so a new
/// injection shape can be checked in a second instead of costing a rejoin.
fn oracle(pid: u32) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED | PROCESS_VM_READ, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let modules = modules_of(pid);
    let inside_module = |address: u64| {
        modules
            .iter()
            .any(|module| address >= module.base && address < module.base + module.size)
    };

    let mut address = 0x10000u64;
    let mut unregistered = Vec::new();
    let mut private_exec = Vec::new();
    let mut image_regions = 0usize;
    let mut private_regions = 0usize;
    let mut info = [0u8; 48];

    while address < 0x7FFF_FFFF_0000 {
        let got = unsafe {
            VirtualQueryEx(
                handle,
                address as *const c_void,
                info.as_mut_ptr() as *mut c_void,
                48,
            )
        };
        if got == 0 {
            break;
        }
        let base = u64::from_le_bytes(info[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(info[0x18..0x20].try_into().unwrap());
        let state = u32::from_le_bytes(info[0x20..0x24].try_into().unwrap());
        let protect = u32::from_le_bytes(info[0x24..0x28].try_into().unwrap());
        let kind = u32::from_le_bytes(info[0x28..0x2C].try_into().unwrap());
        if size == 0 {
            break;
        }

        if state == 0x1000 {
            match kind {
                0x100_0000 => {
                    image_regions += 1;
                    // An image region is "unowned" only when it sits outside
                    // every module's span; a module is split into one region per
                    // protection, so comparing bases directly flags everything.
                    if !inside_module(base) {
                        unregistered.push((base, size, protect));
                    }
                }
                0x2_0000 => {
                    private_regions += 1;
                    let executable = matches!(
                        protect & 0xFF,
                        0x10 | 0x20 | 0x40 | 0x80
                    );
                    // Windows itself keeps private executable pages inside
                    // modules (CFG bitmaps, hot patches). Only pages with no
                    // module to belong to are worth reporting.
                    if executable && !inside_module(base) {
                        private_exec.push((base, size, protect));
                    }
                }
                _ => {}
            }
        }
        address = base + size;
        if address <= base {
            break;
        }
    }

    println!(
        "oracle      modules {}, image regions {image_regions}, private regions {private_regions}",
        modules.len()
    );
    println!("oracle      unregistered image views: {}", unregistered.len());
    for (base, size, protect) in &unregistered {
        println!("oracle        image 0x{base:X} +0x{size:X} prot 0x{protect:X}");
    }
    println!("oracle      executable private regions: {}", private_exec.len());
    for (base, size, protect) in &private_exec {
        if *size >= 0x1000 {
            println!("oracle        private 0x{base:X} +0x{size:X} prot 0x{protect:X}");
        }
    }

    let verdict = unregistered.is_empty() && private_exec.is_empty();
    println!(
        "oracle      verdict: {}",
        if verdict { "clean" } else { "would trip" }
    );
    unsafe { CloseHandle(handle) };
    Ok(())
}

/// Captures `lua_State*` without writing a single byte into the client.
///
/// Patching `luaD_call` is closed: even rewriting its original bytes kills the
/// client, so the check watches whether a code page stopped being the shared
/// file view. Sampling is passive by comparison — suspend a thread, read RIP and
/// RCX, resume. When RIP lands inside a function of interest, RCX is its first
/// argument, which for `luaD_call` is the thread state.
/// Reads raw memory as qwords. Used to lay out a captured `lua_State` field by
/// field instead of trusting an offset table.
fn dump_memory(pid: u32, address: u64, length: usize) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    dump_in(handle, address, length);
    unsafe { CloseHandle(handle) };
    Ok(())
}

fn raw_dump(pid: u32, address: u64, length: usize) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let mut offset = 0usize;
    while offset < length {
        let chunk = (length - offset).min(0x20);
        let mut bytes = vec![0u8; chunk];
        let mut got = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                (address + offset as u64) as *const c_void,
                bytes.as_mut_ptr() as *mut c_void,
                chunk,
                &mut got,
            )
        };
        if ok == 0 || got != chunk {
            println!("bytes       0x{:X} unreadable", address + offset as u64);
            break;
        }
        let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
        println!("bytes       +{:04X}  {}", offset, hex.join(" "));
        offset += chunk;
    }
    unsafe { CloseHandle(handle) };
    Ok(())
}

fn dump_in(handle: Handle, address: u64, length: usize) {
    let mut offset = 0usize;
    while offset < length {
        let chunk = (length - offset).min(0x40);
        let mut bytes = vec![0u8; chunk];
        let mut got = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                (address + offset as u64) as *const c_void,
                bytes.as_mut_ptr() as *mut c_void,
                chunk,
                &mut got,
            )
        };
        if ok == 0 || got != chunk {
            println!("dump        0x{:X} unreadable", address + offset as u64);
            break;
        }
        let words: Vec<String> = bytes
            .chunks_exact(8)
            .map(|word| {
                format!(
                    "{:016X}",
                    u64::from_le_bytes(word.try_into().expect("eight bytes"))
                )
            })
            .collect();
        println!("dump        +{:04X}  {}", offset, words.join(" "));
        offset += chunk;
    }
}

fn sample_state(pid: u32, rva: u32, span: u64, seconds: u64) -> Result<(), String> {    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let modules = modules_of(pid);
    let client = modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(EXE))
        .ok_or("client module not found")?;
    let entry = client.base + rva as u64;
    println!(
        "sampler     watching RobloxPlayerBeta+0x{rva:X} (0x{entry:X} .. 0x{:X})",
        entry + span
    );

    let ids = threads_of(pid);
    let mut threads: Vec<(u32, Handle)> = Vec::new();
    for id in ids {
        let thread = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, id) };
        if !thread.is_null() {
            threads.push((id, thread));
        }
    }
    println!("sampler     {} threads held open", threads.len());

    // Phase A — which thread spends its time where. One pass over every thread
    // is low resolution, so the point is not to catch the target but to find
    // the thread that runs the interpreter.
    let mut histogram: HashMap<u32, HashMap<u64, u32>> = HashMap::new();
    let mut samples = 0u64;
    let phase_a_seconds = (seconds / 3).max(4);
    let phase_a_end = std::time::Instant::now() + std::time::Duration::from_secs(phase_a_seconds);
    while std::time::Instant::now() < phase_a_end {
        for (id, thread) in &threads {
            if let Some(rip) = context_rip(*thread) {
                samples += 1;
                if rip >= client.base && rip < client.base + client.size {
                    *histogram
                        .entry(*id)
                        .or_default()
                        .entry(rip - client.base)
                        .or_insert(0) += 1;
                }
            }
        }
    }
    println!("sampler     phase A: {samples} samples over {phase_a_seconds}s");

    // Rank each thread by how much of its time lands in the Luau window around
    // the sampled function.
    let window_lo = (rva as u64).saturating_sub(0x10000);
    let window_hi = rva as u64 + 0x60000;
    let mut candidates: Vec<(u32, u32)> = Vec::new();
    let mut ranked_threads: Vec<(u32, u32, u64)> = Vec::new();
    for (id, offsets) in &histogram {
        let total: u32 = offsets.values().sum();
        let mut sorted: Vec<(u64, u32)> = offsets.iter().map(|(k, v)| (*k, *v)).collect();
        sorted.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        let top = sorted.first().map(|(offset, _)| *offset).unwrap_or(0);
        ranked_threads.push((*id, total, top));
        let in_window: u32 = sorted
            .iter()
            .filter(|(offset, _)| *offset >= window_lo && *offset <= window_hi)
            .map(|(_, count)| *count)
            .sum();
        if in_window > 0 {
            candidates.push((in_window, *id));
            let shown = sorted
                .iter()
                .take(3)
                .map(|(offset, count)| format!("+0x{offset:X} x{count}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "sampler     thread {id}: {total} samples, {in_window} in window [{shown}]"
            );
        }
    }
    ranked_threads.sort_by_key(|(_, total, _)| std::cmp::Reverse(*total));
    for (id, total, top) in ranked_threads.iter().take(6) {
        if candidates.iter().any(|(_, candidate)| candidate == id) {
            continue;
        }
        println!("sampler     thread {id}: {total} samples, top +0x{top:X}");
    }
    candidates.sort_by_key(|(count, _)| std::cmp::Reverse(*count));

    // Phase B — hammer only the candidates. One thread at a time raises the
    // rate from hundreds of samples to tens of thousands.
    let remaining = seconds.saturating_sub(phase_a_seconds).max(5);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(remaining);
    let mut spins = 0u64;
    let mut last_report = std::time::Instant::now();
    while std::time::Instant::now() < deadline {
        for (_, id) in &candidates {
            let Some((_, thread)) = threads.iter().find(|(tid, _)| tid == id) else {
                continue;
            };
            unsafe { SuspendThread(*thread) };
            let mut context = vec![0u8; CONTEXT_SIZE];
            unsafe {
                *(context.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL;
            }
            let ok = unsafe { GetThreadContext(*thread, context.as_mut_ptr() as *mut c_void) } != 0;
            let rip = unsafe { *(context.as_ptr().add(0xF8) as *const u64) };
            // CONTEXT layout: RAX 0x78, RCX 0x80, RDX 0x88, RBX 0x90.
            // luaD_call copies RCX into RBX at +0x20, so after that the state
            // lives in RBX and RCX is scratch. Before it, RCX is the state.
            let rcx = unsafe { *(context.as_ptr().add(0x80) as *const u64) };
            let rbx = unsafe { *(context.as_ptr().add(0x90) as *const u64) };
            unsafe { ResumeThread(*thread) };
            if !ok {
                continue;
            }
            spins += 1;
            if rip >= entry && rip < entry + span {
                // luaV_execute keeps `L` in r12 (mov r12, rcx at +0x20), so r12
                // is the reliable carrier anywhere in the interpreter body.
                let mut registers = [0u64; 16];
                let slots = [
                    0x78usize, 0x80, 0x88, 0x90, 0xB0, 0xA8, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0,
                    0xE8, 0xF0, 0x98, 0xA0,
                ];
                for (index, slot) in slots.iter().enumerate() {
                    registers[index] = unsafe { *(context.as_ptr().add(*slot) as *const u64) };
                }
                let r12 = registers[10];
                let mut state = 0u64;
                // `lea rsi, [r12 + 0x70]` right in the interpreter prologue
                // proves r12 is the state; its header tag byte is 0x0A in this
                // build, not the Luau textbook 8, so tag alone is not a test.
                let r12_stack = read_u64(handle, r12 + LUA_U64_STACK);
                let r12_top = read_u64(handle, r12 + LUA_U64_TOP);
                let r12_last = read_u64(handle, r12 + LUA_U64_STACK_LAST);
                if r12_stack > 0x10000 && r12_stack <= r12_top && r12_top <= r12_last {
                    state = r12;
                }
                if state == 0 {
                    for candidate in registers {
                        let stack = read_u64(handle, candidate + LUA_U64_STACK);
                        let top = read_u64(handle, candidate + LUA_U64_TOP);
                        let last = read_u64(handle, candidate + LUA_U64_STACK_LAST);
                        let global = read_u64(handle, candidate + LUA_U64_GLOBAL);
                        if stack > 0x10000 && stack <= top && top <= last && global > 0x10000 {
                            state = candidate;
                            break;
                        }
                    }
                }
                println!(
                    "sampler     hit thread {id} rip 0x{rip:X} (+0x{:X}) state 0x{state:X} after {spins} spins",
                    rip - entry
                );
                println!(
                    "sampler     rax 0x{:X} rcx 0x{:X} rdx 0x{:X} rbx 0x{:X} rsi 0x{:X} rdi 0x{:X} r8 0x{:X} r9 0x{:X}",
                    registers[0], registers[1], registers[2], registers[3],
                    registers[5], registers[4], registers[6], registers[7]
                );
                println!(
                    "sampler     r10 0x{:X} r11 0x{:X} r12 0x{:X} r13 0x{:X} r14 0x{:X} r15 0x{:X} rsp 0x{:X} rbp 0x{:X}",
                    registers[8], registers[9], registers[10], registers[11],
                    registers[12], registers[13], registers[14], registers[15]
                );
                // The interpreter keeps the instruction stream in r14 (code base)
                // and the program counter in r15. Dumping both shows what real,
                // working bytecode looks like — the ground truth for the mapping.
                let code = registers[12];
                let pc = registers[13];
                if pc > 0x10000 {
                    if let Some(bytes) = read_bytes(handle, pc.saturating_sub(8), 0x40) {
                        let hx: Vec<String> =
                            bytes.iter().map(|b| format!("{b:02X}")).collect();
                        println!("sampler     pc 0x{pc:X} [-8..+0x38] {}", hx.join(" "));
                    }
                }
                if code > 0x10000 && code != pc.saturating_sub(0) {
                    if let Some(bytes) = read_bytes(handle, code, 0x40) {
                        let hx: Vec<String> =
                            bytes.iter().map(|b| format!("{b:02X}")).collect();
                        println!("sampler     code 0x{code:X} {hx}", hx = hx.join(" "));
                    }
                }
                // Which register actually points at the instruction stream? Score
                // every pointer-looking register: a real code base is a run of
                // dwords whose low byte is a live dispatch byte. The client's
                // valid-dispatch table at +0x26933F4 is the oracle.
                let mut valid = [false; 256];
                if let Some(bytes) = read_bytes(handle, client.base + 0x26933F4, 254) {
                    for (index, value) in bytes.iter().enumerate() {
                        if *value != 0x5E {
                            valid[index + 1] = true;
                        }
                    }
                }
                let mut best: Option<(usize, u64, u32)> = None;
                for (index, value) in registers.iter().enumerate() {
                    if *value < 0x10000 {
                        continue;
                    }
                    for shift in 0..8u64 {
                        let start = value.wrapping_sub(shift * 4);
                        let Some(words) = read_bytes(handle, start, 0x40) else { continue };
                        let mut score = 0u32;
                        for chunk in words.chunks_exact(4) {
                            if valid[chunk[0] as usize] {
                                score += 1;
                            }
                        }
                        if best.map_or(true, |(_, _, top)| score > top) {
                            best = Some((index, start, score));
                        }
                    }
                }
                if let Some((index, start, score)) = best {
                    println!(
                        "sampler     codestream candidate reg[{index}] 0x{start:X} score {score}/16"
                    );
                    if let Some(bytes) = read_bytes(handle, start, 0x60) {
                        let hx: Vec<String> =
                            bytes.iter().map(|b| format!("{b:02X}")).collect();
                        println!("sampler     stream {}", hx.join(" "));
                    }
                }
                if state == 0 {
                    println!("sampler     no register carried a lua_State; r12 0x{r12:X} contents:");
                    dump_in(handle, r12, 0x40);
                    continue;
                }
                describe_state(handle, &modules, state);
                println!("sampler     raw state:");
                dump_in(handle, state, 0x100);
                for (_, thread) in &threads {
                    unsafe { CloseHandle(*thread) };
                }
                unsafe { CloseHandle(handle) };
                return Ok(());
            }
            if last_report.elapsed() > std::time::Duration::from_secs(5) {
                println!(
                    "sampler     thread {id} rip +0x{:X}, {spins} spins, no hit yet",
                    rip.wrapping_sub(client.base)
                );
                last_report = std::time::Instant::now();
            }
        }
        if candidates.is_empty() {
            break;
        }
    }
    println!("sampler     {spins} focused spins, no hit in window");
    for (_, thread) in &threads {
        unsafe { CloseHandle(*thread) };
    }
    unsafe { CloseHandle(handle) };
    Ok(())
}

fn context_rip(thread: Handle) -> Option<u64> {
    unsafe { SuspendThread(thread) };
    let mut context = vec![0u8; CONTEXT_SIZE];
    unsafe { *(context.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL };
    let ok = unsafe { GetThreadContext(thread, context.as_mut_ptr() as *mut c_void) } != 0;
    unsafe { ResumeThread(thread) };
    if !ok {
        return None;
    }
    Some(unsafe { *(context.as_ptr().add(0xF8) as *const u64) })
}

// ---------------------------------------------------------------------------
// Luau layout for version-f0ea5da9412f4e35 (Credoxy 2.6.9 dump).
// Field offsets are the ones the client actually reads; `base` and `stacksize`
// are pointer-encoded in memory, so they are shown raw and marked.
// ---------------------------------------------------------------------------
const LUA_U8_TT: u64 = 0x1;
const LUA_U8_STATUS: u64 = 0x3;
const LUA_U64_USERDATA: u64 = 0x8;
const LUA_U64_GT: u64 = 0x10;
const LUA_U64_NAMECALL: u64 = 0x18;
const LUA_U64_END_CI: u64 = 0x20;
const LUA_U64_BASE_CI: u64 = 0x28;
const LUA_U64_STACK: u64 = 0x48;
const LUA_U64_GLOBAL: u64 = 0x50;
const LUA_U64_BASE_ENC: u64 = 0x58;
const LUA_U64_TOP: u64 = 0x60;
const LUA_U64_STACK_LAST: u64 = 0x68;
const LUA_U64_CI: u64 = 0x70;
const LUA_U64_STACKSIZE_ENC: u64 = 0x78;
const LUA_I32_SIZE_CI: u64 = 0x7c;

const G_U64_MAINTHREAD: u64 = 0x78;
const G_U64_GC_THRESHOLD: u64 = 0x60;
const G_U64_TOTALBYTES: u64 = 0x68;
const G_U64_BUILTIN_PCALL: u64 = 0x5488;
const G_U64_BUILTIN_XPCALL: u64 = 0x5490;
const G_U64_PTRENCKEY: u64 = 0x650;

const CLOSURE_U8_NUPVALUES: u64 = 0x4;
const CLOSURE_U8_IS_C: u64 = 0x5;
const CLOSURE_U64_ENV: u64 = 0x10;
const CLOSURE_U64_F: u64 = 0x28;

const CALLINFO_STRIDE: u64 = 0x30;
const CI_U64_BASE: u64 = 0x0;
const CI_U64_TOP: u64 = 0x8;
const CI_U64_FUNC: u64 = 0x10;
const CI_U64_PROTO: u64 = 0x18;
const CI_U64_SAVEDPC: u64 = 0x20;
const CI_I32_NRESULTS: u64 = 0x28;
const CI_U32_FLAGS: u64 = 0x2c;

const PROTO_U64_CODE: u64 = 0x68;

const TVAL_U64_VALUE: u64 = 0x0;
const TVAL_I32_TT: u64 = 0xc;
const PROTO_I32_SIZECODE: u64 = 0xa8;
const EXTRA_U64_SHARED: u64 = 0x18;
const SHARED_U64_HEAD: u64 = 0x8;
const SHARED_U64_COUNT: u64 = 0x0;
const SHARED_U64_SCRIPT_CONTEXT: u64 = 0x18;
const SHARED_I32_THREADCOUNT: u64 = 0x20;

/// Dumps the runtime opcode-dispatch table and checks a set of bytes against it.
///
/// The table in the on-disk image is a build-time placeholder: the client fills
/// it at startup, so any verdict about "is this a legal dispatch byte" has to
/// come from the live process, not the file.
fn dump_opcode_table(pid: u32, probe: &[u8]) -> Result<(), String> {
    let modules = modules_of(pid);
    let client = modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(EXE))
        .ok_or("client module not found")?;
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let Some(table) = read_bytes(handle, client.base + 0x26933F4, 254) else {
        return Err("dispatch table unreadable".into());
    };
    let hex: Vec<String> = table.iter().map(|b| format!("{b:02X}")).collect();
    println!("opmap       table {}", hex.join(" "));

    let mut seen = [false; 256];
    for byte in probe {
        let index = *byte as usize;
        let dense = if index >= 1 { table[index - 1] } else { 0x5E };
        seen[index] = true;
        println!(
            "opmap       0x{byte:02X} -> table[{}] = 0x{dense:02X} {}",
            index as i64 - 1,
            if dense == 0x5E { "INVALID" } else { "ok" }
        );
    }

    let mut invert = [0xFFu8; 256];
    for (index, dense) in table.iter().enumerate() {
        if *dense != 0x5E {
            invert[*dense as usize] = (index + 1) as u8;
        }
    }
    let inv: Vec<String> = invert[..94]
        .iter()
        .enumerate()
        .map(|(dense, byte)| format!("{dense}:{byte:02X}"))
        .collect();
    println!("opmap       inverse {}", inv.join(" "));
    let _ = seen;
    unsafe { CloseHandle(handle) };
    Ok(())
}

/// The elevated helper is launched by `Start-Process -Verb RunAs`, which does not
/// inherit the parent environment, so an env var alone cannot gate the run. A
/// marker file next to the driver works regardless of how the process started.
fn no_exec_requested() -> bool {
    if std::env::var_os("ZENO_NO_EXEC").is_some() {
        return true;
    }

    let path = std::env::temp_dir().join("opencode").join("zeno-payload").join("noexec.flag");
    path.exists()
}

const BUILD_TO_VM_TABLE_V0: [(usize, u8); 12] = [
    (0, 0xb2),
    (1, 0x01),
    (4, 0x72),
    (5, 0x0e),
    (6, 0x45),
    (12, 0x02),
    (18, 0x95),
    (21, 0xe2),
    (22, 0x57),
    (53, 0xd7),
    (64, 0x9a),
    (65, 0x4a),
];

const BUILD_TO_VM_TABLE_V1: [(usize, u8); 12] = [
    (0, 0x01),
    (3, 0x72),
    (4, 0x0e),
    (5, 0x45),
    (11, 0x02),
    (17, 0x95),
    (20, 0xe2),
    (21, 0x57),
    (52, 0xd7),
    (63, 0x9a),
    (64, 0x4a),
    (193, 0x41),
];

/// The client rewrites each instruction's opcode byte during `luau_load`, so the
/// byte a compiler has to emit is not the byte the VM dispatches on. That rewrite
/// is a byte table built at startup — the pairs below were measured by loading
/// probe chunks and reading `Proto::code` back. This scans the process for it.
fn find_byte_map(pid: u32) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }

    let mut address = 0x10000u64;
    let mut info = [0u8; 48];
    let mut scanned: u64 = 0;
    let mut hits: Vec<(u64, usize, bool)> = Vec::new();
    let chunk = 4u64 * 1024 * 1024;
    let span = 0x100usize;

    while address < 0x7FFF_FFFF_0000 {
        let got = unsafe {
            VirtualQueryEx(handle, address as *const c_void, info.as_mut_ptr() as *mut c_void, 48)
        };
        if got == 0 {
            break;
        }
        let base = u64::from_le_bytes(info[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(info[0x18..0x20].try_into().unwrap());
        let state = u32::from_le_bytes(info[0x20..0x24].try_into().unwrap());
        let protect = u32::from_le_bytes(info[0x24..0x28].try_into().unwrap());
        if size == 0 {
            break;
        }

        let readable = state == 0x1000
            && protect & 0x100 == 0
            && matches!(protect & 0xFF, 0x02 | 0x04 | 0x06 | 0x08 | 0x20 | 0x40 | 0x80);
        if readable && size <= 512 * 1024 * 1024 {
            let mut cursor = 0u64;
            let mut buffer = vec![0u8; chunk as usize + span];
            while cursor < size {
                let want = chunk.min(size - cursor);
                let mut read = 0usize;
                let ok = unsafe {
                    ReadProcessMemory(
                        handle,
                        (base + cursor) as *const c_void,
                        buffer.as_mut_ptr() as *mut c_void,
                        want as usize,
                        &mut read,
                    )
                };
                if ok != 0 && read > span {
                    let window = &buffer[..read];
                    for i in 0..window.len() - span {
                        if window[i] != 0xb2 && window[i] != 0x01 {
                            continue;
                        }
                        if window[i] != 0xb2 {
                            continue;
                        }
                        if BUILD_TO_VM_TABLE_V0
                            .iter()
                            .all(|(offset, value)| window[i + offset] == *value)
                        {
                            hits.push((base + cursor + i as u64, 0, false));
                            println!("findmap      v0 table at 0x{:X}", base + cursor + i as u64);
                        }
                    }
                    scanned += read as u64;
                }
                cursor += want;
            }
        }
        address = base + size;
        if address <= base {
            break;
        }
    }

    println!("findmap      scanned {:.1} MB in {pid}, {} hit(s)", scanned as f64 / 1_048_576.0, hits.len());
    for (at, _, _) in &hits {
        if let Some(table) = read_bytes(handle, *at, 256) {
            let hex: Vec<String> = table[..160].iter().map(|b| format!("{b:02X}")).collect();
            println!("findmap      0x{at:X}: {}", hex.join(" "));
        }
    }
    unsafe { CloseHandle(handle) };
    let _ = BUILD_TO_VM_TABLE_V1;
    Ok(())
}

/// Finds live `lua_State` objects without needing an interpreter frame. The
/// header tag byte is 0x0A at +1 in this build, and the stack window
/// (stack <= base <= top <= stack_last) plus the `global` back-pointer at
/// `global+0x78 == state` are strong enough that false hits are rare.
fn find_states(pid: u32) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }

    let mut address = 0x10000u64;
    let mut info = [0u8; 48];
    let mut scanned: u64 = 0;
    let mut hits: Vec<u64> = Vec::new();
    let chunk = 4u64 * 1024 * 1024;
    let span = 0x100usize;

    while address < 0x7FFF_FFFF_0000 && hits.len() < 16 {
        let got = unsafe {
            VirtualQueryEx(handle, address as *const c_void, info.as_mut_ptr() as *mut c_void, 48)
        };
        if got == 0 {
            break;
        }
        let base = u64::from_le_bytes(info[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(info[0x18..0x20].try_into().unwrap());
        let state = u32::from_le_bytes(info[0x20..0x24].try_into().unwrap());
        let protect = u32::from_le_bytes(info[0x24..0x28].try_into().unwrap());
        if size == 0 {
            break;
        }

        let readable = state == 0x1000
            && protect & 0x100 == 0
            && matches!(protect & 0xFF, 0x02 | 0x04 | 0x06 | 0x08 | 0x20 | 0x40 | 0x80);
        if readable && size <= 512 * 1024 * 1024 {
            let mut cursor = 0u64;
            let mut buffer = vec![0u8; chunk as usize + span];
            while cursor < size {
                let want = chunk.min(size - cursor);
                let mut read = 0usize;
                let ok = unsafe {
                    ReadProcessMemory(
                        handle,
                        (base + cursor) as *const c_void,
                        buffer.as_mut_ptr() as *mut c_void,
                        want as usize,
                        &mut read,
                    )
                };
                if ok != 0 && read > span {
                    let window = &buffer[..read];
                    let mut i = 0usize;
                    while i + span <= window.len() {
                        if window[i + 1] != 0x0A {
                            i += 8;
                            continue;
                        }
                        let q = |off: usize| -> u64 {
                            u64::from_le_bytes(window[i + off..i + off + 8].try_into().unwrap())
                        };
                        let global = q(0x50);
                        let stack = q(0x48);
                        let l_base = q(0x58);
                        let top = q(0x60);
                        let last = q(0x68);
                        let end_ci = q(0x20);
                        if stack > 0x10000
                            && stack <= l_base
                            && l_base <= top
                            && top <= last
                            && last - stack < 0x1000_0000
                            && global > 0x10000
                            && end_ci > 0x10000
                        {
                            let candidate = base + cursor + i as u64;
                            let mainthread = read_u64(handle, global + G_U64_MAINTHREAD);
                            if mainthread == candidate {
                                println!(
                                    "findstate   0x{candidate:X} global 0x{global:X} stack 0x{stack:X} top 0x{top:X} last 0x{last:X}"
                                );
                                hits.push(candidate);
                            }
                        }
                        i += 8;
                    }
                    scanned += read as u64;
                }
                cursor += want;
            }
        }
        address = base + size;
        if address <= base {
            break;
        }
    }

    println!(
        "findstate   scanned {:.1} MB in {pid}, {} state(s)",
        scanned as f64 / 1_048_576.0,
        hits.len()
    );
    for at in &hits {
        let hdr = read_bytes(handle, *at, 0x80).unwrap_or_default();
        let hex: Vec<String> = hdr.iter().map(|b| format!("{b:02X}")).collect();
        println!("findstate   0x{at:X}: {}", hex.join(" "));
    }
    unsafe { CloseHandle(handle) };
    Ok(())
}

/// `EB FE` filler in the client's `.text`, used as a parking lot: a hijacked
/// thread that returns here spins without touching its stack, so the original
/// context can be put back at leisure.
const PARK_RVA: u64 = 0x4320D92;

const LUA_TTHREAD: u8 = 8;
// Roblox inserts LUA_TBUFFER at 7, so a function TValue carries tag 8.
const LUA_TFUNCTION: i32 = 8;

fn read_bytes(handle: Handle, address: u64, length: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; length];
    let mut got = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            length,
            &mut got,
        )
    };
    if ok == 0 || got != length {
        return None;
    }
    Some(buffer)
}

fn read_u8_at(handle: Handle, address: u64) -> Option<u8> {
    read_bytes(handle, address, 1).map(|bytes| bytes[0])
}

fn read_u16_at(handle: Handle, address: u64) -> Option<u16> {
    read_bytes(handle, address, 2).map(|bytes| u16::from_le_bytes(bytes[..2].try_into().unwrap()))
}

fn read_u32_at(handle: Handle, address: u64) -> Option<u32> {
    read_bytes(handle, address, 4).map(|bytes| u32::from_le_bytes(bytes[..4].try_into().unwrap()))
}

fn read_i32_at(handle: Handle, address: u64) -> Option<i32> {
    read_u32_at(handle, address).map(|value| value as i32)
}

fn module_hit(modules: &[Module], address: u64) -> String {
    for module in modules {
        if address >= module.base && address < module.base + module.size {
            return format!("{}+0x{:X}", module.name, address - module.base);
        }
    }
    format!("0x{address:X}")
}

fn module_name_at(modules: &[Module], address: u64) -> Option<&str> {
    modules
        .iter()
        .find(|module| address >= module.base && address < module.base + module.size)
        .map(|module| module.name.as_str())
}

fn describe_closure(handle: Handle, modules: &[Module], label: &str, closure: u64) {
    if closure == 0 {
        println!("vminfo      {label:<14} 0x0");
        return;
    }
    let is_c = read_u8_at(handle, closure + CLOSURE_U8_IS_C).unwrap_or(0xff);
    let nup = read_u8_at(handle, closure + CLOSURE_U8_NUPVALUES).unwrap_or(0xff);
    let env = read_u64(handle, closure + CLOSURE_U64_ENV);
    let function = read_u64(handle, closure + CLOSURE_U64_F);
    println!(
        "vminfo      {label:<14} 0x{closure:X} isC {is_c} nup {nup} env {} f {}",
        module_hit(modules, env),
        module_hit(modules, function)
    );
}

/// Prints a candidate `lua_State` against the real layout so a false hit is
/// obvious: `stack < top <= stack_last`, a readable `global`, and a `ci` that
/// sits inside `base_ci .. end_ci`.
fn describe_state(handle: Handle, modules: &[Module], state: u64) {
    if state < 0x10000 || state % 8 != 0 {
        println!("vminfo      rcx 0x{state:X} does not look like a pointer");
        return;
    }
    let aa = read_u8_at(handle, state + LUA_U8_TT).unwrap_or(0xff);
    let status = read_u8_at(handle, state + LUA_U8_STATUS).unwrap_or(0xff);
    let userdata = read_u64(handle, state + LUA_U64_USERDATA);
    let gt = read_u64(handle, state + LUA_U64_GT);
    let stack = read_u64(handle, state + LUA_U64_STACK);
    let global = read_u64(handle, state + LUA_U64_GLOBAL);
    let base = read_u64(handle, state + LUA_U64_BASE_ENC);
    let top = read_u64(handle, state + LUA_U64_TOP);
    let stack_last = read_u64(handle, state + LUA_U64_STACK_LAST);
    let ci = read_u64(handle, state + LUA_U64_CI);
    let base_ci = read_u64(handle, state + LUA_U64_BASE_CI);
    let end_ci = read_u64(handle, state + LUA_U64_END_CI);
    let stacksize = read_u64(handle, state + LUA_U64_STACKSIZE_ENC);
    let size_ci = read_i32_at(handle, state + LUA_I32_SIZE_CI).unwrap_or(0);

    println!("vminfo      state        0x{state:X}");
    println!("vminfo      tt={aa} status={status} {}", if aa == LUA_TTHREAD { "(thread)" } else { "(NOT a thread)" });
    println!("vminfo      userdata     {}  (delta 0x{:X})", module_hit(modules, userdata), userdata.wrapping_sub(state));
    println!("vminfo      gt           {}", module_hit(modules, gt));
    println!("vminfo      stack        0x{stack:X}");
    println!("vminfo      top          0x{top:X}  (depth {} slots)", top.wrapping_sub(stack) / 16);
    println!("vminfo      stack_last   0x{stack_last:X}");
    println!("vminfo      base+0x58    0x{base:X}  (VMValue-encoded)");
    println!("vminfo      stacksize    0x{stacksize:X}  (VMValue-encoded)");
    println!("vminfo      global       {}", module_hit(modules, global));
    println!("vminfo      base_ci      0x{base_ci:X}  ci 0x{ci:X}  end_ci 0x{end_ci:X}  size_ci {size_ci}");

    let sane = stack < top && top <= stack_last && global > 0x10000 && ci >= base_ci && ci < end_ci;
    println!("vminfo      sanity       {}", if sane { "consistent" } else { "INCONSISTENT" });

    if global > 0x10000 {
        let mainthread = read_u64(handle, global + G_U64_MAINTHREAD);
        let threshold = read_u64(handle, global + G_U64_GC_THRESHOLD);
        let total = read_u64(handle, global + G_U64_TOTALBYTES);
        let pcall = read_u64(handle, global + G_U64_BUILTIN_PCALL);
        let xpcall = read_u64(handle, global + G_U64_BUILTIN_XPCALL);
        println!("vminfo      mainthread   {}", module_hit(modules, mainthread));
        println!("vminfo      gc           total {total} threshold {threshold}");
        let keys = [
            read_u64(handle, global + G_U64_PTRENCKEY),
            read_u64(handle, global + G_U64_PTRENCKEY + 8),
            read_u64(handle, global + G_U64_PTRENCKEY + 16),
            read_u64(handle, global + G_U64_PTRENCKEY + 24),
        ];
        println!(
            "vminfo      ptrenckey    {:016X} {:016X} {:016X} {:016X}",
            keys[0], keys[1], keys[2], keys[3]
        );
        describe_closure(handle, modules, "builtinPcall", pcall);
        describe_closure(handle, modules, "builtinXpcall", xpcall);
    }

    // Frame walk: CallInfo is a contiguous array, so `previous` is `ci - 0x30`
    // and the walk stops at base_ci.
    let mut frame = ci;
    for depth in 0..10 {
        if frame < base_ci || frame >= end_ci || frame == 0 {
            break;
        }
        let func = read_u64(handle, frame + CI_U64_FUNC);
        let func_value = read_u64(handle, func + TVAL_U64_VALUE);
        let func_tt = read_i32_at(handle, func + TVAL_I32_TT).unwrap_or(-1);
        let proto = read_u64(handle, frame + CI_U64_PROTO);
        let savedpc = read_u64(handle, frame + CI_U64_SAVEDPC);
        let code = read_u64(handle, proto + PROTO_U64_CODE);
        let insn = if savedpc >= code && code > 0x10000 {
            ((savedpc - code) / 4) as i64
        } else {
            -1
        };
        let klass = if func_tt == LUA_TFUNCTION {
            let is_c = read_u8_at(handle, func_value + CLOSURE_U8_IS_C).unwrap_or(0xff);
            if is_c == 1 {
                format!("C fn {}", module_hit(modules, read_u64(handle, func_value + CLOSURE_U64_F)))
            } else {
                format!("Lua closure 0x{func_value:X}")
            }
        } else {
            format!("tt {func_tt} value 0x{func_value:X}")
        };
        println!(
            "vminfo      frame[{depth}] ci 0x{frame:X} nresults {} flags 0x{:X} {klass} proto {} insn {insn}",
            read_i32_at(handle, frame + CI_I32_NRESULTS).unwrap_or(0),
            read_u32_at(handle, frame + CI_U32_FLAGS).unwrap_or(0),
            module_hit(modules, proto),
        );
        let _ = read_u64(handle, frame + CI_U64_BASE);
        let _ = read_u64(handle, frame + CI_U64_TOP);
        frame = frame.wrapping_sub(CALLINFO_STRIDE);
    }

    // Every Roblox lua_State owns a RobloxExtraSpace that links into the
    // Shared thread list: state -> extra -> shared_ptr<Shared> -> allThreads.
    let extra_shared_ptr = read_u64(handle, userdata + EXTRA_U64_SHARED);
    if extra_shared_ptr > 0x10000 {
        let shared = extra_shared_ptr;
        let count = read_u64(handle, shared + SHARED_U64_COUNT);
        let head = read_u64(handle, shared + SHARED_U64_HEAD);
        let thread_count = read_i32_at(handle, shared + SHARED_I32_THREADCOUNT).unwrap_or(0);
        let script_context = read_u64(handle, shared + SHARED_U64_SCRIPT_CONTEXT);
        println!(
            "vminfo      shared       0x{shared:X} threads {count}/{thread_count} head 0x{head:X} scriptContext {}",
            module_hit(modules, script_context)
        );
        let delta = userdata.wrapping_sub(state);
        let mut entry = head;
        let mut seen = 0u64;
        while entry > 0x10000 && seen < 64 && seen < thread_count.max(1) as u64 {
            let sibling = entry.wrapping_sub(delta);
            let sibling_tt = read_u8_at(handle, sibling + LUA_U8_TT).unwrap_or(0xff);
            let sibling_global = read_u64(handle, sibling + LUA_U64_GLOBAL);
            let looks_like_state =
                sibling_tt == LUA_TTHREAD && sibling_global == global && sibling_global > 0x10000;
            println!(
                "vminfo      thread[{seen}] extra 0x{entry:X} -> state 0x{sibling:X} {}",
                if looks_like_state { "ok" } else { "not a state" }
            );
            let next = read_u64(handle, entry);
            if next == 0 || next == head {
                break;
            }
            entry = next;
            seen += 1;
        }
    }
}

/// Walks the collector's all-object list. The offset of `allgc` inside
/// `global_State` is not published, so it is discovered: every qword slot in
/// the first page of the global is treated as a candidate head and the chain
/// is followed for a few links, keeping only slots where every object header
/// carries a plausible type byte. The longest surviving chain is the list.
fn report_closure(
    handle: Handle,
    modules: &[Module],
    label: &str,
    closure: u64,
    dump_proto: bool,
) -> bool {
    if closure < 0x10000 {
        return false;
    }
    let is_c = read_u8_at(handle, closure + 5).unwrap_or(0xff);
    let stacksize = read_u8_at(handle, closure + 6).unwrap_or(0xff);
    let preload = read_u8_at(handle, closure + 7).unwrap_or(0xff);
    let env = read_u64(handle, closure + 0x10);
    println!(
        "lfind       {label} closure 0x{closure:X} isC {is_c} stacksize {stacksize} preload {preload} env {}",
        module_hit(modules, env)
    );
    if is_c != 0 {
        let f = read_u64(handle, closure + 0x28);
        println!("lfind         c.f {}", module_hit(modules, f));
        return false;
    }
    for off in [0x18u64, 0x20, 0x28, 0x30] {
        let p = read_u64(handle, closure + off);
        if p < 0x10000 {
            continue;
        }
        let code = read_u64(handle, p + 0x68);
        let sizecode = read_i32_at(handle, p + 0xa8).unwrap_or(-1);
        let plausible = code > 0x10000 && (0..=100000).contains(&sizecode);
        println!(
            "lfind         +{off:02X} -> 0x{p:X} code 0x{code:X} sizecode {sizecode}{}",
            if plausible { "  PROTO?" } else { "" }
        );
        if dump_proto && plausible {
            if let Some(head) = read_bytes(handle, p, 0x20) {
                let hex: Vec<String> = head.iter().map(|b| format!("{b:02X}")).collect();
                println!("lfind         proto head {}", hex.join(" "));
            }
            for field in [
                0x08u64, 0x10, 0x18, 0x20, 0x28, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78,
                0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8, 0xc0, 0xc8, 0xd0, 0xd8,
            ] {
                let v = read_u64(handle, p + field);
                let d = read_i32_at(handle, p + field).unwrap_or(0);
                println!("lfind         proto+{field:02X} = 0x{v:X} (i32 {d}) {}", module_hit(modules, v));
            }
            if let Some(words) = read_bytes(handle, code, 0x60) {
                let hex: Vec<String> = words.iter().map(|b| format!("{b:02X}")).collect();
                println!("lfind         code[0..0x60] {}", hex.join(" "));
            }
        }
    }
    true
}

fn scan_live_states(pid: u32) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let modules = modules_of(pid);
    let Some(client) = modules.iter().find(|m| m.name.eq_ignore_ascii_case(EXE)) else {
        unsafe { CloseHandle(handle) };
        return Err("client module not found".into());
    };
    let client_base = client.base;
    let client_end = client.base + client.size;

    let ids = threads_of(pid);
    let mut threads: Vec<(u32, Handle)> = Vec::new();
    for id in ids {
        let thread = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, id) };
        if !thread.is_null() {
            threads.push((id, thread));
        }
    }
    println!("findl       {} threads held open", threads.len());

    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    let mut rounds = 0u64;
    while std::time::Instant::now() < deadline {
        rounds += 1;
        for (id, thread) in &threads {
            unsafe { SuspendThread(*thread) };
            let mut context = vec![0u8; CONTEXT_SIZE];
            unsafe {
                *(context.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL;
            }
            let ok = unsafe { GetThreadContext(*thread, context.as_mut_ptr() as *mut c_void) } != 0;
            let mut regs = [0u64; 15];
            if ok {
                let slots = [
                    0x78usize, 0x80, 0x88, 0x90, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8,
                    0xE0, 0xE8, 0xF0,
                ];
                for (index, slot) in slots.iter().enumerate() {
                    regs[index] = unsafe { *(context.as_ptr().add(*slot) as *const u64) };
                }
            }
            let rip = unsafe { *(context.as_ptr().add(0xF8) as *const u64) };
            unsafe { ResumeThread(*thread) };
            if !ok {
                continue;
            }
            for value in regs {
                if value < 0x10000 || value % 8 != 0 || !seen.insert(value) {
                    continue;
                }
                if read_u8_at(handle, value + LUA_U8_TT) != Some(LUA_TTHREAD) {
                    continue;
                }
                let global = read_u64(handle, value + LUA_U64_GLOBAL);
                let stack = read_u64(handle, value + LUA_U64_STACK);
                let top = read_u64(handle, value + LUA_U64_TOP);
                let ci = read_u64(handle, value + LUA_U64_CI);
                let base_ci = read_u64(handle, value + LUA_U64_BASE_CI);
                let end_ci = read_u64(handle, value + LUA_U64_END_CI);
                let size_ci = read_i32_at(handle, value + LUA_I32_SIZE_CI).unwrap_or(-1);
                if global < 0x10000 || stack < 0x10000 || top <= stack || ci < base_ci {
                    continue;
                }
                if end_ci <= base_ci || ci >= end_ci {
                    continue;
                }
                if !(1..=64).contains(&size_ci) {
                    continue;
                }
                if end_ci - base_ci > 64 * CALLINFO_STRIDE {
                    continue;
                }
                let frames = (ci - base_ci) / CALLINFO_STRIDE;
                println!(
                    "findl       thread {id} rip {} state 0x{value:X} global 0x{global:X} frames {frames}",
                    module_hit(&modules, rip)
                );
                if frames > 0 {
                    let mut frame = ci;
                    let mut found = false;
                    for depth in 0..8u64 {
                        if frame < base_ci {
                            break;
                        }
                        let func = read_u64(handle, frame + CI_U64_FUNC);
                        let fvalue = read_u64(handle, func);
                        let ftag = read_i32_at(handle, func + TVAL_I32_TT).unwrap_or(-1);
                        println!(
                            "findl         frame[{depth}] ci 0x{frame:X} func 0x{func:X} tag {ftag} value 0x{fvalue:X}"
                        );
                        if ftag == LUA_TFUNCTION {
                            if report_closure(handle, &modules, &format!("frame[{depth}]"), fvalue, true) {
                                found = true;
                            }
                        }
                        if frame == base_ci {
                            break;
                        }
                        frame -= CALLINFO_STRIDE;
                    }
                    if found {
                        println!("findl       hit after {rounds} rounds");
                        unsafe { CloseHandle(handle) };
                        return Ok(());
                    }
                }
            }
        }
    }
    println!("findl       no live frame found in {rounds} rounds");
    unsafe { CloseHandle(handle) };
    Ok(())
}

fn find_lclosure(pid: u32, state: u64) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let modules = modules_of(pid);
    let stack = read_u64(handle, state + LUA_U64_STACK);
    let top = read_u64(handle, state + LUA_U64_TOP);
    let base_ci = read_u64(handle, state + LUA_U64_BASE_CI);
    let ci = read_u64(handle, state + LUA_U64_CI);
    println!(
        "lfind       state 0x{state:X} stack 0x{stack:X} top 0x{top:X} depth {}",
        top.wrapping_sub(stack) / 16
    );
    println!("lfind       base_ci 0x{base_ci:X} ci 0x{ci:X}");

    let mut frame = ci;
    let mut seen = 0;
    while frame >= base_ci && frame > 0x10000 && seen < 32 {
        let func = read_u64(handle, frame + CI_U64_FUNC);
        let value = read_u64(handle, func);
        let tt = read_i32_at(handle, func + TVAL_I32_TT).unwrap_or(-1);
        if tt == LUA_TFUNCTION {
            report_closure(handle, &modules, &format!("frame[{seen}]"), value, true);
        } else {
            println!("lfind       frame[{seen}] ci 0x{frame:X} func 0x{func:X} tt {tt} value 0x{value:X}");
        }
        if frame == base_ci {
            break;
        }
        frame = frame.wrapping_sub(CALLINFO_STRIDE);
        seen += 1;
    }

    let span = top.wrapping_sub(stack);
    let last = read_u64(handle, state + LUA_U64_STACK_LAST);
    let scan_end = if last > top && last - stack <= 0x40000 {
        last
    } else {
        stack + span
    };
    let span = scan_end.wrapping_sub(stack);
    if stack > 0x10000 && span > 0 && span <= 0x40000 {
        let Some(bytes) = read_bytes(handle, stack, span as usize) else {
            unsafe { CloseHandle(handle) };
            return Err("stack unreadable".into());
        };
        let mut hits = 0;
        for (index, slot) in bytes.chunks_exact(16).enumerate() {
            let tag = i32::from_le_bytes(slot[12..16].try_into().unwrap());
            if tag != LUA_TFUNCTION {
                continue;
            }
            let value = u64::from_le_bytes(slot[..8].try_into().unwrap());
            if report_closure(handle, &modules, &format!("slot[{index}]"), value, false) {
                hits += 1;
            }
            if hits >= 6 {
                break;
            }
        }
        println!("lfind       stack scan hits {hits}");
    }

    unsafe { CloseHandle(handle) };
    Ok(())
}

fn gc_walk(pid: u32, global: u64) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let Some(page) = read_bytes(handle, global, 0x1000) else {
        unsafe { CloseHandle(handle) };
        return Err("cannot read global_State".into());
    };
    let qword = |bytes: &[u8], off: usize| {
        u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
    };

    let mut candidates: Vec<(usize, u64, u32)> = Vec::new();
    for off in (0..0x1000usize).step_by(8) {
        let head = qword(&page, off);
        if head < 0x10000 {
            continue;
        }
        let mut cursor = head;
        let mut links = 0u32;
        for _ in 0..6 {
            let Some(header) = read_bytes(handle, cursor, 16) else { break };
            let next = qword(&header, 8);
            let tt = header[1];
            if tt > 0x30 {
                break;
            }
            links += 1;
            if next < 0x10000 {
                break;
            }
            cursor = next;
        }
        if links >= 4 {
            candidates.push((off, head, links));
        }
    }
    candidates.sort_by_key(|(_, _, links)| std::cmp::Reverse(*links));
    println!("gcwalk      {} candidate list heads", candidates.len());
    for (off, head, links) in candidates.iter().take(6) {
        println!("gcwalk      global+{off:#05X} head 0x{head:X} chain {links}");
    }
    // The main thread is itself a collector object, so it is always a valid
    // entry point into the all-object list.
    let mainthread = qword(&page, 0x78);
    let entry = match candidates.first().copied() {
        Some((off, head, _)) => {
            println!("gcwalk      using global+{off:#05X}");
            head
        }
        None => {
            println!("gcwalk      falling back to mainthread 0x{mainthread:X}");
            mainthread
        }
    };
    let off = 0usize;
    let head = entry;

    let mut counts = std::collections::BTreeMap::<u8, u32>::new();
    let mut first = std::collections::BTreeMap::<u8, u64>::new();
    let mut cursor = head;
    let mut seen = 0u32;
    while seen < 400_000 {
        let Some(header) = read_bytes(handle, cursor, 16) else { break };
        let next = qword(&header, 8);
        let tt = header[1];
        *counts.entry(tt).or_insert(0) += 1;
        first.entry(tt).or_insert(cursor);
        seen += 1;
        if next < 0x10000 {
            break;
        }
        cursor = next;
    }
    println!("gcwalk      global+{off:#05X} walked {seen} objects");
    for (tt, count) in &counts {
        println!("gcwalk      tt {tt:02X}: {count}");
    }
    for (tt, address) in &first {
        println!("gcwalk      --- tt {tt:02X} first 0x{address:X}");
        if let Some(bytes) = read_bytes(handle, *address, 0x100) {
            for row in 0..16 {
                let chunk = &bytes[row * 16..row * 16 + 16];
                let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02X}")).collect();
                println!("gcwalk      +{:03X}  {}", row * 16, hex.join(" "));
            }
        }
    }
    unsafe { CloseHandle(handle) };
    Ok(())
}

fn vm_info(pid: u32, state: u64) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let modules = modules_of(pid);
    describe_state(handle, &modules, state);
    unsafe { CloseHandle(handle) };
    Ok(())
}

/// One call in a chain. `prepare` runs with the target thread suspended and
/// returns the four Win64 argument registers, or `None` to abort and restore.
struct Step {
    label: &'static str,
    rva: u64,
    absolute: bool,
    prepare: Box<dyn FnMut(Handle) -> Option<[u64; 4]>>,
}

fn write_bytes_at(handle: Handle, address: u64, data: &[u8]) -> bool {
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            handle,
            address as *mut c_void,
            data.as_ptr() as *const c_void,
            data.len(),
            &mut written,
        )
    };
    ok != 0 && written == data.len()
}

fn write_u64_at(handle: Handle, address: u64, value: u64) -> bool {
    write_bytes_at(handle, address, &value.to_le_bytes())
}

/// A stack slot in this VM is a plain 16-byte `TValue`: value at +0, `extra` at
/// +8, type tag at +0xC. Nothing in the tag or the value is VMValue-encoded.
fn write_tvalue(handle: Handle, address: u64, value: u64, tag: i32) -> bool {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&value.to_le_bytes());
    raw[12..].copy_from_slice(&(tag as u32).to_le_bytes());
    write_bytes_at(handle, address, &raw)
}

fn read_cstring(handle: Handle, address: u64, limit: usize) -> Option<String> {
    let bytes = read_bytes(handle, address, limit)?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).to_string())
}

fn read_tstring(handle: Handle, string: u64) -> String {
    if string < 0x10000 {
        return String::new();
    }
    let len = read_u32_at(handle, string + 0x14).unwrap_or(0) as usize;
    let len = len.min(4096);
    match read_bytes(handle, string + 0x18, len) {
        Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        None => String::new(),
    }
}

/// Renders one 16-byte TValue. The client tags strings with 6 in this build,
/// not the 5 the upstream Luau header uses, so both are handled.
fn describe_tvalue(handle: Handle, slot: u64) -> String {
    let value = read_u64(handle, slot);
    let tag = read_i32_at(handle, slot + TVAL_I32_TT).unwrap_or(-1);
    match tag {
        0 => "nil".to_string(),
        1 => format!("boolean raw 0x{value:X} extra 0x{:X}", read_u64(handle, slot + 8)),
        3 => format!("number {}", f64::from_bits(value)),
        4 => format!("vector 0x{value:X}"),
        5 | 6 if value < 0x10000 => format!("string (null) tag {tag}"),
        5 | 6 => {
            let len = read_u32_at(handle, value + 0x14).unwrap_or(u32::MAX);
            match read_bytes(handle, value + 0x18, (len as usize).min(64)) {
                Some(bytes) => format!("string tag {tag} len {len} {:?}", String::from_utf8_lossy(&bytes)),
                None => format!("string tag {tag} 0x{value:X} (unreadable)"),
            }
        }
        8 => format!("function 0x{value:X}"),
        9 => format!("userdata 0x{value:X}"),
        10 => format!("thread 0x{value:X}"),
        other => format!("tag {other} value 0x{value:X}"),
    }
}

/// Walks a thread forward until it lands on the `EB FE` pad, leaving it
/// suspended there so the next step can arm the same thread again.
fn wait_for_park(
    thread: Handle,
    target: u64,
    park: u64,
    stack_top: u64,
    wait_ms: u64,
) -> Option<[u64; 4]> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
    let mut last = (0u64, 0u64);
    let mut first: Option<u64> = None;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(8));
        unsafe { SuspendThread(thread) };
        let mut probe = vec![0u8; CONTEXT_SIZE];
        unsafe { *(probe.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL };
        let ok = unsafe { GetThreadContext(thread, probe.as_mut_ptr() as *mut c_void) } != 0;
        if ok {
            let rip = unsafe { *(probe.as_ptr().add(0xF8) as *const u64) };
            let rsp = unsafe { *(probe.as_ptr().add(0x98) as *const u64) };
            let rax = unsafe { *(probe.as_ptr().add(0x78) as *const u64) };
            last = (rip, rsp);
            if first.is_none() && rip != target {
                first = Some(rip);
            }
            if rip == park && rsp == stack_top {
                return Some([rax, 0, 0, 0]);
            }
        }
        unsafe { ResumeThread(thread) };
        if std::time::Instant::now() >= deadline {
            println!(
                "run         gave up: first non-target rip {first:?} last rip 0x{:X} (target+0x{:X}) rsp 0x{:X} (stack_top 0x{stack_top:X})",
                last.0,
                last.0.wrapping_sub(target),
                last.1
            );
            return None;
        }
    }
}

/// Runs one or more client functions back to back on a hijacked thread.
///
/// Only data is written: a scratch stack plus register values. No code bytes
/// are touched and no new executable region appears, which is the only shape
/// that has survived the client's integrity watch so far. Each call returns
/// onto an `EB FE` pad inside the client's own `.text`, so the thread spins
/// with its stack pointer parked at `stack_top` until the next step is armed.
/// The original context goes back only after the last step.
fn remote_run(pid: u32, mut steps: Vec<Step>, wait_ms: u64) -> Result<u64, String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let modules = modules_of(pid);
    let Some(client) = modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(EXE))
    else {
        unsafe { CloseHandle(handle) };
        return Err("client module not found".into());
    };
    let client_base = client.base;
    let park = client_base + PARK_RVA;
    match read_bytes(handle, park, 2) {
        Some(bytes) if bytes == [0xEB, 0xFE] => {}
        other => {
            unsafe { CloseHandle(handle) };
            return Err(format!("park pad at {PARK_RVA:#X} is not EB FE: {other:?}"));
        }
    }

    let scratch =
        unsafe { VirtualAllocEx(handle, std::ptr::null_mut(), 0x2000, MEM_COMMIT_RESERVE, 0x04) };
    if scratch.is_null() {
        unsafe { CloseHandle(handle) };
        return Err("scratch allocation failed".into());
    }
    let stack_top = scratch as u64 + 0x2000 - 0x10;
    if !write_u64_at(handle, stack_top - 8, park) {
        unsafe {
            CloseHandle(handle);
        }
        return Err("scratch write failed".into());
    }
    println!(
        "run         scratch 0x{:X} park {} target {}",
        scratch as u64,
        module_hit(&modules, park),
        steps
            .iter()
            .map(|step| {
                let target = if step.absolute {
                    step.rva
                } else {
                    client_base + step.rva
                };
                format!("{}={}", step.label, module_hit(&modules, target))
            })
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!(
        "run         base 0x{client_base:X} park_abs 0x{park:X} first_target_abs 0x{:X}",
        match steps.first() {
            Some(step) if step.absolute => step.rva,
            Some(step) => client_base + step.rva,
            None => 0,
        }
    );

    let mut ordered: Vec<(u8, u32)> = threads_of(pid)
        .into_iter()
        .take(64)
        .map(|id| {
            (
                thread_rip(handle, id)
                    .map(|rip| hijack_rank(rip, &modules))
                    .unwrap_or(3),
                id,
            )
        })
        .collect();
    ordered.sort_by_key(|entry| entry.0);

    // A thread blocked in a kernel wait keeps its user RIP frozen and ignores
    // the context we install until it wakes, so take samples twice and put the
    // ones that are actually consuming cycles first.
    let mut candidates: Vec<(bool, u32)> = Vec::new();
    for (rank, id) in ordered.iter().filter(|(rank, _)| *rank <= 2) {
        let _ = rank;
        let first = thread_rip(handle, *id);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = thread_rip(handle, *id);
        let hot = matches!((first, second), (Some(a), Some(b)) if a != b);
        candidates.push((hot, *id));
    }
    candidates.sort_by_key(|(hot, _)| !*hot);
    let candidates: Vec<u32> = candidates.into_iter().map(|(_, id)| id).take(4).collect();
    println!(
        "run         {} candidate threads (hot first)",
        candidates.len()
    );

    let mut last_error = String::from("no thread available");
    let mut done = false;

    for id in candidates {
        let thread = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, id) };
        if thread.is_null() {
            continue;
        }
        unsafe { SuspendThread(thread) };
        let mut original = vec![0u8; CONTEXT_SIZE];
        unsafe { *(original.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL };
        if unsafe { GetThreadContext(thread, original.as_mut_ptr() as *mut c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            };
            continue;
        }
        // Run the call on the thread's own stack. A scratch allocation puts
        // RSP outside every stack range the client knows about, and that is
        // fatal here. The bytes below the thread's current RSP are unused by
        // its live frames, so they are safe to borrow.
        let original_rsp = unsafe { *(original.as_ptr().add(0x98) as *const u64) };
        let resume_rsp = (original_rsp - 0x800) & !0xF;
        let expected_rsp = resume_rsp + 8;
        if !write_u64_at(handle, resume_rsp, park) {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            };
            continue;
        }
        let mut context = original.clone();
        let mut armed = false;
        let mut failure: Option<String> = None;

        for (index, step) in steps.iter_mut().enumerate() {
            let Some(args) = (step.prepare)(handle) else {
                failure = Some(format!("{} aborted in prepare", step.label));
                break;
            };
            let target = if step.absolute {
                step.rva
            } else {
                client_base + step.rva
            };
            arm_context(&mut context, target, resume_rsp, args);
            if unsafe { SetThreadContext(thread, context.as_ptr() as *const c_void) } == 0 {
                failure = Some(format!("{}: SetThreadContext failed", step.label));
                break;
            }
            unsafe { ResumeThread(thread) };
            armed = true;
            if index == 0 && !thread_started(thread, target) {
                failure = Some("frozen, never executed a single instruction".to_string());
                break;
            }
            match wait_for_park(thread, target, park, expected_rsp, wait_ms) {
                Some(registers) => {
                    println!(
                        "run         {} parked, rax 0x{:X} ({})",
                        step.label,
                        registers[0],
                        module_hit(&modules, registers[0])
                    );
                }
                None => {
                    failure = Some(format!("{} never reached the park pad", step.label));
                    break;
                }
            }
            let mut current = vec![0u8; CONTEXT_SIZE];
            unsafe { *(current.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL };
            if unsafe { GetThreadContext(thread, current.as_mut_ptr() as *mut c_void) } != 0 {
                context = current;
            }
        }

        if armed {
            let clean = failure.is_none();
            unsafe {
                SuspendThread(thread);
                if clean {
                    SetThreadContext(thread, original.as_ptr() as *const c_void);
                    ResumeThread(thread);
                } else {
                    // The thread is mid-call. Putting the pre-hijack context
                    // back would resume it inside a half-built Lua frame, and
                    // that is what actually corrupts the client. Park it on the
                    // `EB FE` pad instead and leave it spinning there.
                    let mut parked = vec![0u8; CONTEXT_SIZE];
                    *(parked.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL;
                    if GetThreadContext(thread, parked.as_mut_ptr() as *mut c_void) != 0 {
                        *(parked.as_mut_ptr().add(0xF8) as *mut u64) = park;
                        SetThreadContext(thread, parked.as_ptr() as *const c_void);
                    }
                    ResumeThread(thread);
                    println!(
                        "run         thread {id} left parked, not restored: a mid-frame restore corrupts the client"
                    );
                }
            }
        } else {
            unsafe { ResumeThread(thread) };
        }

        match failure {
            None => {
                println!("run         thread {id} restored");
                unsafe { CloseHandle(thread) };
                done = true;
                break;
            }
            Some(message) => {
                println!("run         thread {id}: {message}");
                last_error = message;
                unsafe { CloseHandle(thread) };
            }
        }
    }

    unsafe { CloseHandle(handle) };
    if done {
        Ok(park)
    } else {
        Err(last_error)
    }
}

/// Writes the four argument registers plus RIP/RSP into a saved CONTEXT.
/// RAX is cleared and RBX left alone so nothing that peeks at them before
/// writing sees a foreign pointer.
fn arm_context(context: &mut [u8], target: u64, rsp: u64, args: [u64; 4]) {
    unsafe {
        *(context.as_mut_ptr().add(0xF8) as *mut u64) = target;
        *(context.as_mut_ptr().add(0x98) as *mut u64) = rsp;
        *(context.as_mut_ptr().add(0x78) as *mut u64) = 0;
        *(context.as_mut_ptr().add(0x80) as *mut u64) = args[0];
        *(context.as_mut_ptr().add(0x88) as *mut u64) = args[1];
        *(context.as_mut_ptr().add(0xB8) as *mut u64) = args[2];
        *(context.as_mut_ptr().add(0xC0) as *mut u64) = args[3];
    }
}

/// Checks whether an armed thread actually executes. Some threads in this
/// client are parked by the anti-tamper logic and never run our context at all,
/// which is indistinguishable from a hang unless the instruction pointer is
/// watched from the very first moment.
fn thread_started(thread: Handle, entry: u64) -> bool {
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        unsafe { SuspendThread(thread) };
        let mut probe = vec![0u8; CONTEXT_SIZE];
        unsafe { *(probe.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL };
        let ok = unsafe { GetThreadContext(thread, probe.as_mut_ptr() as *mut c_void) } != 0;
        let rip = unsafe { *(probe.as_ptr().add(0xF8) as *const u64) };
        unsafe { ResumeThread(thread) };
        if ok && rip != entry {
            return true;
        }
    }
    false
}

fn remote_call(pid: u32, target_rva: u64, args: [u64; 4], wait_ms: u64) -> Result<u64, String> {
    remote_run(
        pid,
        vec![Step {
            label: "xcall",
            rva: target_rva,
            absolute: target_rva >= 0x7FF0_0000_0000,
            prepare: Box::new(move |_handle| Some(args)),
        }],
        wait_ms,
    )
}

/// Calls client functions from a brand new thread instead of stealing one.
///
/// A thread parked inside a kernel wait ignores everything the context API
/// writes, so the only reliable window is a thread that has not started yet.
/// CreateRemoteThread with CREATE_SUSPENDED gives exactly that: a real
/// thread with a real stack, whose very first instruction is ours.
/// Takes over a thread that is provably in user mode.
///
/// Every previous attempt resumed the thread before arming it, and a thread
/// that resumes out of a kernel wait keeps its own trap frame: the context we
/// write is thrown away. The only honest test is to inspect and act inside one
/// suspension, and to require that RIP is inside the client image. A thread
/// sitting in the game module is executing game code, not waiting.
fn hijack_now(
    pid: u32,
    mut steps: Vec<Step>,
    wait_ms: u64,
    limit: usize,
    prefer: Option<u32>,
) -> Result<u64, String> {
    hijack_now_watch(pid, steps, wait_ms, limit, prefer, Vec::new())
}

/// `watch` runs while the thread is still parked after the named step returns,
/// which is the only moment the callee's results are guaranteed to be sitting
/// on a stack nobody else is touching.
fn hijack_now_watch(
    pid: u32,
    mut steps: Vec<Step>,
    wait_ms: u64,
    limit: usize,
    prefer: Option<u32>,
    watch: Vec<(&'static str, Box<dyn Fn(Handle)>)>,
) -> Result<u64, String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let modules = modules_of(pid);
    let Some(client) = modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(EXE))
    else {
        unsafe { CloseHandle(handle) };
        return Err("client module not found".into());
    };
    let client_base = client.base;
    let client_end = client.base + client.size;
    let park = client_base + PARK_RVA;
    match read_bytes(handle, park, 2) {
        Some(bytes) if bytes == [0xEB, 0xFE] => {}
        other => {
            unsafe { CloseHandle(handle) };
            return Err(format!("park pad at {PARK_RVA:#X} is not EB FE: {other:?}"));
        }
    }

    let mut last = String::from("no thread was executing client code");
    let mut done = false;
    let mut attempted = false;
    let scan_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);

    // A thread that was spinning in Luau a heartbeat ago can be asleep in a
    // kernel wait by the time this runs, and none of the others are in the
    // image either. Rescan instead of giving up on the first pass.
    'scan: loop {
    let mut tried = 0usize;
    // The state belongs to one thread. Calling into the VM from any other
    // thread races the owner while it keeps running, which corrupts the stack
    // under our feet - so the owner is the only candidate, always.
    let mut order = match prefer {
        Some(preferred) => vec![preferred],
        None => threads_of(pid),
    };

    for id in order {
        if tried >= limit {
            break;
        }
        let thread = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, id) };
        if thread.is_null() {
            continue;
        }
        unsafe { SuspendThread(thread) };
        let mut original = vec![0u8; CONTEXT_SIZE];
        unsafe { *(original.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL };
        if unsafe { GetThreadContext(thread, original.as_mut_ptr() as *mut c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            };
            continue;
        }
        let rip = unsafe { *(original.as_ptr().add(CONTEXT_RIP_OFFSET) as *const u64) };
        let rsp = unsafe { *(original.as_ptr().add(0x98) as *const u64) };
        if rip < client_base || rip >= client_end || rip == park {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            };
            continue;
        }
        tried += 1;
        attempted = true;
        println!(
            "run         thread {id} executing at {} (rsp 0x{rsp:X})",
            module_hit(&modules, rip)
        );

        // Win64 entry alignment: rsp % 16 == 8 at a function entry. An
        // aligned resume slot makes every SSE spill in the callee fault.
        // The margin is generous: the loader recurses through the parser and
        // the GC, and a shallow slot faults deep inside it.
        let resume_rsp = ((rsp - 0x4000) & !0xF) | 0x8;
        let expected_rsp = resume_rsp + 8;
        if !write_u64_at(handle, resume_rsp, park) {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            };
            continue;
        }
        let mut context = original.clone();
        let mut failure: Option<String> = None;
        for step in steps.iter_mut() {
            let Some(args) = (step.prepare)(handle) else {
                failure = Some(format!("{} aborted in prepare", step.label));
                break;
            };
            let target = if step.absolute {
                step.rva
            } else {
                client_base + step.rva
            };
            arm_context(&mut context, target, resume_rsp, args);
            if unsafe { SetThreadContext(thread, context.as_ptr() as *const c_void) } == 0 {
                failure = Some(format!("{}: SetThreadContext failed", step.label));
                break;
            }
            unsafe { ResumeThread(thread) };
            match wait_for_park(thread, target, park, expected_rsp, wait_ms) {
                Some(registers) => println!(
                    "run         {} parked, rax 0x{:X} ({})",
                    step.label,
                    registers[0],
                    module_hit(&modules, registers[0])
                ),
                None => {
                    failure = Some(format!("{} never reached the park pad", step.label));
                    break;
                }
            }
            for (label, hook) in watch.iter() {
                if *label == step.label {
                    hook(handle);
                }
            }
            let mut current = vec![0u8; CONTEXT_SIZE];
            unsafe { *(current.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL };
            if unsafe { GetThreadContext(thread, current.as_mut_ptr() as *mut c_void) } != 0 {
                context = current;
            }
        }

        unsafe {
            SuspendThread(thread);
            SetThreadContext(thread, original.as_ptr() as *const c_void);
            ResumeThread(thread);
        }
        match failure {
            None => {
                println!("run         thread {id} restored");
                done = true;
                unsafe { CloseHandle(thread) };
                break 'scan;
            }
            Some(message) => {
                println!("run         thread {id}: {message}");
                last = message;
                unsafe { CloseHandle(thread) };
            }
        }
    }
        if done || (prefer.is_none() && attempted) || std::time::Instant::now() >= scan_deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    unsafe { CloseHandle(handle) };
    if done {
        Ok(park)
    } else {
        Err(last)
    }
}

fn remote_thread_run(pid: u32, mut steps: Vec<Step>, wait_ms: u64) -> Result<u64, String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let modules = modules_of(pid);
    let Some(client) = modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(EXE))
    else {
        unsafe { CloseHandle(handle) };
        return Err("client module not found".into());
    };
    let client_base = client.base;
    let park = client_base + PARK_RVA;
    match read_bytes(handle, park, 2) {
        Some(bytes) if bytes == [0xEB, 0xFE] => {}
        other => {
            unsafe { CloseHandle(handle) };
            return Err(format!("park pad at {PARK_RVA:#X} is not EB FE: {other:?}"));
        }
    }

    let exit_thread = {
        let ntdll = unsafe { GetModuleHandleW(wide("ntdll.dll").as_ptr()) };
        if ntdll.is_null() {
            unsafe { CloseHandle(handle) };
            return Err("ntdll not loaded".into());
        }
        let address = unsafe { GetProcAddress(ntdll, b"RtlExitUserThread\0".as_ptr()) };
        if address.is_null() {
            unsafe { CloseHandle(handle) };
            return Err("RtlExitUserThread not found".into());
        }
        address as u64
    };

    let mut thread_id = 0u32;
    let thread = unsafe {
        CreateRemoteThread(
            handle,
            std::ptr::null_mut(),
            0,
            park as *mut c_void,
            std::ptr::null_mut(),
            0x4, // CREATE_SUSPENDED
            &mut thread_id,
        )
    };
    if thread.is_null() {
        unsafe { CloseHandle(handle) };
        return Err(format!("CreateRemoteThread failed ({})", unsafe { GetLastError() }));
    }
    println!(
        "thread      spawned {thread_id}, park {} exit {}",
        module_hit(&modules, park),
        module_hit(&modules, exit_thread)
    );

    let mut original = vec![0u8; CONTEXT_SIZE];
    unsafe { *(original.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL };
    if unsafe { GetThreadContext(thread, original.as_mut_ptr() as *mut c_void) } == 0 {
        unsafe {
            TerminateThread(thread, 1);
            CloseHandle(thread);
            CloseHandle(handle);
        }
        return Err("GetThreadContext on the new thread failed".into());
    }
    let bootstrap_rsp = unsafe { *(original.as_ptr().add(0x98) as *const u64) };

    let mut context = original.clone();
    let mut failure: Option<String> = None;
    for step in steps.iter_mut() {
        let Some(args) = (step.prepare)(handle) else {
            failure = Some(format!("{} aborted in prepare", step.label));
            break;
        };
        let target = if step.absolute {
            step.rva
        } else {
            client_base + step.rva
        };
        let resume_rsp = (bootstrap_rsp - 0x800) & !0xF;
        if !write_u64_at(handle, resume_rsp, park) {
            failure = Some("stack write failed".to_string());
            break;
        }
        arm_context(&mut context, target, resume_rsp, args);
        if unsafe { SetThreadContext(thread, context.as_ptr() as *const c_void) } == 0 {
            failure = Some(format!("{}: SetThreadContext failed", step.label));
            break;
        }
        unsafe { ResumeThread(thread) };
        match wait_for_park(thread, target, park, resume_rsp + 8, wait_ms) {
            Some(registers) => println!(
                "thread      {} parked, rax 0x{:X}",
                step.label, registers[0]
            ),
            None => {
                let mut code = 0u32;
                let got = unsafe { GetExitCodeThread(thread, &mut code) };
                failure = Some(format!(
                    "{} never returned (exit code query {got}, code 0x{code:X})",
                    step.label
                ));
                break;
            }
        }
    }

    // Leave through RtlExitUserThread rather than parking forever: a spinning
    // thread inside the client is a thread the anti-tamper walk can see.
    unsafe {
        arm_context(&mut context, exit_thread, bootstrap_rsp, [0; 4]);
        SetThreadContext(thread, context.as_ptr() as *const c_void);
        ResumeThread(thread);
        WaitForSingleObject(thread, 2000);
        CloseHandle(thread);
        CloseHandle(handle);
    }
    match failure {
        Some(message) => Err(message),
        None => Ok(park),
    }
}

const LUA_D_CALL_RVA: u64 = 0x26361C0;
const LUA_LOAD_RVA: u64 = 0x426A570;
/// `lua_pcall(lua_State*, int nargs, int nresults, int errfunc)`. Found by
/// following `luaB_pcall` at `0x26993D0`, which tail-jumps here after loading
/// `nresults = LUA_MULTRET`. It takes four plain arguments, so unlike
/// `luaD_rawrunprotected` it needs no indirect call and stays inside the CFG.
const LUA_PCALL_RVA: u64 = 0x2631F40;
/// `luaD_rawrunprotected(lua_State*, Pfunc, void*)` — the primitive `lua_pcall`
/// builds on. Its second argument is a function pointer, so it reaches its
/// target through the guard dispatch, which only accepts real function entries.
const LUA_RAWPROT_RVA: u64 = 0x26360B0;
/// The `Pfunc` that `lua_pcall` hands to `luaD_rawrunprotected`: it reads a
/// `CallS { StkId func; int nresults; }` and runs `luaD_call` on it.
const LUA_F_CALL_RVA: u64 = 0x2632230;
const LUA_COMPILE_RVA: u64 = 0x426A1F0;

/// Loads a script with the client's own `luau_load` and runs it through the
/// client's own `pcall` closure, so a script error unwinds through Roblox's
/// handler instead of escaping into the hijacked thread.
fn lua_exec(pid: u32, state: u64, script: &std::path::Path, prefer: Option<u32>) -> Result<(), String> {
    let source = std::fs::read(script).map_err(|e| format!("{}: {e}", script.display()))?;
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }

    // LuaVMLoad(L, const std::string* source, const char* chunkname, int env)
    //   rdx is an MSVC std::string: buffer pointer at +0x0, size at +0x10,
    //   capacity at +0x18, inline buffer 16 bytes when capacity is 15.
    //   Capacity is forced above 15 so the client reads through `[obj+0]`,
    //   which is the branch it takes for anything longer than SSO.
    let source_size = source.len();
    let source_capacity = source_size.max(15) + 1;
    let chunkname = b"=zeno\0";

    let string_slot = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x40, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    };
    let buffer_slot = unsafe {
        VirtualAllocEx(
            handle,
            std::ptr::null_mut(),
            source_size + 1,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        )
    };
    let name_slot = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x20, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    };
    if string_slot.is_null() || buffer_slot.is_null() || name_slot.is_null() {
        unsafe { CloseHandle(handle) };
        return Err("argument allocation failed".into());
    }

    let mut descriptor = vec![0u8; 0x20];
    descriptor[0x0..0x8].copy_from_slice(&(buffer_slot as u64).to_le_bytes());
    descriptor[0x10..0x18].copy_from_slice(&(source_size as u64).to_le_bytes());
    descriptor[0x18..0x20].copy_from_slice(&(source_capacity as u64).to_le_bytes());

    let string_ok = write_bytes_at(handle, string_slot as u64, &descriptor);
    let buffer_ok = write_bytes_at(handle, buffer_slot as u64, &source);
    let name_ok = write_bytes_at(handle, name_slot as u64, chunkname);
    if !string_ok || !buffer_ok || !name_ok {
        unsafe { CloseHandle(handle) };
        return Err("argument write failed".into());
    }
    println!(
        "exec        staged string 0x{:X} -> buffer 0x{:X} ({source_size} bytes, cap {source_capacity}) name 0x{:X}",
        string_slot as u64, buffer_slot as u64, name_slot as u64
    );
    if let Some(client) = modules_of(pid).iter().find(|m| m.name.eq_ignore_ascii_case(EXE)) {
        println!(
            "exec        loader compile-flag byte {}",
            read_u8_at(handle, client.base + 0x81967B0).unwrap_or(0xFF)
        );
    }

    let slot = std::rc::Rc::new(std::cell::Cell::new(0u64));

    let mut steps: Vec<Step> = Vec::new();
    // The loader takes a container, not source: eight magic bytes followed by
    // raw Luau bytecode. A leaf call parks first so a failure here is
    // unambiguous about which side is broken.
    let sleep_address = {
        let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
        if kernel32.is_null() {
            0
        } else {
            unsafe { GetProcAddress(kernel32, b"Sleep\\0".as_ptr()) as u64 }
        }
    };
    println!("exec        leaf target 0x{sleep_address:X}");
    if sleep_address != 0 {
        steps.push(Step {
            label: "probe_sleep",
            rva: sleep_address,
            absolute: true,
            prepare: Box::new(|_handle| Some([1, 0, 0, 0])),
        });
    }
    steps.push(Step {
        label: "luau_load",
        rva: LUA_LOAD_RVA,
        absolute: false,
        prepare: Box::new(move |_handle| {
            println!("exec        loading {source_size} bytes at 0x{:X}", string_slot as u64);
            Some([state, string_slot as u64, name_slot as u64, 0])
        }),
    });
    let call_slot = slot.clone();
    let result_slot = slot.clone();
    steps.push(Step {
        label: "luaD_call",
        rva: LUA_D_CALL_RVA,
        absolute: false,
        prepare: Box::new(move |handle| {
            if no_exec_requested() {
                println!("exec        noexec set, skipping the call");
                return None;
            }
            let top = read_u64_checked(handle, state + LUA_U64_TOP)?;
            if top < 32 {
                println!("exec        top 0x{top:X} is implausible");
                return None;
            }
            let function_slot = top - 16;
            let value = read_u64(handle, function_slot);
            let tag = read_i32_at(handle, function_slot + TVAL_I32_TT).unwrap_or(-1);
            let global = read_u64(handle, state + LUA_U64_GLOBAL);
            let pcall = read_u64(handle, global + G_U64_BUILTIN_PCALL);
            println!(
                "exec        load left top 0x{top:X}, slot 0x{function_slot:X}, tag {tag}, value 0x{value:X}, pcall 0x{pcall:X}"
            );
            if tag == 4 {
                println!("exec        compile error: {}", read_tstring(handle, value));
                return None;
            }
            if tag != LUA_TFUNCTION {
                return None;
            }
            // Call the chunk directly. Wrapping it in the builtin `pcall` adds a
            // second unknown (the builtin's own calling convention) on top of the
            // bytecode, and this chunk cannot throw.
            if !write_tvalue(handle, function_slot, value, LUA_TFUNCTION) {
                return None;
            }
            // This client's VM has a native-code path: `luau_precall` tags the
            // frame as native when `proto->exectarget != 0 && proto->execdata`
            // and then dispatches through a JIT entry instead of the
            // interpreter. Bytecode protos must leave both fields null. If the
            // loader left anything behind them, the dispatch lands on a bad
            // pointer and the CFG guard fires `int 0x29`. Force the interpreter.
            let proto = read_u64(handle, value + 0x18);
            if proto > 0x10000 {
                let target = read_u64(handle, proto + 0x8);
                let data = read_u64(handle, proto + 0x10);
                if target != 0 || data != 0 {
                    println!(
                        "exec        clearing native entry proto 0x{proto:X} exectarget 0x{target:X} execdata 0x{data:X}"
                    );
                    let _ = write_u64_at(handle, proto + 0x8, 0);
                    let _ = write_u64_at(handle, proto + 0x10, 0);
                }
            }
            if !write_u64_at(handle, state + LUA_U64_TOP, function_slot + 16) {
                return None;
            }
            call_slot.set(function_slot);
            Some([state, function_slot, u64::MAX, 0])
        }),
    });

    let outcome = hijack_now_watch(
        pid,
        steps,
        20000,
        10,
        prefer,
        vec![
            (
                "luau_load",
                Box::new(move |handle| {
                    let top = read_u64(handle, state + LUA_U64_TOP);
                    let closure = read_u64(handle, top - 16);
                    println!("exec        closure 0x{closure:X}");
                    if let Some(head) = read_bytes(handle, closure, 0x80) {
                        for row in 0..8 {
                            let chunk = &head[row * 16..row * 16 + 16];
                            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02X}")).collect();
                            println!("exec        closure+{:02X}: {}", row * 16, hex.join(" "));
                        }
                    }
                    for off in (0..0x80u64).step_by(8) {
                        let candidate = read_u64(handle, closure + off);
                        if candidate < 0x10000 {
                            continue;
                        }
                        let sizecode = read_i32_at(handle, candidate + PROTO_I32_SIZECODE).unwrap_or(-1);
                        let code = read_u64(handle, candidate + PROTO_U64_CODE);
                        if code < 0x10000 || !(0..=4096).contains(&sizecode) {
                            continue;
                        }
                        let Some(words) = read_bytes(handle, code, 0x800) else { continue };
                        let take = ((sizecode as usize) * 4).min(words.len());
                        let hex: Vec<String> =
                            words[..take].iter().map(|b| format!("{b:02X}")).collect();
                        println!(
                            "exec        proto via +{off:02X} 0x{candidate:X} sizecode {sizecode} code 0x{code:X} [{}]",
                            hex.join(" ")
                        );
                        let k = read_u64(handle, candidate + 0x60);
                        if k >= 0x10000 {
                            let mut line = String::new();
                            for slot in 0..4u64 {
                                let text = describe_tvalue(handle, k + slot * 16);
                                line.push_str(&format!("k[{slot}]={text} "));
                            }
                            println!("exec        consts {line}");
                        }
                        for field in [0x50u64, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80] {
                            let p = read_u64(handle, candidate + field);
                            if p < 0x10000 {
                                println!("exec        proto+{field:02X} = 0x{p:X} (small)");
                                continue;
                            }
                            match read_bytes(handle, p, 0x20) {
                                Some(head) => {
                                    let hx: Vec<String> =
                                        head.iter().map(|b| format!("{b:02X}")).collect();
                                    println!("exec        proto+{field:02X} -> 0x{p:X} [{}]", hx.join(" "));
                                }
                                None => println!("exec        proto+{field:02X} -> 0x{p:X} (unreadable)"),
                            }
                        }
                    }
                }),
            ),
            (
                "luaD_call",
                Box::new(move |handle| {
                    let base = result_slot.get();
                    let top = read_u64(handle, state + LUA_U64_TOP);
                    println!(
                        "exec        capture base 0x{base:X} top 0x{top:X} delta 0x{:X}",
                        top.wrapping_sub(base)
                    );
                    let l_base = read_u64(handle, state + 0x58);
                    let ci = read_u64(handle, state + 0x70);
                    let stack = read_u64(handle, state + LUA_U64_STACK);
                    let last = read_u64(handle, state + LUA_U64_STACK_LAST);
                    let status = read_bytes(handle, state, 8)
                        .map(|b| b.iter().map(|v| format!("{v:02X}")).collect::<Vec<_>>().join(" "))
                        .unwrap_or_default();
                    println!(
                        "exec        state base 0x{l_base:X} ci 0x{ci:X} stack 0x{stack:X} last 0x{last:X} hdr {status}"
                    );
                    for back in 1..=8u64 {
                        let slot = top - 0x10 * back;
                        println!("exec        top-{back} 0x{slot:X} {}", describe_tvalue(handle, slot));
                    }
                    let mut cursor = base;
                    let mut index = 0;
                    while cursor + 16 <= top && index < 40 {
                        println!("exec        out[{index}] {}", describe_tvalue(handle, cursor));
                        cursor += 16;
                        index += 1;
                    }
                }),
            ),
        ],
    );
    let base = slot.get();

    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if !handle.is_null() && handle != -1isize as Handle {
        // The host thread was suspended with its own top; put it back.
        if base != 0 {
            write_u64_at(handle, state + LUA_U64_TOP, base);
        }
        unsafe { CloseHandle(handle) };
    }
    outcome.map(|_| ())
}

const PROBE_MAGIC: [u8; 8] = [0x52, 0x7A, 0x10, 0x4A, 0x5B, 0x32, 0x09, 0xE0];

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// The loader behind this client's `LuaVMLoad` takes a container: eight magic
/// bytes, then a version-14 Luau blob with one proto. Everything after
/// `protoSize` is skipped, so a one-instruction proto stays tiny.
fn probe_blob(words: &[u32], maxstack: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[maxstack, 0, 0, 0, 0]);
    write_varint(&mut body, 0); // typesize
    write_varint(&mut body, words.len() as u64);
    for word in words {
        body.extend_from_slice(&word.to_le_bytes());
    }
    write_varint(&mut body, 0); // sizek
    write_varint(&mut body, 0); // sizep
    write_varint(&mut body, 0); // linedefined
    write_varint(&mut body, 0); // debugname
    body.push(0); // lineinfo
    body.push(0); // debuginfo
    write_varint(&mut body, 0); // feedback vector size

    let mut blob = Vec::new();
    blob.extend_from_slice(&PROBE_MAGIC);
    blob.extend_from_slice(&[14, 3]);
    write_varint(&mut blob, 0); // string count
    blob.push(0); // userdata remap terminator
    write_varint(&mut blob, 1); // proto count
    write_varint(&mut blob, body.len() as u64);
    blob.extend_from_slice(&body);
    write_varint(&mut blob, 0); // main proto id
    blob
}

/// Loads one one-instruction chunk per encoded byte and reads the proto back.
/// The loader rewrites the opcode byte in place, so a successful load yields the
/// encoded -> dispatch byte the VM actually dispatches on. Nothing is executed.
fn lua_scan(pid: u32, state: u64, prefer: Option<u32>) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let blob_slot = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x40, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    };
    let string_slot = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x40, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    };
    let name_slot = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x20, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    };
    if blob_slot.is_null() || string_slot.is_null() || name_slot.is_null() {
        unsafe { CloseHandle(handle) };
        return Err("probe allocation failed".into());
    }

    let template = probe_blob(&[0], 3);
    let size = template.len();
    let capacity = size + 1;
    let mut descriptor = vec![0u8; 0x20];
    descriptor[0x0..0x8].copy_from_slice(&(blob_slot as u64).to_le_bytes());
    descriptor[0x10..0x18].copy_from_slice(&(size as u64).to_le_bytes());
    descriptor[0x18..0x20].copy_from_slice(&(capacity as u64).to_le_bytes());
    if !write_bytes_at(handle, string_slot as u64, &descriptor)
        || !write_bytes_at(handle, name_slot as u64, b"=scan\0")
    {
        unsafe { CloseHandle(handle) };
        return Err("probe descriptor write failed".into());
    }
    println!("scan        blob {size} bytes, blob slot 0x{:X}", blob_slot as u64);

    let cursor = std::rc::Rc::new(std::cell::Cell::new(0u8));
    let top_before = std::rc::Rc::new(std::cell::Cell::new(0u64));
    let mut steps: Vec<Step> = Vec::new();
    for byte in 0u8..=255 {
        let shape = probe_blob(&[byte as u32], 3);
        let cursor = cursor.clone();
        let top_before = top_before.clone();
        steps.push(Step {
            label: "scan",
            rva: LUA_LOAD_RVA,
            absolute: false,
            prepare: Box::new(move |handle| {
                if !write_bytes_at(handle, blob_slot as u64, &shape) {
                    return None;
                }
                cursor.set(byte);
                top_before.set(read_u64(handle, state + LUA_U64_TOP));
                Some([state, string_slot as u64, name_slot as u64, 0])
            }),
        });
    }

    let watch_cursor = cursor.clone();
    let watch_top = top_before.clone();
    let result = hijack_now_watch(
        pid,
        steps,
        20000,
        10,
        prefer,
        vec![(
            "scan",
            Box::new(move |handle| {
                let byte = watch_cursor.get();
                let top = read_u64(handle, state + LUA_U64_TOP);
                let slot = top.wrapping_sub(16);
                let value = read_u64(handle, slot);
                let tag = read_i32_at(handle, slot + TVAL_I32_TT).unwrap_or(-1);
                if tag == LUA_TFUNCTION {
                    let mut rendered = String::from("no proto");
                    for off in (0..0x80u64).step_by(8) {
                        let candidate = read_u64(handle, value + off);
                        if candidate < 0x10000 {
                            continue;
                        }
                        let sizecode =
                            read_i32_at(handle, candidate + PROTO_I32_SIZECODE).unwrap_or(-1);
                        let code = read_u64(handle, candidate + PROTO_U64_CODE);
                        if code < 0x10000 || sizecode != 1 {
                            continue;
                        }
                        if let Some(words) = read_bytes(handle, code, 8) {
                            let word = u32::from_le_bytes(words[0..4].try_into().unwrap());
                            rendered = format!("word 0x{word:08X} (low 0x{:02X})", word & 0xFF);
                        }
                        break;
                    }
                    println!("scan        0x{byte:02X} -> {rendered}");
                } else {
                    let text = if tag == 5 { read_tstring(handle, value) } else { String::new() };
                    println!("scan        0x{byte:02X} rejected tag {tag} {text}");
                }
                let before = watch_top.get();
                if before >= 0x10000 {
                    write_u64_at(handle, state + LUA_U64_TOP, before);
                }
            }),
        )],
    );
    unsafe { CloseHandle(handle) };
    result.map(|_| ())
}

/// Probe blob for a single canonical opcode byte.
///
/// Four `LOADN`s seed R0..R3 with known numbers, then the candidate runs, then a
/// zero word, then `RETURN R0,4`. Canonical 0x00 is `NOP` and one word wide, so
/// that zero word is either the candidate's aux or a harmless filler, and a
/// branch with a zero displacement falls through to it instead of looping. The
/// constant table is seeded so an operand reading `k[0]` sees a number instead
/// of a wild pointer.
fn classify_blob(canonical: u8) -> Vec<u8> {
    const OP_LOADN: u32 = 0x8C;
    const OP_RETURN: u32 = 0x82;
    let loadn = |a: u32, d: u32| OP_LOADN | (a << 8) | (d << 16);
    let words = [
        loadn(0, 7),
        loadn(1, 9),
        loadn(2, 0),
        loadn(3, 0),
        canonical as u32,
        0,
        OP_RETURN | (0 << 8) | (5 << 16),
    ];

    let mut body = Vec::new();
    body.extend_from_slice(&[8, 0, 0, 0, 0]);
    write_varint(&mut body, 0); // typesize
    write_varint(&mut body, words.len() as u64);
    for word in words {
        body.extend_from_slice(&word.to_le_bytes());
    }
    write_varint(&mut body, 4); // sizek
    body.push(2); // number
    body.extend_from_slice(&7.0f64.to_le_bytes());
    body.push(2);
    body.extend_from_slice(&9.0f64.to_le_bytes());
    body.push(3);
    write_varint(&mut body, 1); // string, table index 1
    body.push(1); // boolean
    body.push(1);
    write_varint(&mut body, 0); // sizep
    write_varint(&mut body, 0); // linedefined
    write_varint(&mut body, 0); // debugname
    body.push(0); // lineinfo
    body.push(0); // debuginfo
    write_varint(&mut body, 0); // feedback vector size

    let mut blob = Vec::new();
    blob.extend_from_slice(&PROBE_MAGIC);
    blob.extend_from_slice(&[14, 3]);
    write_varint(&mut blob, 1); // string count
    write_varint(&mut blob, 4);
    blob.extend_from_slice(b"zeno");
    blob.push(0); // userdata remap terminator
    write_varint(&mut blob, 1); // proto count
    write_varint(&mut blob, body.len() as u64);
    blob.extend_from_slice(&body);
    write_varint(&mut blob, 0); // main proto id
    blob
}

/// Runs one candidate opcode per chunk, each wrapped in the client's own
/// `pcall`, and prints the registers it left behind or the error it raised.
/// The error text is the classification: "attempt to index" is a table read,
/// "attempt to compare" is a branch, and a clean return means the instruction
/// only touched its own registers.
fn lua_classify(
    pid: u32,
    state: u64,
    from: u8,
    to: u8,
    prefer: Option<u32>,
) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }
    let candidates: Vec<u8> = (from..=to).collect();
    let count = candidates.len();

    // A direct `luaD_call` runs the chunk unprotected, so one raising opcode
    // unwinds the hijacked thread and takes the client with it. `lua_pcall`
    // wraps the same call in `luaD_rawrunprotected`, so a raise comes back as a
    // status and an error value instead. That is the only way to sweep all 94
    // opcodes without losing the client on the first one that errors.
    let protected = std::env::var("ZENO_PCALL").is_ok();

    let blob_region = unsafe {
        VirtualAllocEx(
            handle,
            std::ptr::null_mut(),
            count * 0x400,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        )
    };
    let desc_region = unsafe {
        VirtualAllocEx(
            handle,
            std::ptr::null_mut(),
            count * 0x20,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        )
    };
    let name_slot = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x20, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    };
    if blob_region.is_null() || desc_region.is_null() || name_slot.is_null() {
        unsafe { CloseHandle(handle) };
        return Err("argument allocation failed".into());
    }
    let blob_base = blob_region as u64;
    let desc_base = desc_region as u64;

    for (index, canonical) in candidates.iter().enumerate() {
        let blob = classify_blob(*canonical);
        let slot = blob_base + (index as u64) * 0x400;
        if !write_bytes_at(handle, slot, &blob) {
            unsafe { CloseHandle(handle) };
            return Err("blob write failed".into());
        }
        let mut descriptor = vec![0u8; 0x20];
        descriptor[0x0..0x8].copy_from_slice(&slot.to_le_bytes());
        descriptor[0x10..0x18].copy_from_slice(&(blob.len() as u64).to_le_bytes());
        descriptor[0x18..0x20].copy_from_slice(&(blob.len() as u64 + 1).to_le_bytes());
        if !write_bytes_at(handle, desc_base + (index as u64) * 0x20, &descriptor) {
            unsafe { CloseHandle(handle) };
            return Err("descriptor write failed".into());
        }
    }
    if !write_bytes_at(handle, name_slot as u64, b"=zeno\0") {
        unsafe { CloseHandle(handle) };
        return Err("name write failed".into());
    }

    println!("classify    {} candidates 0x{from:02X}..0x{to:02X}", count);

    let index = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let call_slot = std::rc::Rc::new(std::cell::Cell::new(0u64));

    // `lua_pcall` is a wrapper, and that wrapper is what misbehaves here: it
    // leaves the state's status set and a CallInfo pushed, so the frame it ran
    // never comes back. `luaD_rawrunprotected` is the primitive underneath, so
    // drive it directly with the same `f_call` thunk and a `CallS` of our own.
    let rawprot = std::env::var("ZENO_RAWPROT").is_ok();
    let calls_region = if rawprot {
        let region = unsafe {
            VirtualAllocEx(
                handle,
                std::ptr::null_mut(),
                0x20,
                MEM_COMMIT_RESERVE,
                PAGE_READWRITE,
            )
        };
        if region.is_null() {
            unsafe { CloseHandle(handle) };
            return Err("call struct allocation failed".into());
        }
        region as u64
    } else {
        0
    };
    let saved = std::rc::Rc::new(std::cell::Cell::new([0u64; 4]));

    let mut steps: Vec<Step> = Vec::new();
    for (position, _) in candidates.iter().enumerate() {
        let descriptor = desc_base + (position as u64) * 0x20;
        steps.push(Step {
            label: "luau_load",
            rva: LUA_LOAD_RVA,
            absolute: false,
            prepare: Box::new(move |_handle| Some([state, descriptor, name_slot as u64, 0])),
        });
        let slot_cell = call_slot.clone();
        let saved_cell = saved.clone();
        let call_label: &'static str = if rawprot {
            "rawprot"
        } else if protected {
            "lua_pcall"
        } else {
            "luaD_call"
        };
        let call_rva = if rawprot {
            LUA_RAWPROT_RVA
        } else if protected {
            LUA_PCALL_RVA
        } else {
            LUA_D_CALL_RVA
        };
        steps.push(Step {
            label: call_label,
            rva: call_rva,
            absolute: false,
            prepare: Box::new(move |handle| {
                if no_exec_requested() {
                    return None;
                }
                let top = read_u64_checked(handle, state + LUA_U64_TOP)?;
                if top < 64 {
                    return None;
                }
                let Some(closure) = read_bytes(handle, top - 16, 16) else {
                    return None;
                };
                // Every entry point keeps the chunk closure in the slot the
                // loader left it in and `top` just past it. They differ only in
                // what the second register carries: a slot, an argument count,
                // or a function pointer.
                let slot = top - 16;
                if !write_bytes_at(handle, slot, &closure) {
                    return None;
                }
                if !write_u64_at(handle, state + LUA_U64_TOP, top) {
                    return None;
                }
                // The protected call grows the stack, and a grown stack is a
                // reallocated one: the address we arm is stale by the time the
                // call returns. Carry the slot's offset from the stack instead
                // and rebase it on the new stack when reading results.
                let stack = read_u64(handle, state + LUA_U64_STACK);
                if std::env::var("ZENO_STACK").is_ok() {
                    let last = read_u64(handle, state + LUA_U64_STACK_LAST);
                    let base = read_u64(handle, state + 0x58);
                    let status = read_u8_at(handle, state + LUA_U8_STATUS).unwrap_or(0xFF);
                    let ncalls = read_u16_at(handle, state + 0x38).unwrap_or(0);
                    let ci = read_u64(handle, state + 0x70);
                    let is_c = read_u8_at(handle, read_u64(handle, slot) + CLOSURE_U8_IS_C);
                    println!(
                        "classify   prep top 0x{top:X} slot 0x{slot:X} base 0x{base:X} stack 0x{stack:X} last 0x{last:X} status {status} ncalls {ncalls} ci 0x{ci:X} isC {is_c:?}"
                    );
                    println!("classify   prep slot[0] {}", describe_tvalue(handle, slot));
                    println!("classify   prep slot[1] {}", describe_tvalue(handle, slot + 16));
                }
                slot_cell.set(slot.wrapping_sub(stack));
                if rawprot {
                    if !write_u64_at(handle, calls_region, slot) {
                        return None;
                    }
                    if !write_u64_at(handle, calls_region + 8, u64::MAX) {
                        return None;
                    }
                    // A raise leaves the CallInfo chain and the status byte
                    // dirty, so remember them before the call and put them back
                    // afterwards. `luaD_pcall` does the same on its error path.
                    saved_cell.set([
                        read_u64(handle, state + 0x70),
                        read_u64(handle, state + 0x58),
                        top,
                        read_u8_at(handle, state + LUA_U8_STATUS).unwrap_or(0) as u64,
                    ]);
                    return Some([state, LUA_F_CALL_RVA, calls_region, 0]);
                }
                Some(if protected {
                    [state, 0, u64::MAX, 0]
                } else {
                    [state, slot, u64::MAX, 0]
                })
            }),
        });
    }

    let watch_index = index.clone();
    let watch_slot = call_slot.clone();
    let watch_saved = saved.clone();
    let watch_candidates = candidates.clone();
    let watch_label: &'static str = if rawprot {
        "rawprot"
    } else if protected {
        "lua_pcall"
    } else {
        "luaD_call"
    };
    let outcome = hijack_now_watch(
        pid,
        steps,
        20000,
        10,
        prefer,
        vec![(
            watch_label,
            Box::new(move |handle| {
                let current = watch_index.get();
                let canonical = watch_candidates.get(current).copied().unwrap_or(0xFF);
                // A raise unwinds past `luaD_call` and leaves the CallInfo chain
                // and the status byte pointing at the dead frame. Put back what
                // the call started with before anything else touches the state.
                if rawprot {
                    let status = read_u8_at(handle, state + LUA_U8_STATUS).unwrap_or(0);
                    if status != 0 {
                        let before = watch_saved.get();
                        write_u64_at(handle, state + 0x70, before[0]);
                        write_u64_at(handle, state + 0x58, before[1]);
                        write_u64_at(handle, state + LUA_U64_TOP, before[2]);
                        write_bytes_at(handle, state + LUA_U8_STATUS, &[before[3] as u8]);
                        println!("classify   0x{canonical:02X} -> raised, status {status} restored");
                        watch_index.set(current + 1);
                        return;
                    }
                }
                // The armed address is only valid until the call grows the
                // stack. Rebase the offset we stored at arm time onto whatever
                // stack the state holds now, and read the six result slots from
                // there. A fresh stack with an out-of-range offset means the
                // call never ran, so fall back to the raw armed address.
                let stack = read_u64(handle, state + LUA_U64_STACK);
                let last = read_u64(handle, state + LUA_U64_STACK_LAST);
                let base = read_u64(handle, state + 0x58);
                let offset = watch_slot.get();
                let rebased = stack.wrapping_add(offset);
                let slot = if offset < 0x4000 && rebased >= stack && rebased < last {
                    rebased
                } else {
                    offset
                };
                let mut rendered = Vec::new();
                for index in 0..6u64 {
                    rendered.push(describe_tvalue(handle, slot + index * 16));
                }
                println!("classify   0x{canonical:02X} -> {}", rendered.join(" | "));
                if std::env::var("ZENO_STACK").is_ok() {
                    let top = read_u64(handle, state + LUA_U64_TOP);
                    let status = read_u8_at(handle, state + LUA_U8_STATUS).unwrap_or(0xFF);
                    let ncalls = read_u16_at(handle, state + 0x38).unwrap_or(0);
                    let ci = read_u64(handle, state + 0x70);
                    println!(
                        "classify       stack 0x{stack:X} last 0x{last:X} base 0x{base:X} top 0x{top:X} off 0x{offset:X} used 0x{slot:X} status {status} ncalls {ncalls} ci 0x{ci:X}"
                    );
                    let mut cursor = slot.saturating_sub(0x20);
                    while cursor + 16 <= last && cursor < slot + 0x60 {
                        println!(
                            "classify       [{:03X}] {}",
                            cursor.wrapping_sub(slot),
                            describe_tvalue(handle, cursor)
                        );
                        cursor += 16;
                    }
                }
                watch_index.set(current + 1);
            }),
        )],
    );
    unsafe { CloseHandle(handle) };
    outcome.map(|_| ())
}

fn image_test(
    pid: u32,
    dll: &std::path::Path,
    opts: ImageOpts,
) -> Result<(), String> {
    let absolute = std::fs::canonicalize(dll).map_err(|e| format!("{}: {e}", dll.display()))?;
    let file = std::fs::read(dll).map_err(|e| format!("{}: {e}", dll.display()))?;
    let ping_rva = match map::export_rva(&file, "zeno_ping") {
        Some(rva) => rva,
        None if !opts.exec => 0,
        None => return Err("zeno_ping export not found in payload".into()),
    };
    println!("imagetest   zeno_ping rva 0x{ping_rva:X}");

    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
    }

    let wide_path = wide(&absolute.to_string_lossy());
    let file_handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            0x8000_0000, // GENERIC_READ
            0x0000_0007, // FILE_SHARE_READ | WRITE | DELETE
            std::ptr::null_mut(),
            3,    // OPEN_EXISTING
            0x80, // FILE_ATTRIBUTE_NORMAL
            std::ptr::null_mut(),
        )
    };
    if file_handle.is_null() || file_handle == (-1isize) as Handle {
        unsafe { CloseHandle(handle) };
        return Err("CreateFileW failed".into());
    }

    let mut section: Handle = std::ptr::null_mut();
    let mut max_size: i64 = 0;
    let status = unsafe {
        NtCreateSection(
            &mut section,
            0x000F_001F, // SECTION_ALL_ACCESS
            std::ptr::null_mut(),
            &mut max_size,
            0x02,        // PAGE_READONLY
            0x0100_0000, // SEC_IMAGE
            file_handle,
        )
    };
    unsafe { CloseHandle(file_handle) };
    if status != 0 {
        unsafe { CloseHandle(handle) };
        return Err(format!("NtCreateSection failed 0x{:X}", status as u32));
    }

    let mut base: *mut c_void = std::ptr::null_mut();
    let mut size: usize = 0;
    let status = unsafe {
        NtMapViewOfSection(
            section,
            handle,
            &mut base,
            0,
            0,
            std::ptr::null_mut(),
            &mut size,
            1, // ViewShare
            0, // allocation type must be zero for image views
            0x02, // PAGE_READONLY; the section already carries the image's own rights
        )
    };
    unsafe { NtClose(section) };
    if status != 0 {
        unsafe { CloseHandle(handle) };
        return Err(format!("NtMapViewOfSection failed 0x{:X}", status as u32));
    }
    println!(
        "imagetest   mapped at 0x{:X}, view size 0x{size:X}, ping at 0x{:X}",
        base as u64,
        base as u64 + ping_rva as u64
    );

    // The loader is not involved in this mapping, so every IAT slot is still
    // whatever the linker left there. Fill them from this process: system
    // modules sit at the same addresses in both processes.
    let mut resolved = 0usize;
    let mut failed: Vec<String> = Vec::new();
    let mut protected: Vec<u64> = Vec::new();
    let mapped = base as u64;
    if opts.load {
        for import in map::import_table(&file)? {
        let library = wide(&import.library);
        let module = unsafe { GetModuleHandleW(library.as_ptr()) };
        if module.is_null() {
            failed.push(format!("{} missing", import.library));
            continue;
        }
        let address = match &import.name {
            Some(name) => {
                let mut owned = name.clone().into_bytes();
                owned.push(0);
                unsafe { GetProcAddress(module, owned.as_ptr()) as u64 }
            }
            None => unsafe {
                GetProcAddress(module, import.ordinal as usize as *const u8) as u64
            },
        };
        if address == 0 {
            failed.push(format!(
                "{}!{}",
                import.library,
                import
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("#{}", import.ordinal))
            ));
            continue;
        }
        let slot = mapped + import.iat_rva as u64;
        let page = slot & !0xFFF;
        if !protected.contains(&page) {
            let mut old = 0u32;
            unsafe {
                VirtualProtectEx(handle, page as *mut c_void, 0x1000, 0x04, &mut old)
            };
            protected.push(page);
        }
        let mut written = 0usize;
        unsafe {
            WriteProcessMemory(
                handle,
                slot as *mut c_void,
                &address as *const u64 as *const c_void,
                8,
                &mut written,
            )
        };
        resolved += 1;
    }
    }
    println!(
        "imagetest   imports {resolved} resolved, {} failed{}",
        failed.len(),
        if failed.is_empty() {
            String::new()
        } else {
            format!(" ({})", failed.join(", "))
        }
    );

    let ping_rva = match map::export_rva(&file, "zeno_run") {
        Some(rva) => rva,
        None => ping_rva,
    };
    println!("imagetest   calling 0x{:X}", base as u64 + ping_rva as u64);

    if opts.link {
        let pe = u32::from_le_bytes(file[0x3C..0x40].try_into().unwrap()) as usize;
        let entry_point =
            u32::from_le_bytes(file[pe + 24 + 16..pe + 24 + 20].try_into().unwrap());
        if let Err(error) = link_module(
            handle,
            base as u64,
            size as u32,
            entry_point,
            &absolute.to_string_lossy(),
        ) {
            println!("imagetest   link failed: {error}");
        }
    }

    // Mapping-only mode: never touch a thread, just watch. This separates
    // "the view itself is detected" from "executing out of the view is
    // detected", which is the only open question left.
    if !opts.exec {
        for step in 1..=12 {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let alive = unsafe { WaitForSingleObject(handle, 0) } != 0;
            println!(
                "imagetest   t+{}s client {}",
                step * 5,
                if alive { "alive" } else { "DIED" }
            );
            if !alive {
                break;
            }
        }
        unsafe { CloseHandle(handle) };
        return Ok(());
    }

    let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
    let park = unsafe { GetProcAddress(kernel32, b"SleepEx\0".as_ptr()) } as u64;

    let block = unsafe {
        VirtualAllocEx(handle, std::ptr::null_mut(), 0x2000, MEM_COMMIT_RESERVE, 0x04)
    };
    if block.is_null() {
        unsafe { CloseHandle(handle) };
        return Err("VirtualAllocEx for the fake stack failed".into());
    }
    let stack_top = block as u64 + 0x2000 - 0x10;
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(
            handle,
            (stack_top - 8) as *mut c_void,
            &park as *const u64 as *const c_void,
            8,
            &mut written,
        )
    };

    let modules = modules_of(pid);
    let mut ordered: Vec<(u8, u32)> = threads_of(pid)
        .iter()
        .take(64)
        .map(|id| {
            (
                thread_rip(handle, *id)
                    .map(|rip| hijack_rank(rip, &modules))
                    .unwrap_or(3),
                *id,
            )
        })
        .collect();
    ordered.sort_by_key(|entry| entry.0);

    for (rank, id) in ordered.iter().take(2) {
        if *rank > 2 {
            break;
        }
        let thread = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, *id) };
        if thread.is_null() {
            continue;
        }
        unsafe { SuspendThread(thread) };
        let mut original = vec![0u8; CONTEXT_SIZE];
        unsafe {
            *(original.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL;
        }
        if unsafe { GetThreadContext(thread, original.as_mut_ptr() as *mut c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            }
            continue;
        }
        let mut patched = original.clone();
        unsafe {
            *(patched.as_mut_ptr().add(0xF8) as *mut u64) = base as u64 + ping_rva as u64;
            *(patched.as_mut_ptr().add(0x98) as *mut u64) = stack_top - 8;
            // x64 ABI: arg0 in rcx, arg1 in rdx. `zeno_run(base, mode)` needs
            // both; `zeno_ping()` reads neither.
            *(patched.as_mut_ptr().add(0x78) as *mut u64) = base as u64;
            *(patched.as_mut_ptr().add(0x80) as *mut u64) = 1;
        }
        if unsafe { SetThreadContext(thread, patched.as_ptr() as *const c_void) } == 0 {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            }
            continue;
        }
        unsafe { ResumeThread(thread) };
        println!(
            "imagetest   thread {id} (rank {rank}) sent into {}",
            if opts.load { "zeno_run" } else { "zeno_ping" }
        );

        std::thread::sleep(std::time::Duration::from_secs(1));
        let mut now = vec![0u8; CONTEXT_SIZE];
        unsafe {
            *(now.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_FULL;
        }
        if unsafe { GetThreadContext(thread, now.as_mut_ptr() as *mut c_void) } != 0 {
            let rip = unsafe { *(now.as_ptr().add(0xF8) as *const u64) };
            println!(
                "imagetest   thread rip 0x{rip:X}, left the view = {}",
                rip < base as u64 || rip >= base as u64 + size as u64
            );
        }

        // Put the thread back exactly where we found it. A thread parked at a
        // foreign RIP with a fabricated stack is exactly the kind of anomaly a
        // periodic scan would notice, and it is not part of the experiment.
        unsafe {
            SuspendThread(thread);
            SetThreadContext(thread, original.as_ptr() as *const c_void);
            ResumeThread(thread);
            CloseHandle(thread);
        }
        println!("imagetest   thread restored");

        if opts.unmap {
            let status = unsafe { NtUnmapViewOfSection(handle, base) };
            println!(
                "imagetest   unmap 0x{:X} -> 0x{:X}",
                base as u64, status as u32
            );
        }

        for step in 1..=12 {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let alive = unsafe { WaitForSingleObject(handle, 0) } != 0;
            println!(
                "imagetest   t+{}s client {}",
                step * 5,
                if alive { "alive" } else { "DIED" }
            );
            if !alive {
                break;
            }
        }
        break;
    }

    unsafe { CloseHandle(handle) };
    Ok(())
}

fn main() -> Result<(), String> {
    let mut dll: Option<PathBuf> = None;
    let mut pack: Option<PathBuf> = None;
    let mut pid: Option<u32> = None;
    let mut probe = false;
    let mut nt = false;
    let mut hook = false;
    let mut hijack = false;
    let mut map_payload = false;
    let mut map_only = false;
    let mut no_entry = false;
    let mut ctxtest = false;
    let mut libtest = false;
    let mut imagetest = false;
    let mut imageload = false;
    let mut imagehold = false;
    let mut nolink = false;
    let mut unmap = false;
    let mut touch = 0u8; // 0 off, 1 open, 2 open+alloc, 3 open+alloc+write
    let mut hollow = false;
    let mut list_modules: Option<u32> = None;
    let mut load_watch_lib: Option<String> = None;
    let mut exec_ping_pid: Option<u32> = None;
    let mut patch: Option<(u32, bool)> = None;
    let mut oracle_pid: Option<u32> = None;
    let mut sampler: Option<(u32, u32, u64)> = None;
    let mut dump: Option<(u32, u64, usize)> = None;
    let mut raw_bytes: Option<(u64, usize)> = None;
    let mut vminfo: Option<u64> = None;
    let mut lfind: Option<u64> = None;
    let mut scan_live = false;
    let mut gcwalk: Option<u64> = None;
    let mut xcall: Option<(u64, [u64; 4], u64)> = None;
    let mut xthread: Option<(u64, [u64; 4], u64)> = None;
    let mut hijack_now_opts: Option<(u64, [u64; 4], u64)> = None;
    let mut forced_thread: Option<u32> = None;
    let mut execute: Option<(u64, PathBuf)> = None;
    let mut scan_state: Option<u64> = None;
    let mut classify_state: Option<(u64, u8, u8)> = None;
    let mut findmap = false;
    let mut findstate = false;
    let mut opmap_probe: Option<Vec<u8>> = None;
    let mut carrier: Option<String> = None;
    let mut use_existing = false;
    let mut mode: u64 = 1;
    let mut load: Option<PathBuf> = None;
    let mut config = PathBuf::from(
        "C:\\Users\\ezan\\AppData\\Local\\Temp\\opencode\\zeno-payload",
    );

    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--dll" => dll = Some(PathBuf::from(argv.next().ok_or("--dll needs a path")?)),
            "--pack" => pack = Some(PathBuf::from(argv.next().ok_or("--pack needs a path")?)),
            "--config" => config = PathBuf::from(argv.next().ok_or("--config needs a path")?),
            "--probe" => probe = true,
            "--nt" => nt = true,
            "--hook" => hook = true,
            "--hijack" => hijack = true,
            "--map" => map_payload = true,
            "--maponly" => {
                map_payload = true;
                map_only = true;
            }
            "--noentry" => no_entry = true,
            "--ctxtest" => ctxtest = true,
            "--libtest" => libtest = true,
            "--imagetest" => imagetest = true,
            "--imageload" => imageload = true,
            "--imagehold" => imagehold = true,
            "--nolink" => nolink = true,
            "--imageunmap" => unmap = true,
            "--touch" => touch = 1,
            "--touchalloc" => touch = 2,
            "--touchwrite" => touch = 3,
            "--touchprot" => touch = 4,
            "--touchrwx" => touch = 5,
            "--hollow" => hollow = true,
            "--loadwatch" => {
                load_watch_lib = Some(argv.next().ok_or("--loadwatch needs a dll path")?);
            }
            "--execping" => {
                exec_ping_pid = Some(match pid {
                    Some(value) => value,
                    None => find_pid(EXE).ok_or_else(|| format!("{EXE} is not running"))?,
                });
            }
            "--dump" => {
                let value = argv.next().ok_or("--dump needs an address")?;
                let address = u64::from_str_radix(value.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("bad address {value}"))?;
                let length = match argv.next() {
                    Some(text) => usize::from_str_radix(text.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad length {text}"))?,
                    None => 0x80,
                };
                dump = Some((
                    match pid {
                        Some(value) => value,
                        None => find_pid(EXE).ok_or_else(|| format!("{EXE} is not running"))?,
                    },
                    address,
                    length,
                ));
            }
            "--bytes" => {
                let value = argv.next().ok_or("--bytes needs an address")?;
                let address = u64::from_str_radix(value.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("bad address {value}"))?;
                let length = match argv.next() {
                    Some(text) => usize::from_str_radix(text.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad length {text}"))?,
                    None => 0x80,
                };
                raw_bytes = Some((address, length));
            }
            "--sample" => {                let value = argv.next().ok_or("--sample needs an rva")?;
                let rva = u32::from_str_radix(value.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("bad rva {value}"))?;
                let span = match argv.next() {
                    Some(text) => u64::from_str_radix(text.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad span {text}"))?,
                    None => 0x200,
                };
                sampler = Some((
                    match pid {
                        Some(value) => value,
                        None => find_pid(EXE).ok_or_else(|| format!("{EXE} is not running"))?,
                    },
                    rva,
                    span,
                ));
            }
            "--gcwalk" => {
                let value = argv.next().ok_or("--gcwalk needs a global_State address")?;
                gcwalk = Some(
                    u64::from_str_radix(value.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad address {value}"))?,
                );
            }
            "--lfind" => {
                let value = argv.next().ok_or("--lfind needs a lua_State address")?;
                lfind = Some(
                    u64::from_str_radix(value.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad address {value}"))?,
                );
            }
            "--findl" => {
                scan_live = true;
            }
            "--vminfo" => {
                let value = argv.next().ok_or("--vminfo needs a lua_State address")?;
                vminfo = Some(
                    u64::from_str_radix(value.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad address {value}"))?,
                );
            }
            flag @ ("--xthread" | "--hijacknow") => {
                let value = argv.next().ok_or("--xthread needs an rva")?;
                let rva = if let Some(symbol) = value.strip_prefix("@") {
                    let (module, export) = symbol
                        .split_once('!')
                        .ok_or_else(|| format!("bad symbol {symbol}"))?;
                    let base = unsafe { GetModuleHandleW(wide(module).as_ptr()) };
                    if base.is_null() {
                        return Err(format!("{module} is not loaded here"));
                    }
                    let address = unsafe { GetProcAddress(base, export.as_ptr()) };
                    if address.is_null() {
                        return Err(format!("{symbol} not found"));
                    }
                    address as u64
                } else {
                    u64::from_str_radix(value.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad rva {value}"))?
                };
                let mut call_args = [0u64; 4];
                for slot in call_args.iter_mut() {
                    let text = argv.next().ok_or("--xthread needs four hex arguments")?;
                    *slot = u64::from_str_radix(text.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad argument {text}"))?;
                }
                let wait_ms = match argv.next() {
                    Some(text) => text
                        .parse::<u64>()
                        .map_err(|_| format!("bad wait {text}"))?,
                    None => 8000,
                };
                if flag == "--hijacknow" {
                    hijack_now_opts = Some((rva, call_args, wait_ms));
                } else {
                    xthread = Some((rva, call_args, wait_ms));
                }
            }
            "--xcall" => {
                let value = argv.next().ok_or("--xcall needs an rva")?;
                let rva = if let Some(symbol) = value.strip_prefix("@") {
                    // System DLLs are mapped at the same address in every
                    // process on this boot, so a local lookup is valid.
                    let (module, export) = symbol
                        .split_once('!')
                        .ok_or_else(|| format!("bad symbol {symbol}"))?;
                    let base = unsafe { GetModuleHandleW(wide(module).as_ptr()) };
                    if base.is_null() {
                        return Err(format!("{module} is not loaded here"));
                    }
                    let address = unsafe { GetProcAddress(base, export.as_ptr()) };
                    if address.is_null() {
                        return Err(format!("{symbol} not found"));
                    }
                    address as u64
                } else {
                    u64::from_str_radix(value.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad rva {value}"))?
                };
                let mut call_args = [0u64; 4];
                for slot in call_args.iter_mut() {
                    let text = argv.next().ok_or("--xcall needs four hex arguments")?;
                    *slot = u64::from_str_radix(text.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad argument {text}"))?;
                }
                let wait_ms = match argv.next() {
                    Some(text) => text
                        .parse::<u64>()
                        .map_err(|_| format!("bad wait {text}"))?,
                    None => 8000,
                };
                xcall = Some((rva, call_args, wait_ms));
            }
            "--thread" => {
                let value = argv.next().ok_or("--thread needs a thread id")?;
                forced_thread = Some(
                    u32::from_str_radix(value.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad thread id {value}"))?,
                );
            }
            "--findmap" => findmap = true,
            "--findstate" => findstate = true,
            "--opmap" => {
                let text = argv.next().ok_or("--opmap needs hex bytes")?;
                let mut bytes = Vec::new();
                for piece in text.split([',', ' ', ':']).filter(|p| !p.is_empty()) {
                    let value = u8::from_str_radix(piece.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad byte {piece}"))?;
                    bytes.push(value);
                }
                opmap_probe = Some(bytes);
            }
            "--scan" => {
                let value = argv.next().ok_or("--scan needs a lua_State address")?;
                scan_state = Some(
                    u64::from_str_radix(value.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad address {value}"))?,
                );
            }
            "--classify" => {
                let value = argv.next().ok_or("--classify needs a lua_State address")?;
                let address = u64::from_str_radix(value.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("bad address {value}"))?;
                classify_state = Some((address, 0x00, 0x3F));
            }
            "--from" => {
                let value = argv.next().ok_or("--from needs a hex byte")?;
                if let Some((_, from, _)) = classify_state.as_mut() {
                    *from = u8::from_str_radix(value.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad byte {value}"))?;
                }
            }
            "--to" => {
                let value = argv.next().ok_or("--to needs a hex byte")?;
                if let Some((_, _, to)) = classify_state.as_mut() {
                    *to = u8::from_str_radix(value.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad byte {value}"))?;
                }
            }
            "--exec" => {                let value = argv.next().ok_or("--exec needs a lua_State address")?;
                let state = u64::from_str_radix(value.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("bad address {value}"))?;
                let script = PathBuf::from(argv.next().ok_or("--exec needs a script path")?);
                execute = Some((state, script));
            }
            "--oracle" => {                oracle_pid = Some(match pid {
                    Some(value) => value,
                    None => find_pid(EXE).ok_or_else(|| format!("{EXE} is not running"))?,
                });
            }
            "--patchtest" => {                let value = argv.next().ok_or("--patchtest needs an rva")?;
                let rva = u32::from_str_radix(value.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("bad rva {value}"))?;
                patch = Some((rva, true));
            }
            "--patchflip" => {
                let value = argv.next().ok_or("--patchflip needs an rva")?;
                let rva = u32::from_str_radix(value.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("bad rva {value}"))?;
                patch = Some((rva, false));
            }
            "--modules" => {
                list_modules = Some(match pid {
                    Some(value) => value,
                    None => find_pid(EXE).ok_or_else(|| format!("{EXE} is not running"))?,
                });
            }
            "--carrier" => {
                carrier = Some(argv.next().ok_or("--carrier needs a path")?);
            }
            "--carrier-existing" => use_existing = true,
            "--load" => load = Some(PathBuf::from(argv.next().ok_or("--load needs a path")?)),
            "--mode" => {
                let value = argv.next().ok_or("--mode needs a number")?;
                mode = u64::from_str_radix(value.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("bad mode {value}"))?;
            }
            "--pid" => {
                let value = argv.next().ok_or("--pid needs a number")?;
                pid = Some(value.parse().map_err(|_| format!("bad pid {value}"))?);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }

    let absolute = match &dll {
        Some(path) => {
            if !path.is_file() {
                return Err(format!("{} does not exist", path.display()));
            }
            Some(std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?)
        }
        None => None,
    };

    if let Some(global) = gcwalk {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return gc_walk(target, global);
    }

    if scan_live {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return scan_live_states(target);
    }

    if let Some(state) = lfind {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return find_lclosure(target, state);
    }

    if let Some(state) = vminfo {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return vm_info(target, state);
    }

    if let Some((rva, call_args, wait_ms)) = hijack_now_opts {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        let outcome = hijack_now(
            target,
            vec![Step {
                label: "hijacknow",
                rva,
                absolute: rva >= 0x7FF0_0000_0000,
                prepare: Box::new(move |_handle| Some(call_args)),
            }],
            wait_ms,
            10,
            forced_thread,
        );
        println!("hijack      done: {outcome:?}");
        return outcome.map(|_| ());
    }

    if let Some((rva, call_args, wait_ms)) = xthread {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        let outcome = remote_thread_run(
            target,
            vec![Step {
                label: "xthread",
                rva,
                absolute: rva >= 0x7FF0_0000_0000,
                prepare: Box::new(move |_handle| Some(call_args)),
            }],
            wait_ms,
        );
        println!("thread      done: {outcome:?}");
        return outcome.map(|_| ());
    }

    if let Some((rva, call_args, wait_ms)) = xcall {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        let park = remote_call(target, rva, call_args, wait_ms)?;
        println!("xcall       done, park pad 0x{park:X}");
        return Ok(());
    }

    if findmap {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return find_byte_map(target);
    }

    if findstate {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return find_states(target);
    }

    if let Some(bytes) = opmap_probe {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return dump_opcode_table(target, &bytes);
    }

    if let Some((state, from, to)) = classify_state {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return lua_classify(target, state, from, to, forced_thread);
    }
    if let Some(state) = scan_state {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return lua_scan(target, state, forced_thread);
    }

    if let Some((state, script)) = execute {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return lua_exec(target, state, &script, forced_thread);
    }

    if let Some((address, length)) = raw_bytes {
        let target = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return raw_dump(target, address, length);
    }

    if let Some((target, address, length)) = dump {
        return dump_memory(target, address, length);
    }

    if let Some((target, rva, span)) = sampler {
        return sample_state(target, rva, span, 30);
    }

    if let Some(target) = oracle_pid {
        return oracle(target);
    }

    if let Some((rva, identical)) = patch {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return patch_test(pid, rva, identical);
    }

    if let Some(target) = exec_ping_pid {
        return exec_ping(target);
    }

    if let Some(library) = load_watch_lib {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return load_watch(pid, &library);
    }

    if let Some(list) = list_modules {
        let mut modules = modules_of(list);
        modules.sort_by_key(|module| module.base);
        for module in &modules {
            println!("0x{:012X} 0x{:08X}  {}", module.base, module.size, module.name);
        }
        println!("{} modules", modules.len());
        return Ok(());
    }

    if hollow {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        let dll = dll.as_ref().ok_or("--hollow needs --dll <payload.dll>")?;
        return hollow_test(pid, dll, carrier.as_deref(), use_existing);
    }

    if touch != 0 {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return touch_test(pid, touch >= 2, touch == 3 || touch == 5, touch >= 4);
    }

    if imagetest || imageload || imagehold {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        let dll = dll.as_ref().ok_or("--imagetest/--imageload/--imagehold needs --dll <payload.dll>")?;
        return image_test(
            pid,
            dll,
            ImageOpts {
                load: imageload,
                exec: !imagehold,
                link: !nolink,
                unmap,
            },
        );
    }

    if libtest {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        let dll = dll.as_ref().ok_or("--libtest needs --dll <payload.dll>")?;
        return lib_test(pid, dll);
    }

    if ctxtest {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return context_test(pid);
    }

    if map_payload {
        let dll = dll.as_ref().ok_or("--map needs --dll <payload.dll>")?;
        let file = std::fs::read(dll).map_err(|e| format!("{}: {e}", dll.display()))?;

        for (library, names) in map::list_imports(&file)? {
            println!("import      {library}  ({} symbols)", names.len());
        }

        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;

        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
        if handle.is_null() || handle == -1isize as Handle {
            return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
        }

        let size = map::image_size(&file)?;
        let block = unsafe {
            VirtualAllocEx(handle, std::ptr::null_mut(), size as usize, MEM_COMMIT_RESERVE, PAGE_READWRITE)
        };
        if block.is_null() {
            unsafe { CloseHandle(handle) };
            return Err(format!("VirtualAllocEx({size}) failed ({})", unsafe { GetLastError() }));
        }
        let base = block as u64;

        let prepared = map::prepare(&file, base)?;
        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                handle,
                block,
                prepared.image.as_ptr() as *const c_void,
                prepared.image.len(),
                &mut written,
            )
        };
        println!(
            "mapped      0x{base:X}, {} bytes (preferred 0x{:X}), entry rva 0x{:X}",
            prepared.image.len(),
            prepared.preferred,
            prepared.entry
        );
        if ok == 0 || written != prepared.image.len() {
            unsafe {
                VirtualFreeEx(handle, block, 0, 0x8000);
                CloseHandle(handle);
            }
            return Err(format!("WriteProcessMemory failed ({})", unsafe { GetLastError() }));
        }

        let mut previous = 0u32;
        unsafe { VirtualProtectEx(handle, block, size as usize, 0x40, &mut previous) };

        let marker = base + size as u64 - 0x10;
        unsafe {
            WriteProcessMemory(
                handle,
                marker as *mut c_void,
                &SENTINEL as *const u64 as *const c_void,
                8,
                &mut written,
            )
        };

        let entry = match map::export_rva(&prepared.image, "zeno_run") {
            Some(rva) => {
                println!("entry       export zeno_run rva 0x{rva:X}");
                base + rva as u64
            }
            None => {
                println!("entry       PE entry rva 0x{:X} (CRT startup)", prepared.entry);
                base + prepared.entry as u64
            }
        };
        let mixed = marker;
        let mut code = Vec::new();
        // Realign the stack: the hijacked thread was stopped at an arbitrary
        // point, and Windows x64 wants rsp 16-aligned at a call boundary.
        code.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]);
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x10]);
        // Publish "the stub is running" before the call, so a hang inside the
        // payload is distinguishable from "the thread never ran at all".
        code.extend_from_slice(&[0x48, 0xBA]);
        code.extend_from_slice(&mixed.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&ENTERED.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x02]);

        if !no_entry {
            // CFG. `call rax` into a private page is an invalid indirect target
            // and the client is killed with no crash dump. A `ret` is not an
            // indirect branch, so this reaches the payload with the same stack
            // shape a `call` would have produced.
            code.extend_from_slice(&[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]); // lea rax,[rip+after]
            let disp_at = code.len() - 4;
            code.push(0x50); // push rax   (return address)
            code.extend_from_slice(&[0x48, 0xB8]);
            code.extend_from_slice(&entry.to_le_bytes());
            code.extend_from_slice(&[0x48, 0xB9]);
            code.extend_from_slice(&base.to_le_bytes());
            code.push(0xBA);
            code.extend_from_slice(&(mode as u32).to_le_bytes());
            code.extend_from_slice(&[0x45, 0x31, 0xC0]);
            code.push(0x50); // push rax   (target)
            code.push(0xC3); // ret
            let after = code.len() as i32;
            let lea_end = disp_at as i32 + 4;
            let disp = after - lea_end;
            code[disp_at..disp_at + 4].copy_from_slice(&disp.to_le_bytes());
        } else {
            code.extend_from_slice(&[0x48, 0xB8]);
            code.extend_from_slice(&0x9999u64.to_le_bytes());
            code.extend_from_slice(&[0x48, 0x89, 0x02]);
        }

        code.extend_from_slice(&[0x48, 0xBA]);
        code.extend_from_slice(&mixed.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x02]);
        code.extend_from_slice(&[0xEB, 0xFE]);

        let stub_block = unsafe {
            VirtualAllocEx(handle, std::ptr::null_mut(), 0x1000, MEM_COMMIT_RESERVE, 0x40)
        };
        if stub_block.is_null() {
            unsafe {
                VirtualFreeEx(handle, block, 0, 0x8000);
                CloseHandle(handle);
            }
            return Err("cannot allocate the stub".into());
        }
        unsafe {
            WriteProcessMemory(
                handle,
                stub_block,
                code.as_ptr() as *const c_void,
                code.len(),
                &mut written,
            )
        };
        {
            let mut check = [0u8; 16];
            let mut got = 0usize;
            let ok = unsafe {
                ReadProcessMemory(
                    handle,
                    stub_block as *const c_void,
                    check.as_mut_ptr() as *mut c_void,
                    check.len(),
                    &mut got,
                )
            };
            let hex: Vec<String> = check.iter().map(|b| format!("{b:02X}")).collect();
            println!(
                "stub        0x{:X}, {} bytes written, readback ok={} [{}]",
                stub_block as u64,
                code.len(),
                ok != 0 && got == check.len(),
                hex.join(" ")
            );
        }

        let list = threads_of(pid);
        let modules = modules_of(pid);
        println!("target      pid {pid}, {} threads, {} modules", list.len(), modules.len());

        if map_only {
            println!("map         image in place; --maponly, no thread touched");
            for _ in 0..12 {
                std::thread::sleep(std::time::Duration::from_millis(1000));
                if read_u64_checked(handle, marker).is_none() {
                    println!("map         client died while the image just sat there");
                    unsafe { CloseHandle(handle) };
                    return Ok(());
                }
            }
            println!("map         client still alive after 12s with the image mapped");
            unsafe { CloseHandle(handle) };
            return Ok(());
        }

        let result = run_stub(handle, &list, &modules, stub_block as u64, marker);

        unsafe {
            VirtualFreeEx(handle, stub_block, 0, 0x8000);
            CloseHandle(handle);
        }

        match result {
            Some((id, value)) => println!("map         thread {id} called the entry point, returned {value}"),
            None => return Err("no thread ran the entry point".into()),
        }

        let log = config.join(format!("payload-{pid}.log"));
        for _ in 0..40 {
            if log.is_file() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        match std::fs::read_to_string(&log) {
            Ok(text) => println!("\n--- payload log ---\n{text}"),
            Err(_) => println!("payload wrote no log for pid {pid}"),
        }
        return Ok(());
    }

    if hijack {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
        if handle.is_null() || handle == -1isize as Handle {
            return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
        }

        let list = threads_of(pid);
        let modules = modules_of(pid);
        println!("target      pid {pid}, {} threads, {} modules", list.len(), modules.len());
        if list.is_empty() {
            unsafe { CloseHandle(handle) };
            return Err("no threads to hijack".into());
        }

        let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
        let (name, argument) = match &load {
            Some(dll) => {
                let absolute =
                    std::fs::canonicalize(dll).map_err(|e| format!("{}: {e}", dll.display()))?;
                (
                    b"LoadLibraryW\0".as_slice(),
                    Some(wide(&absolute.to_string_lossy())),
                )
            }
            None => (b"GetTickCount\0".as_slice(), None),
        };
        let func = unsafe { GetProcAddress(kernel32, name.as_ptr()) } as u64;
        if func == 0 {
            unsafe { CloseHandle(handle) };
            return Err(format!("{} not found", String::from_utf8_lossy(name)));
        }

        let block = unsafe {
            VirtualAllocEx(
                handle,
                std::ptr::null_mut(),
                0x2000,
                MEM_COMMIT_RESERVE,
                0x40,
            )
        };
        if block.is_null() {
            unsafe { CloseHandle(handle) };
            return Err(format!("VirtualAllocEx failed ({})", unsafe { GetLastError() }));
        }

        let base = block as u64;
        let stub = base;
        let argument_address = base + 0x800;
        let marker = base + 0x1000;

        if let Some(text) = &argument {
            let bytes = text.len() * 2;
            let mut written = 0usize;
            unsafe {
                WriteProcessMemory(
                    handle,
                    argument_address as *mut c_void,
                    text.as_ptr() as *const c_void,
                    bytes,
                    &mut written,
                )
            };
        }

        let mut code = Vec::new();
        // Realign the stack before the call; the thread was stopped at an
        // arbitrary instruction with an arbitrary rsp.
        code.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]);
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
        // Marker first, so "the thread never ran" and "the call returned zero"
        // are different observations.
        code.extend_from_slice(&[0x48, 0xBA]);
        code.extend_from_slice(&marker.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&SENTINEL.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x02]);
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&func.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xB9]);
        code.extend_from_slice(&argument_address.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD0]);
        code.extend_from_slice(&[0x48, 0xBA]);
        code.extend_from_slice(&marker.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x02]);
        code.extend_from_slice(&[0xEB, 0xFE]);

        let mut written = 0usize;
        unsafe {
            WriteProcessMemory(
                handle,
                stub as *mut c_void,
                code.as_ptr() as *const c_void,
                code.len(),
                &mut written,
            )
        };
        let zero = 0u64;
        unsafe {
            WriteProcessMemory(
                handle,
                marker as *mut c_void,
                &zero as *const u64 as *const c_void,
                8,
                &mut written,
            )
        };

        println!("stub        0x{stub:X} -> func 0x{func:X}, marker 0x{marker:X}");

        let mut success = false;
        if let Some((id, value)) = run_stub(handle, &list, &modules, stub, marker) {
            println!("hijack      thread {id} ran the stub, result 0x{value:X}");
            success = true;
        }

        unsafe {
            VirtualFreeEx(handle, block, 0, 0x8000);
            CloseHandle(handle);
        }

        if !success {
            return Err("no thread executed the stub".into());
        }

        if load.is_some() {
            let log = config.join(format!("payload-{pid}.log"));
            for _ in 0..60 {
                if log.is_file() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            match std::fs::read_to_string(&log) {
                Ok(text) => println!("\n--- payload log ---\n{text}"),
                Err(_) => println!("payload did not load in pid {pid}"),
            }
        }
        return Ok(());
    }

    if nt {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
        if handle.is_null() || handle == -1isize as Handle {
            return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
        }
        let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
        let tick = unsafe { GetProcAddress(kernel32, b"GetTickCount\0".as_ptr()) };

        let mut thread: Handle = std::ptr::null_mut();
        let status = unsafe {
            NtCreateThreadEx(
                &mut thread,
                0x1F_FFFF,
                std::ptr::null_mut(),
                handle,
                tick,
                std::ptr::null_mut(),
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
            )
        };
        println!("NtCreateThreadEx status 0x{:X} thread {:?}", status, thread);
        if status == 0 && !thread.is_null() {
            unsafe { WaitForSingleObject(thread, 5000) };
            let mut code = 0u32;
            unsafe { GetExitCodeThread(thread, &mut code) };
            println!("thread exit 0x{code:X}");
            unsafe { CloseHandle(thread) };
        }
        unsafe { CloseHandle(handle) };
        return Ok(());
    }

    if hook {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        let thread = ui_thread(pid).ok_or_else(|| format!("pid {pid} has no window"))?;
        println!("target      pid {pid} ui thread {thread}");

        let module = unsafe {
            LoadLibraryW(wide(
                &absolute
                    .as_ref()
                    .ok_or("--dll <path> is required for --hook")?
                    .to_string_lossy(),
            ).as_ptr())
        };
        if module.is_null() {
            return Err(format!("LoadLibraryW failed locally ({})", unsafe { GetLastError() }));
        }
        let proc = unsafe { GetProcAddress(module, b"DummyHookProc\0".as_ptr()) };
        if proc.is_null() {
            return Err("DummyHookProc is not exported".into());
        }

        let hook = unsafe { SetWindowsHookExW(WH_CALLWNDPROC, proc, module, thread) };
        if hook.is_null() {
            return Err(format!("SetWindowsHookExW failed ({})", unsafe { GetLastError() }));
        }
        println!("hook        installed, waiting for a message");
        std::thread::sleep(std::time::Duration::from_secs(6));
        unsafe { UnhookWindowsHookEx(hook) };

        let log = config.join(format!("payload-{pid}.log"));
        let mut wrote = false;
        for _ in 0..60 {
            if log.is_file() {
                wrote = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        match std::fs::read_to_string(&log) {
            Ok(text) => println!("\n--- payload log ---\n{text}"),
            Err(_) => {
                let _ = wrote;
                println!("payload did not load in pid {pid} ({})", log.display())
            }
        }
        return Ok(());
    }

    if probe {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
        if handle.is_null() || handle == -1isize as Handle {
            return Err(format!("OpenProcess({pid}) failed ({})", unsafe { GetLastError() }));
        }
        let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
        let tick = unsafe { GetProcAddress(kernel32, b"GetTickCount\0".as_ptr()) };
        if tick.is_null() {
            unsafe { CloseHandle(handle) };
            return Err("GetTickCount not found".into());
        }
        let start: extern "system" fn(*mut c_void) -> u32 = unsafe { std::mem::transmute(tick) };
        let thread = unsafe {
            CreateRemoteThread(
                handle,
                std::ptr::null_mut(),
                0,
                start as *mut c_void,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        };
        if thread.is_null() {
            unsafe { CloseHandle(handle) };
            return Err(format!("CreateRemoteThread failed ({})", unsafe { GetLastError() }));
        }
        unsafe { WaitForSingleObject(thread, 5000) };
        let mut code = 0u32;
        unsafe { GetExitCodeThread(thread, &mut code) };
        println!("probe thread exit 0x{code:X}");
        if code == 0xC000_071C {
            println!("verdict      remote threads are terminated before they run");
        } else if code == 259 {
            println!("verdict      thread did not finish (still running)");
        } else {
            println!("verdict      remote threads run — the DLL load itself is refused");
        }
        unsafe {
            CloseHandle(thread);
            CloseHandle(handle);
        }
        return Ok(());
    }

    if let Some(pack) = &pack {
        let count = write_config(pack, &config)?;
        println!("config      {} offsets -> {}", count, config.display());
    }

    let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
    println!("target      pid {pid}");

    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!(
            "OpenProcess({pid}) failed ({}); run elevated",
            unsafe { GetLastError() }
        ));
    }

    let path = wide(
        &absolute
            .as_ref()
            .ok_or("--dll <path to zeno_payload.dll> is required")?
            .to_string_lossy(),
    );
    let bytes = path.len() * 2;
    let remote = unsafe {
        VirtualAllocEx(
            handle,
            std::ptr::null_mut(),
            bytes,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote.is_null() {
        unsafe { CloseHandle(handle) };
        return Err(format!("VirtualAllocEx failed ({})", unsafe { GetLastError() }));
    }

    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            handle,
            remote,
            path.as_ptr() as *const c_void,
            bytes,
            &mut written,
        )
    };
    if ok == 0 || written != bytes {
        unsafe {
            VirtualFreeEx(handle, remote, 0, 0x8000);
            CloseHandle(handle);
        }
        return Err(format!("WriteProcessMemory failed ({})", unsafe { GetLastError() }));
    }

    let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
    let load_library = unsafe { GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr()) };
    if load_library.is_null() {
        unsafe {
            VirtualFreeEx(handle, remote, 0, 0x8000);
            CloseHandle(handle);
        }
        return Err("LoadLibraryW not found".into());
    }
    let start: extern "system" fn(*mut c_void) -> u32 = unsafe { std::mem::transmute(load_library) };

    let thread = unsafe {
        CreateRemoteThread(
            handle,
            std::ptr::null_mut(),
            0,
            start as *mut c_void,
            remote,
            0,
            std::ptr::null_mut(),
        )
    };
    if thread.is_null() {
        unsafe {
            VirtualFreeEx(handle, remote, 0, 0x8000);
            CloseHandle(handle);
        }
        return Err(format!("CreateRemoteThread failed ({})", unsafe { GetLastError() }));
    }

    unsafe { WaitForSingleObject(thread, INFINITE) };
    let mut code = 0u32;
    unsafe { GetExitCodeThread(thread, &mut code) };
    println!("module      loaded at 0x{code:X}");
    if code == 0 {
        println!("result      LoadLibraryW returned NULL — check the DLL architecture");
    }

    unsafe {
        CloseHandle(thread);
        VirtualFreeEx(handle, remote, 0, 0x8000);
        CloseHandle(handle);
    }

    let log = config.join(format!("payload-{pid}.log"));
    for _ in 0..40 {
        if log.is_file() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    match std::fs::read_to_string(&log) {
        Ok(text) => println!("\n--- payload log ---\n{text}"),
        Err(_) => println!("payload did not write {}", log.display()),
    }

    Ok(())
}
