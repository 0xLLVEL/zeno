//! Loads `zeno-payload.dll` into the live client and waits for its thread.
//!
//! The injector only writes the DLL path and starts `LoadLibraryW`; everything
//! after that runs inside the target, where its own memory is ordinary memory.

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
        start: extern "system" fn(*mut c_void) -> u32,
        parameter: *mut c_void,
        flags: u32,
        id: *mut u32,
    ) -> Handle;
    fn WaitForSingleObject(handle: Handle, millis: u32) -> u32;
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
        let size = read_u64(handle, entry + 0x38) & 0xFFFF_FFFF;
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
            out.push(Module { name, base, size });
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
fn touch_test(pid: u32, alloc: bool, write: bool) -> Result<(), String> {
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
            *(patched.as_mut_ptr().add(0x78) as *mut u64) = arg;
            *(patched.as_mut_ptr().add(0x80) as *mut u64) = 0;
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
            r"C:\Windows\System32\WindowsCodecs.dll",
            r"C:\Windows\System32\msmpeg2vdec.dll",
            r"C:\Windows\System32\NaturalLanguage6.dll",
            r"C:\Windows\System32\mscms.dll",
            r"C:\Windows\System32\wmvdspa.dll",
            r"C:\Windows\System32\mswsock.dll",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
    };

    let mut chosen: Option<(String, u64, u64)> = None;
    for candidate in candidates {
        let short = candidate.rsplit('\\').next().unwrap_or(&candidate).to_string();
        let before = modules_of(pid);
        if !before.iter().any(|module| module.name.eq_ignore_ascii_case(&short)) {
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
            std::thread::sleep(std::time::Duration::from_millis(1500));
            unpark(handle, &parked);
            println!("hollow      loaded {short}");
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
    let mut carrier: Option<String> = None;
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
            "--hollow" => hollow = true,
            "--carrier" => {
                carrier = Some(argv.next().ok_or("--carrier needs a path")?);
            }
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

    if hollow {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        let dll = dll.as_ref().ok_or("--hollow needs --dll <payload.dll>")?;
        return hollow_test(pid, dll, carrier.as_deref());
    }

    if touch != 0 {
        let pid = pid.or_else(|| find_pid(EXE)).ok_or_else(|| format!("{EXE} is not running"))?;
        return touch_test(pid, touch >= 2, touch >= 3);
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
                start,
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
            start,
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
