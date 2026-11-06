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

const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const CONTEXT_FULL: u32 = 0x0010_000B;
const CONTEXT_SIZE: usize = 0x4D0;
const CONTEXT_FLAGS_OFFSET: usize = 0x30;

#[link(name = "kernel32")]
extern "system" {
    fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn OpenThread(access: u32, inherit: i32, id: u32) -> Handle;
    fn SuspendThread(thread: Handle) -> u32;
    fn ResumeThread(thread: Handle) -> u32;
    fn GetThreadContext(thread: Handle, context: *mut c_void) -> i32;
    fn SetThreadContext(thread: Handle, context: *const c_void) -> i32;
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
    let mut value = 0u64;
    let mut got = 0usize;
    unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            &mut value as *mut u64 as *mut c_void,
            8,
            &mut got,
        )
    };
    value
}

/// Point a suspended thread at `stub`, wait for it to publish a result at
/// `marker`, then put the thread back exactly where it was.
fn run_stub(handle: Handle, threads: &[u32], stub: u64, marker: u64) -> Option<(u32, u64)> {
    let mut stuck = 0usize;
    for id in threads.iter().take(24) {
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
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            value = read_u64(handle, marker);
            if value != 0 && value != SENTINEL && value != ENTERED {
                break;
            }
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

fn main() -> Result<(), String> {
    let mut dll: Option<PathBuf> = None;
    let mut pack: Option<PathBuf> = None;
    let mut pid: Option<u32> = None;
    let mut probe = false;
    let mut nt = false;
    let mut hook = false;
    let mut hijack = false;
    let mut map_payload = false;
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
            "--load" => load = Some(PathBuf::from(argv.next().ok_or("--load needs a path")?)),
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
        // point, and Windows x64 needs rsp 16-aligned before a call.
        code.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]);
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
        // Publish "the stub is running" before the call, so a hang inside the
        // payload is distinguishable from "the thread never ran at all".
        code.extend_from_slice(&[0x48, 0xBA]);
        code.extend_from_slice(&mixed.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&ENTERED.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x02]);
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&entry.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xB9]);
        code.extend_from_slice(&base.to_le_bytes());
        code.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
        code.extend_from_slice(&[0x45, 0x31, 0xC0]);
        code.extend_from_slice(&[0xFF, 0xD0]);
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
        println!("target      pid {pid}, {} threads", list.len());
        let result = run_stub(handle, &list, stub_block as u64, marker);

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
        println!("target      pid {pid}, {} threads", list.len());
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
        if let Some((id, value)) = run_stub(handle, &list, stub, marker) {
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
