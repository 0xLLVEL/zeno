//! In-process probe for the live client.
//!
//! Loaded with `LoadLibraryW` so every address it touches is its own process's
//! memory. Reads go through `ReadProcessMemory` on `GetCurrentProcess()`, which
//! reports failure instead of faulting, so a bad pointer cannot take the client
//! down. The result is written to a log file next to this module's config.

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::fs;

type Handle = *mut c_void;

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn ReadProcessMemory(
        process: Handle,
        address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GetModuleFileNameW(module: Handle, buffer: *mut u16, size: u32) -> u32;
    fn GetCurrentProcessId() -> u32;
    fn VirtualQuery(
        address: *const c_void,
        buffer: *mut MemoryBasicInformation,
        size: usize,
    ) -> usize;
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn module_base(name: &str) -> u64 {
    unsafe { GetModuleHandleW(wide(name).as_ptr()) as u64 }
}

fn module_path(module: u64) -> String {
    let mut buffer = [0u16; 1024];
    let len = unsafe { GetModuleFileNameW(module as Handle, buffer.as_mut_ptr(), 1024) };
    String::from_utf16_lossy(&buffer[..len as usize])
}

fn read(handle: Handle, address: u64, len: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; len];
    let mut got = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            len,
            &mut got,
        )
    };
    if ok == 0 || got != len {
        return None;
    }
    Some(buffer)
}

fn read_u64(handle: Handle, address: u64) -> Option<u64> {
    if address < 0x10000 {
        return None;
    }
    let bytes = read(handle, address, 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// MSVC `std::string`: 16 inline bytes, length at +0x10, heap buffer when long.
fn read_string(handle: Handle, address: u64) -> String {
    let Some(head) = read(handle, address, 0x20) else {
        return String::new();
    };
    let length = i32::from_le_bytes([head[0x10], head[0x11], head[0x12], head[0x13]]);
    if length <= 0 || length > 4096 {
        return String::new();
    }
    let data = if length >= 16 {
        let pointer = u64::from_le_bytes([
            head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7],
        ]);
        match read(handle, pointer, length as usize) {
            Some(bytes) => bytes,
            None => return String::new(),
        }
    } else {
        head[..length as usize].to_vec()
    };
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn describe(handle: Handle, instance: u64, offsets: &[(String, u64)]) -> (String, String) {
    let pick = |key: &str| {
        offsets
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };

    let name_offset = pick("Instance::NameContainer");
    let name_field = pick("Instance::Name");
    let class_offset = pick("Instance::ClassDescriptor");
    let class_field = pick("Instance::ClassName");

    let name = if name_offset != 0 {
        read_u64(handle, instance + name_offset)
            .map(|base| read_string(handle, base + name_field))
            .unwrap_or_default()
    } else {
        String::new()
    };

    let class = if class_offset != 0 {
        read_u64(handle, instance + class_offset)
            .and_then(|descriptor| read_u64(handle, descriptor + class_field))
            .map(|text| read_string(handle, text))
            .unwrap_or_default()
    } else {
        String::new()
    };

    (name, class)
}

fn children(handle: Handle, instance: u64, offsets: &[(String, u64)], limit: usize) -> Vec<u64> {
    let pick = |key: &str| {
        offsets
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };

    let children_offset = pick("Instance::ChildrenStart");
    if instance == 0 || children_offset == 0 {
        return Vec::new();
    }

    let holder = read_u64(handle, instance + children_offset).unwrap_or(0);
    let begin = read_u64(handle, holder).unwrap_or(0);
    let end = read_u64(handle, holder + 8).unwrap_or(0);
    if begin == 0 || end <= begin {
        return Vec::new();
    }

    const STRIDE: u64 = 0x10;
    let count = ((end - begin) / STRIDE).min(limit as u64);
    let mut out = Vec::new();
    for index in 0..count {
        let child = read_u64(handle, begin + index * STRIDE).unwrap_or(0);
        if child >= 0x10000 {
            out.push(child);
        }
    }
    out
}

fn config_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("ZENO_CONFIG").unwrap_or_else(|_| {
        "C:\\Users\\ezan\\AppData\\Local\\Temp\\opencode\\zeno-payload".to_string()
    }))
}

fn mark(stage: &str) {
    let dir = config_dir();
    let _ = fs::create_dir_all(&dir);
    let pid = unsafe { GetCurrentProcessId() };
    let _ = fs::write(dir.join(format!("stage-{pid}.txt")), stage);
}

/// How many bytes of the ScriptContext object to look at, from `window.txt`
/// (hex). Kept configurable because reading past the object's own region is
/// what gets the client killed.
fn window_size() -> usize {
    fs::read_to_string(config_dir().join("window.txt"))
        .ok()
        .and_then(|text| usize::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x400)
}

fn bytes_left_in_region(address: u64) -> usize {
    let mut info: MemoryBasicInformation = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<MemoryBasicInformation>();
    let ok = unsafe { VirtualQuery(address as *const c_void, &mut info, size) };
    if ok == 0 {
        return 0;
    }
    let end = info.base + info.region_size;
    end.saturating_sub(address) as usize
}

fn load_offsets() -> Vec<(String, u64)> {
    let path = config_dir().join("offsets.txt");
    let Ok(text) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let parsed = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .or_else(|| value.parse::<u64>().ok());
        if let Some(value) = parsed {
            out.push((key.trim().to_string(), value));
        }
    }
    out
}

fn probe() -> String {
    let handle = unsafe { GetCurrentProcess() };

    let mut out = String::new();
    let exe = module_base("RobloxPlayerBeta.exe");
    out.push_str(&format!("pid {}\n", unsafe { GetCurrentProcessId() }));
    out.push_str(&format!("client base 0x{exe:X}\n"));
    out.push_str(&format!("client path {}\n", module_path(exe)));

    if config_dir().join("minimal").is_file() {
        out.push_str("result minimal\n");
        return out;
    }

    mark("offsets");
    let offsets = load_offsets();
    out.push_str(&format!("offsets {}\n", offsets.len()));
    if offsets.is_empty() {
        out.push_str("result no offsets config\n");
        return out;
    }

    let pick = |key: &str| {
        offsets
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };

    let fake_slot = exe + pick("FakeDataModel::Pointer");
    let fake = read_u64(handle, fake_slot).unwrap_or(0);
    mark("chain-1");
    let datamodel = read_u64(handle, fake + pick("FakeDataModel::RealDataModel")).unwrap_or(0);
    out.push_str(&format!("fake datamodel 0x{fake:X}\n"));
    out.push_str(&format!("datamodel 0x{datamodel:X}\n"));

    if datamodel == 0 {
        out.push_str("result datamodel is null\n");
        return out;
    }

    mark("children");
    let list = children(handle, datamodel, &offsets, 400);
    out.push_str(&format!("children {}\n", list.len()));

    mark("context");
    let mut context = 0u64;
    for child in &list {
        let (name, class) = describe(handle, *child, &offsets);
        if class == "ScriptContext" || name.replace(' ', "").eq_ignore_ascii_case("ScriptContext") {
            context = *child;
            out.push_str(&format!("script context 0x{context:X} {name} [{class}]\n"));
        }
    }

    if context == 0 {
        out.push_str("result ScriptContext not found\n");
        return out;
    }

    let vptr = read_u64(handle, context).unwrap_or(0);
    mark("vtable");
    out.push_str(&format!("vtable 0x{vptr:X}\n"));
    for index in 0..96u64 {
        let entry = read_u64(handle, vptr + index * 8).unwrap_or(0);
        if entry != 0 {
            out.push_str(&format!("  slot {index:>2} 0x{entry:X}\n"));
        }
    }

    // Hunt for the Luau main thread inside the ScriptContext object. A
    // `lua_State` starts with a GC header whose `tt` byte is 8 (LUA_TTHREAD),
    // and holds a back-pointer pair with its `global_State`: state->global G,
    // and G->mainthread == state. That pair is the strong check; `tt` alone
    // matches module data by accident.
    out.push_str("\nlua state candidates\n");
    mark("candidates");
    let mut candidates: Vec<(u64, u64)> = Vec::new();
    let window = window_size().min(bytes_left_in_region(context));
    out.push_str(&format!("  window 0x{window:X}\n"));
    let pointers = object_pointers(handle, context, window);
    mark("pointers");
    for (offset, pointer) in pointers {
        if let Some(global) = as_lua_state(handle, pointer) {
            out.push_str(&format!(
                "  +0x{offset:03X} -> state 0x{pointer:X}  global 0x{global:X}\n"
            ));
            candidates.push((pointer, global));
        }
    }
    if candidates.is_empty() {
        out.push_str("  none\n");
    }
    mark("validated");

    // Simple member getters: `mov rax,[rcx+disp]; ret`. Calling those is safe
    // and a Lua state getter is exactly that shape.
    out.push_str("\nvtable getters\n");
    if !config_dir().join("call-getters").is_file() {
        out.push_str("  skipped\n");
        out.push_str("result done\n");
        return out;
    }
    for index in 0..96u64 {
        let address = read_u64(handle, vptr + index * 8).unwrap_or(0);
        if address == 0 {
            continue;
        }
        let Some(code) = read(handle, address, 16) else {
            continue;
        };
        let disp = if code[0] == 0x48 && code[1] == 0x8B && code[2] == 0x41 && code[4] == 0xC3
        {
            Some(code[3])
        } else if code[0] == 0x48 && code[1] == 0x8B && code[2] == 0x01 && code[3] == 0xC3 {
            Some(0)
        } else {
            None
        };
        let Some(disp) = disp else { continue };

        let call: extern "system" fn(u64) -> u64 = unsafe { std::mem::transmute(address) };
        let value = call(context);
        let note = if as_lua_state(handle, value).is_some() {
            "  <- lua_State"
        } else if is_private_heap(value) {
            "  <- heap"
        } else {
            ""
        };
        out.push_str(&format!(
            "  slot {index:>2} 0x{address:X} +0x{disp:02X} -> 0x{value:X}{note}\n"
        ));
    }

    out.push_str("result done\n");
    mark("done");
    out
}

/// Every 8-byte slot in the object that holds a pointer into private heap.
fn object_pointers(handle: Handle, object: u64, length: usize) -> Vec<(usize, u64)> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < length {
        let chunk = length.min(0x200);
        mark(&format!("chunk 0x{offset:X}"));
        let Some(bytes) = read(handle, object + offset as u64, chunk) else {
            break;
        };
        mark(&format!("chunk 0x{offset:X} read"));
        for index in (0..chunk.saturating_sub(8)).step_by(8) {
            let value = u64::from_le_bytes(bytes[index..index + 8].try_into().unwrap());
            if is_private_heap(value) {
                out.push((offset + index, value));
            }
        }
        offset += chunk;
    }
    out
}

fn as_lua_state(handle: Handle, state: u64) -> Option<u64> {
    if !is_private_heap(state) {
        return None;
    }
    let head = read(handle, state, 0x100)?;
    if head[8] != 8 || head[9] > 0x20 {
        return None;
    }
    for index in (0..0x100).step_by(8) {
        let global = u64::from_le_bytes(head[index..index + 8].try_into().unwrap());
        if !is_private_heap(global) {
            continue;
        }
        let Some(back) = read(handle, global, 0x200) else {
            continue;
        };
        if (0..0x200).step_by(8).any(|at| {
            u64::from_le_bytes(back[at..at + 8].try_into().unwrap()) == state
        }) {
            return Some(global);
        }
    }
    None
}

fn is_private_heap(address: u64) -> bool {
    if address < 0x10000 {
        return false;
    }
    let mut info: MemoryBasicInformation = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<MemoryBasicInformation>();
    let ok = unsafe { VirtualQuery(address as *const c_void, &mut info, size) };
    ok != 0 && info.state == 0x1000 && info.kind == 0x20000
}

#[repr(C)]
struct MemoryBasicInformation {
    base: u64,
    allocation_base: u64,
    allocation_protect: u32,
    _align1: u32,
    region_size: u64,
    state: u32,
    protect: u32,
    kind: u32,
    _align2: u32,
}

fn worker() {
    let report = probe();
    let dir = config_dir();
    let _ = fs::create_dir_all(&dir);
    let pid = unsafe { GetCurrentProcessId() };
    let _ = fs::write(dir.join(format!("payload-{pid}.log")), report);
}

/// Exported so `SetWindowsHookExW` can name a procedure inside this DLL.
#[no_mangle]
pub extern "system" fn DummyHookProc(code: i32, w: usize, l: isize) -> isize {
    let _ = (code, w, l);
    0
}

/// Direct entry for manual mapping: no CRT startup, just the probe.
#[no_mangle]
pub extern "system" fn zeno_run(_: *mut c_void) -> u32 {
    worker();
    1
}

#[no_mangle]
pub extern "system" fn DllMain(_module: Handle, reason: u32, _reserved: *mut c_void) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        // Manual mapping never gives us a loader thread, and remote thread
        // creation is refused outright, so the work has to happen right here
        // on whichever thread called the entry point.
        worker();
    }
    1
}
