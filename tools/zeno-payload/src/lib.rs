//! In-process probe for the live client.
//!
//! Loaded with `LoadLibraryW` so every address it touches is its own process's
//! memory. Reads go through `ReadProcessMemory` on `GetCurrentProcess()`, which
//! reports failure instead of faulting, so a bad pointer cannot take the client
//! down. The result is written to a log file next to this module's config.

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::fs;

mod luau;

pub(crate) type Handle = *mut c_void;

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

pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn module_base(name: &str) -> u64 {
    unsafe { GetModuleHandleW(wide(name).as_ptr()) as u64 }
}

fn module_path(module: u64) -> String {
    let mut buffer = [0u16; 1024];
    let len = unsafe { GetModuleFileNameW(module as Handle, buffer.as_mut_ptr(), 1024) };
    String::from_utf16_lossy(&buffer[..len as usize])
}

pub(crate) fn read(handle: Handle, address: u64, len: usize) -> Option<Vec<u8>> {
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

pub(crate) fn read_u64(handle: Handle, address: u64) -> Option<u64> {
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

pub(crate) fn config_dir() -> std::path::PathBuf {
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

    // Hunt for the Luau main thread. A `lua_State` starts with a GC header
    // whose `tt` byte is 8 (LUA_TTHREAD) and holds a back-pointer pair with its
    // `global_State`: state->global == G and G->mainthread == state. That pair
    // is the strong check; `tt` alone matches module data by accident.
    //
    // The state is not a direct member of the ScriptContext on this build, so
    // walk outward: every private-heap pointer inside the object is a node,
    // and each node is searched the same way. One hop is cheap and bounded;
    // `depth.txt` controls how far it goes.
    out.push_str("\nlua state candidates\n");
    mark("candidates");
    let region_left = bytes_left_in_region(context);
    let window = window_size().min(region_left);
    out.push_str(&format!("  window 0x{window:X} of 0x{region_left:X} left in region\n"));

    let max_depth = fs::read_to_string(config_dir().join("depth.txt"))
        .ok()
        .and_then(|text| text.trim().parse::<usize>().ok())
        .unwrap_or(2);
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut frontier: Vec<(u64, usize)> = Vec::new();
    for root in [context, datamodel] {
        if seen.insert(root) {
            frontier.push((root, 0));
        }
    }
    let mut candidates: Vec<(u64, u64)> = Vec::new();

    for depth in 0..max_depth {
        if frontier.is_empty() {
            break;
        }
        out.push_str(&format!("  depth {depth}: {} objects\n", frontier.len()));
        mark(&format!("depth {depth} ({} objects)", frontier.len()));
        let mut next: Vec<(u64, usize)> = Vec::new();
        let mut scanned = 0usize;
        for (object, _) in frontier.drain(..) {
            scanned += 1;
            if scanned % 200 == 0 {
                mark(&format!("depth {depth} object {scanned}"));
            }
            let span = if depth == 0 {
                window
            } else {
                window.min(bytes_left_in_region(object)).min(0x400)
            };
            if span < 8 {
                continue;
            }
            let Some(bytes) = read(handle, object, span) else {
                continue;
            };
            for index in (0..span.saturating_sub(8)).step_by(8) {
                let value = u64::from_le_bytes(bytes[index..index + 8].try_into().unwrap());
                if !is_private_heap(value) || !seen.insert(value) {
                    continue;
                }
                if let Some(global) = as_lua_state(handle, value) {
                    out.push_str(&format!(
                        "  d{depth} 0x{object:X}+0x{index:03X} -> state 0x{value:X}  global 0x{global:X}\n"
                    ));
                    candidates.push((value, global));
                }
                next.push((value, depth + 1));
            }
        }
        next.truncate(20000);
        frontier = next;
    }
    out.push_str(&format!("  visited {}\n", seen.len()));
    if candidates.is_empty() {
        out.push_str("  none\n");
    }
    mark("validated");

    // Fall back to a raw scan of the arena the ScriptContext lives in. The
    // thread object is in the same allocator, and the signature is strong
    // enough that a linear pass is cheaper than a deeper pointer walk.
    if candidates.is_empty() && config_dir().join("scan").is_file() {
        let (start, len) = region_of(context);
        out.push_str(&format!("\nregion scan\n  base 0x{start:X} size 0x{len:X}\n"));
        let hits = scan_region_for_threads(handle, start, len);
        out.push_str(&format!("  hits {}\n", hits.len()));
        for (state, global) in hits.iter().take(8) {
            out.push_str(&format!("  state 0x{state:X}  global 0x{global:X}\n"));
        }
        if hits.is_empty() {
            out.push_str("  none\n");
        }
        candidates.extend(hits.into_iter().take(1));
        mark("scan done");
    }

    // Same idea, but across the whole private working set: the Lua heap is not
    // required to live next to the ScriptContext.
    if candidates.is_empty() && config_dir().join("scan-all").is_file() {
        let cap = fs::read_to_string(config_dir().join("scan-cap-mb.txt"))
            .ok()
            .and_then(|text| text.trim().parse::<usize>().ok())
            .unwrap_or(1024)
            * 1024
            * 1024;
        out.push_str("\nfull scan\n");
        let (hits, scanned) = scan_all_regions(handle, cap, &[exe, context & !0xFFF]);
        out.push_str(&format!("  scanned 0x{scanned:X} bytes\n"));
        out.push_str(&format!("  hits {}\n", hits.len()));
        for (state, global) in hits.iter().take(8) {
            out.push_str(&format!("  state 0x{state:X}  global 0x{global:X}\n"));
        }
        if hits.is_empty() {
            out.push_str("  none\n");
        }
        candidates.extend(hits.into_iter().take(1));
        mark("full scan done");
    }

    // `ScriptContext+0x1B8` holds the main `lua_State` on this build. Dump the
    // state and its `global_State` so the VM's member offsets can be read off
    // real bytes instead of guessed from a layout that changes every release.
    if let Some((state, global)) = candidates.first().copied() {
        if config_dir().join("dump-lua").is_file() {
            mark("dump-lua");
            out.push_str("\nlua state dump\n");
            if let Some(bytes) = read(handle, state, 0x140) {
                out.push_str(&hex_dump("state", &bytes, state));
            }
            out.push_str("\nglobal state dump\n");
            if let Some(bytes) = read(handle, global, 0x140) {
                out.push_str(&hex_dump("global", &bytes, global));
            }
            out.push_str("\nstate members\n");
            if let Some(bytes) = read(handle, state, 0x140) {
                for index in (0..bytes.len().saturating_sub(8)).step_by(8) {
                    let value = u64::from_le_bytes(bytes[index..index + 8].try_into().unwrap());
                    if !is_private_heap(value) {
                        continue;
                    }
                    out.push_str(&format!("  +0x{index:03X} -> 0x{value:X}\n"));
                    if let Some(head) = read(handle, value, 0x40) {
                        out.push_str(&hex_dump("    member", &head, value));
                    }
                    if let Some(text) = as_string(handle, value) {
                        out.push_str(&format!("    string {text:?}\n"));
                    }
                }
            }
            mark("dump-lua done");
        }
    }

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

/// A `lua_State` is a GC object, so it can be recognised from its own bytes
/// once we know where it sits: `next` is null or another GC object, `tt` is
/// LUA_TTHREAD, and one of the words right after the header is a
/// `global_State` whose first member points straight back at the object.
///
/// Scanning the raw region beats walking pointers: a pointer graph only finds
/// what is reachable, and this state is not reachable from the ScriptContext
/// within a safe number of hops.
fn scan_region_for_threads(handle: Handle, start: u64, len: usize) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    let mut offset = 0usize;
    while offset < len {
        if offset % 0x400000 == 0 {
            mark(&format!("scan 0x{offset:X} / 0x{len:X}"));
        }
        let chunk = (len - offset).min(0x10000);
        let Some(bytes) = read(handle, start + offset as u64, chunk) else {
            offset += chunk;
            continue;
        };
        if bytes.len() < 0x100 {
            offset += chunk;
            continue;
        }
        for index in (0..bytes.len().saturating_sub(0x90)).step_by(8) {
            if bytes[index + 8] != 8 {
                continue;
            }
            let next = u64::from_le_bytes(bytes[index..index + 8].try_into().unwrap());
            if next != 0 && !is_private_heap(next) {
                continue;
            }
            let object = start + (offset + index) as u64;
            for slot in (0x10..0x90).step_by(8) {
                let global = u64::from_le_bytes(bytes[index + slot..index + slot + 8].try_into().unwrap());
                if !is_private_heap(global) {
                    continue;
                }
                if read_u64(handle, global) == Some(object) {
                    out.push((object, global));
                    break;
                }
            }
        }
        offset += chunk.saturating_sub(0x100);
        if chunk <= 0x100 {
            break;
        }
    }
    out
}

fn region_of(address: u64) -> (u64, usize) {
    let mut info: MemoryBasicInformation = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<MemoryBasicInformation>();
    let ok = unsafe { VirtualQuery(address as *const c_void, &mut info, size) };
    if ok == 0 {
        return (address, 0);
    }
    (info.base, info.region_size as usize)
}

/// Walk every committed private region in the process and stop as soon as the
/// thread signature shows up. `lua_State` is not guaranteed to sit in the same
/// arena as the ScriptContext, so the search cannot be scoped to one region.
fn scan_all_regions(handle: Handle, cap: usize, skip: &[u64]) -> (Vec<(u64, u64)>, usize) {
    let mut hits = Vec::new();
    let mut scanned = 0usize;
    let mut address = 0x10000u64;
    let ceiling = 0x7FFF_FFFF_FFFFu64;

    while address < ceiling && scanned < cap {
        let mut info: MemoryBasicInformation = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<MemoryBasicInformation>();
        let ok = unsafe { VirtualQuery(address as *const c_void, &mut info, size) };
        if ok == 0 || info.region_size == 0 {
            address += 0x1000;
            continue;
        }
        let next = info.base + info.region_size;
        let readable = info.state == 0x1000
            && (info.kind == 0x20000 || info.kind == 0x40000)
            && info.protect & 0x100 == 0
            && info.protect & 0x01 == 0;
        let skipped = skip
            .iter()
            .any(|base| info.base >= *base && info.base < *base + 0x400000);
        if readable && !skipped {
            let len = (info.region_size as usize).min(0x4000000);
            hits.extend(scan_region_for_threads(handle, info.base, len));
            scanned += len;
            if !hits.is_empty() {
                break;
            }
        }
        address = next;
    }
    (hits, scanned)
}

fn hex_dump(label: &str, bytes: &[u8], base: u64) -> String {    let mut out = String::new();
    for (line, chunk) in bytes.chunks(16).enumerate() {
        let at = base + (line * 16) as u64;
        out.push_str(&format!("  {label} {at:012X}  "));
        for byte in chunk {
            out.push_str(&format!("{byte:02X} "));
        }
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        out.push_str("  ");
        for byte in chunk {
            let c = *byte as char;
            out.push(if c.is_ascii_graphic() || c == ' ' { c } else { '.' });
        }
        out.push('\n');
    }
    out
}

/// Best-effort read of a Luau `TString`: the tag lives at `+8` (LUA_TSTRING is
/// 5) and the payload is either inline past the header or behind a pointer.
/// Both layouts are tried; anything non-printable is rejected, so a wrong
/// guess prints nothing instead of lying.
fn as_string(handle: Handle, object: u64) -> Option<String> {
    if !is_private_heap(object) {
        return None;
    }
    let head = read(handle, object, 0x40)?;
    if head[8] != 5 {
        return None;
    }
    let mut candidates: Vec<(usize, u64)> = Vec::new();
    for len_at in [0x0Cu64, 0x10, 0x14] {
        let len = u32::from_le_bytes(head[len_at as usize..len_at as usize + 4].try_into().ok()?);
        if len == 0 || len > 512 {
            continue;
        }
        let pointer_at = len_at + 4;
        if let Ok(raw) = head[pointer_at as usize..pointer_at as usize + 8].try_into() {
            let pointer = u64::from_le_bytes(raw);
            if is_private_heap(pointer) {
                candidates.push((len as usize, pointer));
            }
        }
        candidates.push((len as usize, object + 0x18));
    }
    for (len, at) in candidates {
        let Some(raw) = read(handle, at, len.min(256)) else {
            continue;
        };
        if raw.iter().all(|b| *b == 0x20 || (0x21..0x7F).contains(b) || *b == b'\n') {
            let text = String::from_utf8_lossy(&raw).into_owned();
            if !text.trim().is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn as_lua_state(handle: Handle, state: u64) -> Option<u64> {
    if !is_private_heap(state) {
        return None;
    }
    let head = read(handle, state, 0x80)?;
    // A thread's GC header is `GCObject* next; uint8_t tt; uint8_t marked`.
    if head[8] != 8 {
        return None;
    }
    // `next` is either null or another GC object; a small integer here means
    // this is a TValue, not an object.
    let next = u64::from_le_bytes(head[0..8].try_into().unwrap());
    if next != 0 && !is_private_heap(next) {
        return None;
    }
    // The strong check: `lua_State::global` points at a `global_State` whose
    // first member is `mainthread`, pointing straight back here.
    for index in (0x10..0x80).step_by(8) {
        let global = u64::from_le_bytes(head[index..index + 8].try_into().unwrap());
        if !is_private_heap(global) {
            continue;
        }
        if read_u64(handle, global) == Some(state) {
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

#[derive(Clone)]
struct Section {
    name: String,
    address: u64,
    size: usize,
}

fn module_sections(handle: Handle, base: u64) -> Vec<Section> {
    let mut out = Vec::new();
    let Some(header) = read(handle, base, 0x1000) else {
        return out;
    };
    let pe = u32::from_le_bytes(header[0x3C..0x40].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(header[pe + 6..pe + 8].try_into().unwrap()) as usize;
    let optional = u16::from_le_bytes(header[pe + 20..pe + 22].try_into().unwrap()) as usize;
    let table = pe + 24 + optional;

    for index in 0..count {
        let at = table + index * 40;
        if at + 40 > header.len() {
            break;
        }
        let raw_name = &header[at..at + 8];
        let end = raw_name.iter().position(|b| *b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..end]).into_owned();
        let size = u32::from_le_bytes(header[at + 8..at + 12].try_into().unwrap()) as usize;
        let address = u32::from_le_bytes(header[at + 12..at + 16].try_into().unwrap()) as u64;
        out.push(Section {
            name,
            address: base + address,
            size,
        });
    }
    out
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return out;
    }
    let last = haystack.len() - needle.len();
    let first = needle[0];
    let mut index = 0;
    while index <= last {
        if haystack[index] == first && &haystack[index..index + needle.len()] == needle {
            out.push(index);
            index += needle.len();
        } else {
            index += 1;
        }
    }
    out
}

fn qword(buffer: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buffer[offset..offset + 8].try_into().unwrap())
}

/// Vtable address for an MSVC class name: type descriptor -> complete object
/// locator -> vtable[-1]. Pure reads of `.rdata`, so it cannot trip the
/// protections that guard the code sections.
fn vtable_of(bytes: &[u8], base: u64, rdata_address: u64, name: &str) -> Option<u64> {
    // MSVC stores the decorated name in the type descriptor.
    let mut needle = format!(".?AV{name}@@").into_bytes();
    needle.push(0);

    for at in find_all(bytes, &needle) {
        if at < 0x10 {
            continue;
        }
        let type_info = qword(bytes, at - 0x10);
        if type_info < base || type_info >= base + 0x1000_0000 {
            continue;
        }
        let descriptor_rva = (rdata_address - base + at as u64 - 0x10) as u32;

        let mut col = None;
        for hit in find_all(bytes, &descriptor_rva.to_le_bytes()) {
            col = Some(rdata_address + hit as u64);
            break;
        }
        let Some(col) = col else { continue };

        for hit in find_all(bytes, &col.to_le_bytes()) {
            let vtable = rdata_address + hit as u64 + 8;
            if vtable >= base {
                return Some(vtable);
            }
        }
    }
    None
}

fn objects_with_vtable(handle: Handle, buffer: &[u8], start: u64, vtable: u64, cap: usize) -> Vec<u64> {
    let mut out = Vec::new();
    for index in (0..buffer.len().saturating_sub(8)).step_by(8) {
        let value = qword(buffer, index);
        if value < 0x10000 || !is_private_heap(value) {
            continue;
        }
        let Some(head) = read(handle, value, 8) else {
            continue;
        };
        if u64::from_le_bytes(head[..8].try_into().unwrap()) == vtable {
            out.push(start + index as u64);
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

/// Locate the data model on the running build without an offsets pack: RTTI
/// gives the class vtables, the writable sections give the globals, and the
/// chain itself is walked with the layout we already verified.
fn discover(handle: Handle, base: u64) -> String {
    let mut out = String::new();
    let sections = module_sections(handle, base);
    out.push_str(&format!("sections {}\n", sections.len()));
    for section in &sections {
        out.push_str(&format!(
            "  {:<10} 0x{:<10X} 0x{:X}\n",
            section.name, section.address, section.size
        ));
    }

    let Some(rdata) = sections.iter().find(|s| s.name == ".rdata").cloned() else {
        out.push_str("result no .rdata\n");
        return out;
    };
    let Some(data) = sections.iter().find(|s| s.name == ".data").cloned() else {
        out.push_str("result no .data\n");
        return out;
    };

    mark("rtti");
    let Some(rdata_bytes) = read(handle, rdata.address, rdata.size) else {
        out.push_str("result cannot read .rdata\n");
        return out;
    };
    let fake_vtable = vtable_of(&rdata_bytes, base, rdata.address, "FakeDataModel");
    let model_vtable = vtable_of(&rdata_bytes, base, rdata.address, "DataModel");
    out.push_str(&format!(
        "FakeDataModel vtable {:?}\nDataModel vtable {:?}\n",
        fake_vtable.map(|v| format!("0x{v:X}")),
        model_vtable.map(|v| format!("0x{v:X}"))
    ));

    let (Some(fake_vtable), Some(model_vtable)) = (fake_vtable, model_vtable) else {
        out.push_str("result RTTI lookup failed\n");
        return out;
    };

    mark("globals");
    let Some(data_bytes) = read(handle, data.address, data.size) else {
        out.push_str("result cannot read .data\n");
        return out;
    };

    let fakes = objects_with_vtable(handle, &data_bytes, data.address, fake_vtable, 8);
    out.push_str(&format!("fake candidates {}\n", fakes.len()));
    for slot in &fakes {
        let Some(value) = read_u64(handle, *slot) else {
            continue;
        };
        out.push_str(&format!("  slot 0x{slot:X} -> fake 0x{value:X}\n"));
        let Some(head) = read(handle, value, 0x800) else {
            continue;
        };
        for offset in (0..0x800).step_by(8) {
            let candidate = qword(&head, offset);
            if candidate < 0x10000 || !is_private_heap(candidate) {
                continue;
            }
            let Some(first) = read(handle, candidate, 8) else {
                continue;
            };
            if u64::from_le_bytes(first[..8].try_into().unwrap()) == model_vtable {
                out.push_str(&format!("  real data model at fake+0x{offset:X} -> 0x{candidate:X}\n"));
                out.push_str(&walk_instances(handle, candidate, base));
            }
        }
    }

    out.push_str("result done\n");
    out
}

/// Try the layout we already verified against f0ea and print names, so a
/// changed offset shows up as garbage instead of a wrong answer.
fn walk_instances(handle: Handle, datamodel: u64, base: u64) -> String {
    let mut out = String::new();
    let holder = match read_u64(handle, datamodel + 0x70) {
        Some(value) if value >= 0x10000 => value,
        _ => {
            out.push_str("  children holder missing at +0x70\n");
            return out;
        }
    };
    let begin = read_u64(handle, holder).unwrap_or(0);
    let end = read_u64(handle, holder + 8).unwrap_or(0);
    if begin < 0x10000 || end <= begin {
        out.push_str("  children vector empty\n");
        return out;
    }
    let count = ((end - begin) / 0x10).min(40);
    out.push_str(&format!("  children {count} (stride 0x10)\n"));
    for index in 0..count {
        let child = read_u64(handle, begin + index * 0x10).unwrap_or(0);
        if child < 0x10000 {
            continue;
        }
        let name = read_u64(handle, child + 0x68)
            .map(|pointer| read_string(handle, pointer))
            .unwrap_or_default();
        let class = read_u64(handle, child + 0x18)
            .and_then(|descriptor| read_u64(handle, descriptor + 8))
            .map(|text| read_string(handle, text))
            .unwrap_or_default();
        let _ = base;
        out.push_str(&format!("    {index:>2} 0x{child:<12X} {name:<30} [{class}]\n"));
    }
    out
}

fn worker() {
    let handle = unsafe { GetCurrentProcess() };
    let exe = module_base("RobloxPlayerBeta.exe");

    let report = if config_dir().join("luau.txt").is_file() {
        mark("luau");
        let mut text = luau::run();
        text.push_str(&format!("pid {}\n", unsafe { GetCurrentProcessId() }));
        text
    } else if config_dir().join("discover").is_file() {
        mark("discover");
        let mut text = format!("pid {}\nclient base 0x{exe:X}\n", unsafe {
            GetCurrentProcessId()
        });
        text.push_str(&format!("client path {}\n", module_path(exe)));
        text.push_str(&discover(handle, exe));
        text
    } else {
        probe()
    };

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

/// Import-free probe used to test whether code can run from an image section
/// the loader does not know about. Must not call anything: the mapped view has
/// no resolved imports, so any call would fault on a zero IAT slot.
#[no_mangle]
pub extern "system" fn zeno_ping() -> u32 {
    0x5EED_0001
}

/// Direct entry for manual mapping: no CRT startup, just the probe.
///
/// The injector's stub calls this as `(image_base, mode)` following the Win64
/// ABI, so `mode` lands in `rdx`. Mode 7 returns without touching anything at
/// all, which answers "does the client survive a hijacked call?" without
/// `worker()` being in the picture.
#[no_mangle]
pub extern "system" fn zeno_run(_base: *mut c_void, mode: *mut c_void) -> u32 {
    if mode as u64 == 7 {
        return 7;
    }
    luau::breadcrumb("entered zeno_run");
    worker();
    1
}

#[no_mangle]
pub extern "system" fn DllMain(_module: Handle, reason: u32, _reserved: *mut c_void) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        // Keep this to a single breadcrumb. LoadLibraryW is holding the loader
        // lock while we are inside DllMain, so anything heavy here stalls the
        // whole process. The real work happens when the injector calls
        // `zeno_run` directly once the module is loaded.
        luau::breadcrumb("dllmain attach");
    }
    1
}
