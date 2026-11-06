//! Luau stage: prove we can reach the live VM.
//!
//! `luaD_call` (`base+0x2639B40`) is entered with `rcx = lua_State*` from
//! `lua_resume`, the VM loops and every `luaB_*` wrapper — 24 callers in
//! total, so it fires constantly. We detour its first 13 bytes into a cave
//! that records `rcx` once, then replays the stolen prologue and jumps back.
//!
//! Nothing here guesses a `lua_State` out of a heap scan. The VM hands it to
//! us on the first call after the hook lands, and the layout is verified
//! against the fields the disassembly actually reads before anything trusts it.
//!
//! The detour is removed again as soon as we have the pointer, so the client
//! is never left with patched code in `.text`.
//!
//! Everything writes a breadcrumb before it does anything that can fault: a
//! manually mapped image has no TLS callbacks, so a crash leaves no traceback.

use std::ffi::c_void;
use std::ptr;

use crate::{module_base, read, read_u64, wide, Handle};

/// `luaD_call`, relative to the client module base.
const LUA_D_CALL_RVA: u64 = 0x2639B40;
/// `mov [rsp+8],rbx; push rdi; sub rsp,0x20; mov rdi,rdx` — 13 whole bytes.
const STOLEN: usize = 13;
const PROLOGUE: [u8; STOLEN] = [
    0x48, 0x89, 0x5C, 0x24, 0x08, // mov qword ptr [rsp+8], rbx
    0x57, //                         push rdi
    0x48, 0x83, 0xEC, 0x20, //       sub rsp, 0x20
    0x48, 0x8B, 0xFA, //             mov rdi, rdx
];

const CAVE_STUB: usize = 0x00;
const CAVE_TRAMP: usize = 0x20;
const CAVE_LEN: usize = 0x1000;

const MEM_COMMIT_RESERVE: u32 = 0x3000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentProcessId() -> u32;
    fn GetTickCount64() -> u64;
    fn Sleep(ms: u32);
    fn VirtualAlloc(base: *mut c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
    fn VirtualProtect(address: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
    fn FlushInstructionCache(process: Handle, address: *const c_void, size: usize) -> i32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        attributes: *mut c_void,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn WriteFile(
        file: Handle,
        buffer: *const c_void,
        len: u32,
        written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn SetEndOfFile(file: Handle) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}

/// First `lua_State*` the VM hands us. Written from the stub, read from Rust.
#[no_mangle]
pub static mut ZENO_CAPTURE: u64 = 0;

/// Where the stub resumes execution: the cave copy of the stolen prologue.
#[no_mangle]
pub static mut ZENO_TRAMPOLINE: u64 = 0;

fn put_u32(buf: &mut [u8], at: usize, value: u32) {
    buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], at: usize, value: u64) {
    buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// Straight to `CreateFileW`/`WriteFile`. No `std::fs`, no allocator
/// assumptions: a manually mapped image never ran the CRT's initialisers, so
/// the only I/O that is guaranteed to work here is the raw syscall wrapper.
fn write_text(path: &str, text: &str) -> bool {
    let wide_path = wide(path);
    let file = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            0x4000_0000, // GENERIC_WRITE
            0x0000_0001, // FILE_SHARE_READ
            ptr::null_mut(),
            4,      // OPEN_ALWAYS
            0x80,   // FILE_ATTRIBUTE_NORMAL
            ptr::null_mut(),
        )
    };
    if file.is_null() || file == (-1isize) as Handle {
        return false;
    }
    let bytes = text.as_bytes();
    let mut written = 0u32;
    let ok = unsafe {
        WriteFile(
            file,
            bytes.as_ptr() as *const c_void,
            bytes.len() as u32,
            &mut written,
            ptr::null_mut(),
        )
    };
    unsafe {
        SetEndOfFile(file);
        CloseHandle(file);
    }
    ok != 0 && written as usize == bytes.len()
}

fn config_path(name: &str) -> String {
    // Hardcoded, not `std::env::var`: a manually mapped image has no CRT
    // start-up, and this removes one more thing that can fail silently.
    format!("C:\\Users\\ezan\\AppData\\Local\\Temp\\opencode\\zeno-payload\\{name}")
}

/// One line per stage, so a crash still leaves the last thing we reached.
pub fn breadcrumb(stage: &str) {
    let pid = unsafe { GetCurrentProcessId() };
    let _ = write_text(&config_path(&format!("stage-{pid}.txt")), stage);
}

/// Incremental writer: one line == one flushed file. A crash keeps everything
/// written before it, which is the whole point of doing it this way.
struct Trail {
    path: String,
    text: String,
}

impl Trail {
    fn new() -> Self {
        let pid = unsafe { GetCurrentProcessId() };
        Trail {
            path: config_path(&format!("payload-{pid}.log")),
            text: String::new(),
        }
    }

    fn add(&mut self, line: &str) {
        self.text.push_str(line);
        self.text.push('\n');
        let _ = write_text(&self.path, &self.text);
    }
}

/// Capture stub. Records `rcx` once, then hands control back to the cave's
/// copy of the stolen prologue. No calls, no stack use, no flags clobbered
/// beyond what the original instructions already touch.
fn build_cave(cave: u64, resume: u64) -> Vec<u8> {
    let mut buf = vec![0u8; CAVE_LEN];
    let capture = ptr::addr_of!(ZENO_CAPTURE) as u64;
    let tramp_slot = ptr::addr_of!(ZENO_TRAMPOLINE) as u64;
    let stub = cave;

    buf[0] = 0x48; // mov rax, [rip+disp32]
    buf[1] = 0x8B;
    buf[2] = 0x05;
    put_u32(&mut buf, 3, (capture as i64 - (stub as i64 + 7)) as u32);

    buf[7] = 0x48; // test rax, rax
    buf[8] = 0x85;
    buf[9] = 0xC0;

    buf[10] = 0x75; // jne .done  (skip the store, 7 bytes)
    buf[11] = 7;

    buf[12] = 0x48; // mov [rip+disp32], rcx
    buf[13] = 0x89;
    buf[14] = 0x0D;
    put_u32(&mut buf, 15, (capture as i64 - (stub as i64 + 19)) as u32);

    buf[19] = 0x48; // .done: mov rax, [rip+disp32]
    buf[20] = 0x8B;
    buf[21] = 0x05;
    put_u32(&mut buf, 22, (tramp_slot as i64 - (stub as i64 + 26)) as u32);

    buf[26] = 0xFF; // jmp rax
    buf[27] = 0xE0;

    buf[CAVE_TRAMP..CAVE_TRAMP + STOLEN].copy_from_slice(&PROLOGUE);
    buf[CAVE_TRAMP + STOLEN] = 0x48; // mov rax, imm64
    buf[CAVE_TRAMP + STOLEN + 1] = 0xB8;
    put_u64(&mut buf, CAVE_TRAMP + STOLEN + 2, resume);
    buf[CAVE_TRAMP + STOLEN + 10] = 0xFF; // jmp rax
    buf[CAVE_TRAMP + STOLEN + 11] = 0xE0;

    buf
}

fn detour_bytes(cave: u64) -> [u8; STOLEN] {
    let mut patch = [0x90u8; STOLEN];
    patch[0] = 0x48; // mov rax, imm64
    patch[1] = 0xB8;
    patch[2..10].copy_from_slice(&cave.to_le_bytes());
    patch[10] = 0xFF; // jmp rax
    patch[11] = 0xE0;
    patch
}

/// Replace the first 13 bytes at `target`. Returns the original page protect.
fn patch(target: u64, bytes: &[u8; STOLEN]) -> Option<u32> {
    let mut old = 0u32;
    if unsafe { VirtualProtect(target as *mut c_void, 16, PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
        return None;
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), target as *mut u8, STOLEN);
        let mut ignored = 0u32;
        VirtualProtect(target as *mut c_void, 16, old, &mut ignored);
        FlushInstructionCache(GetCurrentProcess(), target as *const c_void, 16);
    }
    Some(old)
}

#[derive(Debug)]
struct StateHeader {
    ci_base: u64,
    stack: u64,
    global: u64,
    base: u64,
    top: u64,
    ci: u64,
    stack_size: i32,
    status: u8,
}

fn header(handle: Handle, state: u64) -> Option<StateHeader> {
    let raw = read(handle, state, 0x80)?;
    let q = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
    Some(StateHeader {
        status: raw[3],
        ci_base: q(0x28),
        stack: q(0x48),
        global: q(0x50),
        base: q(0x58),
        top: q(0x60),
        ci: q(0x70),
        stack_size: i32::from_le_bytes(raw[0x7C..0x80].try_into().unwrap()),
    })
}

fn verify(handle: Handle, state: u64) -> Result<StateHeader, String> {
    let h = header(handle, state).ok_or("unreadable")?;

    if h.ci_base == 0 || h.stack == 0 || h.ci == 0 || h.global == 0 {
        return Err(format!("null fields {h:#?}"));
    }
    if h.ci < h.ci_base {
        return Err("ci below ci_base".into());
    }
    if (h.ci - h.ci_base) % 0x30 != 0 {
        return Err(format!("ci stride 0x{:X} is not a multiple of 0x30", h.ci - h.ci_base));
    }
    if !(0x10..=0x100000).contains(&h.stack_size) {
        return Err(format!("stack size 0x{:X}", h.stack_size));
    }
    let stack_end = h.stack + (h.stack_size as u64) * 16;
    if h.base < h.stack || h.base > stack_end || h.top < h.base || h.top > stack_end {
        return Err(format!(
            "stack window bad base=0x{:X} top=0x{:X} range [{:X},{:X})",
            h.base, h.top, h.stack, stack_end
        ));
    }
    if h.status > 1 && h.status != 0x7F {
        return Err(format!("status 0x{:X}", h.status));
    }
    Ok(h)
}

fn dump_callinfo(handle: Handle, h: &StateHeader, out: &mut String) {
    let depth = (h.ci - h.ci_base) / 0x30;
    out.push_str(&format!("\nCallInfo chain: depth {depth}\n"));
    for step in 0..depth.min(8) {
        let ci = h.ci - step * 0x30;
        let func_slot = read_u64(handle, ci + 0x10).unwrap_or(0);
        let nresults = read_u64(handle, ci + 0x28).unwrap_or(0) as u32;
        let flags = read_u64(handle, ci + 0x2C).unwrap_or(0) as u32;
        let closure = if func_slot > 0x10000 {
            read_u64(handle, func_slot).unwrap_or(0)
        } else {
            0
        };
        let is_c = if closure > 0x10000 {
            read(handle, closure + 5, 1).map(|b| b[0]).unwrap_or(0xFF)
        } else {
            0xFF
        };
        out.push_str(&format!(
            "  [{step}] ci=0x{ci:X} func=0x{func_slot:X} closure=0x{closure:X} isC={is_c} nres=0x{nresults:X} flags=0x{flags:X}\n"
        ));
        if closure > 0x10000 && is_c == 0 {
            if let Some(proto) = read_u64(handle, closure + 0x18) {
                let code = read_u64(handle, proto + 0x30).unwrap_or(0);
                let sizecode = read_u64(handle, proto + 0x38).unwrap_or(0) as u32;
                out.push_str(&format!(
                    "      proto=0x{proto:X} code=0x{code:X} sizecode=0x{sizecode:X}\n"
                ));
            }
        }
    }
}

/// Busy-wait without touching std's timer machinery, which expects a runtime a
/// manually mapped image never initialised.
fn wait_for_capture(timeout_ms: u64) -> u64 {
    let start = unsafe { GetTickCount64() };
    loop {
        let seen = unsafe { ZENO_CAPTURE };
        if seen != 0 {
            return seen;
        }
        if unsafe { GetTickCount64() } - start > timeout_ms {
            return 0;
        }
        unsafe { Sleep(1) };
    }
}

pub fn run() -> String {
    let handle = unsafe { GetCurrentProcess() };
    let mut trail = Trail::new();
    let mut out = String::new();
    breadcrumb("luau::run start");

    let base = module_base("RobloxPlayerBeta.exe");
    out.push_str(&format!(
        "pid {}\nclient base 0x{base:X}\n",
        unsafe { GetCurrentProcessId() }
    ));
    if base == 0 {
        out.push_str("FAIL: client module not found\n");
        trail.add(&out);
        return out;
    }

    let target = base + LUA_D_CALL_RVA;
    out.push_str(&format!("luaD_call 0x{target:X} (rva 0x{LUA_D_CALL_RVA:X} + base)\n"));
    trail.add(&out);

    let actual = read(handle, target, STOLEN);
    match actual {
        Some(ref bytes) if *bytes == PROLOGUE => {}
        Some(bytes) => {
            out.push_str(&format!(
                "FAIL: prologue differs, client updated?\n  have {bytes:02X?}\n  want {PROLOGUE:02X?}\n"
            ));
            trail.add(&out);
            return out;
        }
        None => {
            out.push_str("FAIL: cannot read luaD_call (bad base or page unreadable)\n");
            trail.add(&out);
            return out;
        }
    }
    out.push_str("prologue verified byte-for-byte\n");
    trail.add(&out);

    let cave = unsafe {
        VirtualAlloc(
            ptr::null_mut(),
            CAVE_LEN,
            MEM_COMMIT_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    } as u64;
    if cave == 0 {
        out.push_str("FAIL: VirtualAlloc for cave\n");
        trail.add(&out);
        return out;
    }
    unsafe {
        ZENO_TRAMPOLINE = cave + CAVE_TRAMP as u64;
    }
    let bytes = build_cave(cave, target + STOLEN as u64);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), cave as *mut u8, CAVE_LEN);
        FlushInstructionCache(GetCurrentProcess(), cave as *const c_void, CAVE_LEN);
    }
    out.push_str(&format!("cave 0x{cave:X}\n"));
    trail.add(&out);

    let patch_bytes = detour_bytes(cave);
    breadcrumb("luau: patching luaD_call");
    if patch(target, &patch_bytes).is_none() {
        out.push_str("FAIL: VirtualProtect on luaD_call\n");
        trail.add(&out);
        return out;
    }
    out.push_str("detour installed\n");
    trail.add(&out);
    breadcrumb("luau: detour installed, waiting");

    let state = wait_for_capture(4000);
    let restoring = unsafe { patch(target, &PROLOGUE).is_some() };
    unsafe {
        ZENO_CAPTURE = 0;
    }
    out.push_str(&format!(
        "detour {} after {}ms\n",
        if restoring { "restored" } else { "NOT restored" },
        unsafe { GetTickCount64() }
    ));

    if state == 0 {
        out.push_str("no lua_State captured in 4s (VM idle? is a game loaded?)\n");
        trail.add(&out);
        return out;
    }
    out.push_str(&format!("Captured lua_State* = 0x{state:X}\n"));
    trail.add(&out);
    breadcrumb("luau: captured a state");

    match verify(handle, state) {
        Ok(h) => {
            out.push_str("layout verified against every field the VM reads\n");
            out.push_str(&format!(
                "  status={} ci_base=0x{:X} stack=0x{:X} size=0x{:X}\n  global=0x{:X} base=0x{:X} top=0x{:X} ci=0x{:X}\n",
                h.status, h.ci_base, h.stack, h.stack_size, h.global, h.base, h.top, h.ci
            ));
            trail.add(&out);
            if let Some(raw) = read(handle, h.global, 0x40) {
                let mut gs = String::from("  global_State:\n");
                for (i, chunk) in raw.chunks(8).enumerate() {
                    let v = u64::from_le_bytes(chunk.try_into().unwrap());
                    gs.push_str(&format!("    +0x{:02X} 0x{v:016X}\n", i * 8));
                }
                trail.add(&gs.trim_end());
            }
            let mut ci = String::new();
            dump_callinfo(handle, &h, &mut ci);
            trail.add(ci.trim_end());

            let pid = unsafe { GetCurrentProcessId() };
            let _ = write_text(&config_path(&format!("luau-{pid}.txt")), &format!("0x{state:X}"));
        }
        Err(why) => {
            out.push_str(&format!("REJECTED: {why}\n"));
            trail.add(&out);
        }
    }

    out
}
