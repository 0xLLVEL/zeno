//! Locate the Luau main thread by its own shape.
//!
//! A `lua_State` is recognisable without any tag byte: it owns a stack, so four
//! pointers inside it must agree with each other. In the shipped layout they
//! sit at fixed offsets â€”
//!
//! ```text
//! +0x08  top          +0x28  stack_last
//! +0x10  base         +0x30  stack
//! +0x18  global
//! ```
//!
//! and `stack <= base <= top <= stack_last` always holds, with both ends
//! sixteen-byte aligned because the stack is a `TValue` array. A `global_State`
//! found that way then has to point back at the same thread, which is the check
//! that kills lookalikes.
//!
//! This runs from outside the client. Reads never freeze the target.

use std::ffi::c_void;

use crate::live::Process;

type Handle = *mut c_void;

const MEM_COMMIT: u32 = 0x1000;
const MEM_PRIVATE: u32 = 0x20000;
const MEM_MAPPED: u32 = 0x40000;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const PAGE_NOACCESS: u32 = 0x01;
pub const CHUNK: usize = 0x10000;
const HEADER_SPAN: usize = 0x88;

const OFF_TOP: usize = 0x08;
const OFF_BASE: usize = 0x10;
const OFF_GLOBAL: usize = 0x18;
const OFF_STACK_LAST: usize = 0x28;
const OFF_STACK: usize = 0x30;

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

#[link(name = "kernel32")]
extern "system" {
    fn VirtualQueryEx(
        process: Handle,
        address: *const c_void,
        info: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
}

pub struct Hit {
    pub state: u64,
    pub global: u64,
    pub stack: u64,
    pub stack_size: u64,
    /// First byte of the object header. `LUA_TTHREAD` is 8, so a real thread
    /// carries `8` here; anything else is a struct that merely looks like one.
    pub tag: u8,
}

/// Region that owns `address`, as `(base, size)`.
pub fn region_of(process: &Process, address: u64) -> (u64, usize) {
    let handle = process.handle();
    let mut info: MemoryBasicInformation = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<MemoryBasicInformation>();
    let ok = unsafe { VirtualQueryEx(handle, address as *const c_void, &mut info, size) };
    if ok == 0 {
        return (address & !0xFFF, 0);
    }
    (info.base, info.region_size.min(usize::MAX as u64) as usize)
}

/// `MEM_PRIVATE`, `MEM_MAPPED` or `MEM_IMAGE` for the region owning `address`.
pub fn region_kind(process: &Process, address: u64) -> u32 {
    let handle = process.handle();
    let mut info: MemoryBasicInformation = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<MemoryBasicInformation>();
    let ok = unsafe { VirtualQueryEx(handle, address as *const c_void, &mut info, size) };
    if ok == 0 {
        return 0;
    }
    info.kind
}

const READABLE: u32 = PAGE_READONLY
    | PAGE_READWRITE
    | PAGE_WRITECOPY
    | PAGE_EXECUTE_READ
    | PAGE_EXECUTE_READWRITE
    | PAGE_EXECUTE_WRITECOPY;

/// Every committed region the client can read, with its base and size.
pub fn regions(process: &Process) -> Vec<(u64, usize)> {
    let handle = process.handle();
    let mut out = Vec::new();
    let mut address = 0x10000u64;
    let ceiling = 0x7FFF_FFFF_FFFFu64;
    while address < ceiling {
        let mut info: MemoryBasicInformation = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<MemoryBasicInformation>();
        let ok = unsafe { VirtualQueryEx(handle, address as *const c_void, &mut info, size) };
        if ok == 0 || info.region_size == 0 {
            address += 0x1000;
            continue;
        }
        let readable = info.state == MEM_COMMIT
            && (info.kind == MEM_PRIVATE || info.kind == MEM_MAPPED)
            && info.protect & (PAGE_GUARD | PAGE_NOACCESS) == 0
            && info.protect & READABLE != 0;
        if readable {
            out.push((info.base, info.region_size.min(usize::MAX as u64) as usize));
        }
        address = (info.base + info.region_size).max(address + 0x1000);
    }
    out
}

/// Scan every committed, readable region. `cap` bounds the total number of
/// bytes read so a pathological process cannot make this run forever.
pub fn find_threads<F>(process: &Process, cap: usize, mut progress: F) -> (Vec<Hit>, usize)
where
    F: FnMut(usize),
{
    let all = regions(process);
    let mut hits = Vec::new();
    let mut scanned = 0usize;
    for (base, size) in &all {
        if scanned >= cap {
            break;
        }
        let len = (*size).min(cap - scanned).min(0x4000_0000);
        scan_region(process, *base, len, &mut hits);
        scanned += len;
        progress(scanned);
    }
    (hits, scanned)
}

fn qword(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// A stack pointer is only plausible if it names the low end of a `TValue`
/// array. That array is aligned to sixteen bytes and its length is a multiple
/// of one `TValue`.
fn stack_span_ok(top: u64, base: u64, stack: u64, stack_last: u64) -> Option<u64> {
    if stack < 0x10000 || stack & 0xF != 0 {
        return None;
    }
    if stack_last <= stack || stack_last & 0xF != 0 {
        return None;
    }
    let size = stack_last - stack;
    if size > 0x40_0000 {
        return None;
    }
    if base < stack || base > stack_last || base & 0xF != 0 {
        return None;
    }
    if top < base || top > stack_last || top & 0xF != 0 {
        return None;
    }
    Some(size)
}

/// Scan one region for the stack/global pointer pattern.
pub fn scan_region(process: &Process, start: u64, len: usize, hits: &mut Vec<Hit>) {
    let mut offset = 0usize;
    while offset + CHUNK <= len.max(CHUNK) && offset < len {
        let chunk = (len - offset).min(CHUNK);
        let Some(bytes) = process.read(start + offset as u64, chunk) else {
            offset += chunk;
            continue;
        };
        if bytes.len() < HEADER_SPAN {
            offset += chunk;
            continue;
        }
        let limit = bytes.len() - HEADER_SPAN;
        let mut index = 0usize;
        while index < limit {
            let top = qword(&bytes, index + OFF_TOP);
            let base = qword(&bytes, index + OFF_BASE);
            let global = qword(&bytes, index + OFF_GLOBAL);
            if global > 0x10000 {
                let stack_last = qword(&bytes, index + OFF_STACK_LAST);
                let stack = qword(&bytes, index + OFF_STACK);
                if let Some(size) = stack_span_ok(top, base, stack, stack_last) {
                    let state = start + (offset + index) as u64;
                    if global_points_back(process, global, state) {
                        hits.push(Hit {
                            state,
                            global,
                            stack,
                            stack_size: size,
                            tag: bytes[index],
                        });
                    }
                }
            }
            index += 8;
        }
        if chunk <= HEADER_SPAN {
            break;
        }
        offset += chunk - HEADER_SPAN;
    }
}

/// The `global_State` keeps the thread that owns it. For the main thread that
/// is the thread itself, so the pointer has to appear somewhere in the global
/// block â€” offset unknown, but the block is bounded.
fn global_points_back(process: &Process, global: u64, state: u64) -> bool {
    let Some(block) = process.read(global, 0x600) else {
        return false;
    };
    block
        .chunks_exact(8)
        .any(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()) == state)
}

/// Addresses inside one region that hold `needle`, capped at `limit`.
pub fn find_value_in_region(
    process: &Process,
    base: u64,
    size: usize,
    needle: u64,
    limit: usize,
) -> Vec<u64> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < size && out.len() < limit {
        let chunk = (size - offset).min(CHUNK);
        let Some(bytes) = process.read(base + offset as u64, chunk) else {
            offset += chunk;
            continue;
        };
        let mut index = 0usize;
        while index + 8 <= bytes.len() && out.len() < limit {
            if qword(&bytes, index) == needle {
                out.push(base + offset as u64 + index as u64);
            }
            index += 8;
        }
        offset += chunk;
    }
    out
}

/// How many `TValue` slots at `stack` carry a legal tag. The tag is the last
/// word of the sixteen-byte slot; the build decides whether the slot carries an
/// `extra` word before it, so both layouts are scored.
pub fn stack_tags(process: &Process, stack: u64, slots: usize) -> usize {
    let Some(bytes) = process.read(stack, slots * 16) else {
        return 0;
    };
    let mut at_twelve = 0usize;
    let mut at_eight = 0usize;
    for slot in bytes.chunks_exact(16) {
        if u32::from_le_bytes(slot[12..16].try_into().unwrap()) < 16 {
            at_twelve += 1;
        }
        if u32::from_le_bytes(slot[8..12].try_into().unwrap()) < 16 {
            at_eight += 1;
        }
    }
    at_twelve.max(at_eight)
}

/// A VM recognised by its string table, which is the first member of
/// `global_State`. Every check here comes from the layout of `TString`, so
/// nothing has to be guessed about the rest of the struct.
pub struct Vm {
    pub global: u64,
    pub hash: u64,
    pub nuse: u32,
    pub size: u32,
    pub thread: Option<u64>,
}

fn is_pow2(value: u32) -> bool {
    value >= 16 && value <= 0x20_0000 && value.count_ones() == 1
}

/// `TString`: header (3 bytes), atom, next pointer at `+8`, hash at `+16`,
/// length at `+20`, characters at `+24`.
fn looks_like_string(process: &Process, address: u64) -> bool {
    if address < 0x10000 || address & 7 != 0 {
        return false;
    }
    let Some(head) = process.read(address, 0x1C) else {
        return false;
    };
    let len = u32::from_le_bytes(head[20..24].try_into().unwrap()) as usize;
    if len == 0 || len > 0x2000 {
        return false;
    }
    let Some(body) = process.read(address + 24, len.min(64)) else {
        return false;
    };
    let printable = body
        .iter()
        .filter(|byte| (0x20..0x7F).contains(*byte) || **byte >= 0x80)
        .count();
    printable * 10 >= body.len() * 8
}

/// Scan for the string table that opens a `global_State`:
///
/// ```text
/// +0x00  TString** hash
/// +0x08  uint32_t  nuse
/// +0x0C  int       size
/// ```
pub fn find_vms(process: &Process, cap: usize) -> (Vec<Vm>, usize) {
    let all = regions(process);
    let mut found = Vec::new();
    let mut scanned = 0usize;
    for (base, size) in &all {
        if scanned >= cap {
            break;
        }
        let len = (*size).min(cap - scanned);
        scanned += len;
        let mut offset = 0usize;
        while offset < len && found.len() < 32 {
            let chunk = (len - offset).min(CHUNK);
            let Some(bytes) = process.read(base + offset as u64, chunk) else {
                offset += chunk;
                continue;
            };
            let limit = bytes.len().saturating_sub(0x18);
            let mut index = 0usize;
            while index < limit {
                let hash = qword(&bytes, index);
                if hash > 0x10000 && hash & 7 == 0 {
                    let nuse = u32::from_le_bytes(bytes[index + 8..index + 12].try_into().unwrap());
                    let table = u32::from_le_bytes(bytes[index + 12..index + 16].try_into().unwrap());
                    if is_pow2(table) && nuse >= 1 && nuse < table * 4 {
                        let global = base + (offset + index) as u64;
                        if table_matches(process, hash, table) {
                            let thread = find_thread(process, global);
                            found.push(Vm {
                                global,
                                hash,
                                nuse,
                                size: table,
                                thread,
                            });
                        }
                    }
                }
                index += 8;
            }
            offset += chunk;
        }
    }
    (found, scanned)
}

/// A real bucket array points at interned strings. A random array of pointers
/// does not.
fn table_matches(process: &Process, hash: u64, size: u32) -> bool {
    let sample = size.min(256) as usize;
    let Some(buckets) = process.read(hash, sample * 8) else {
        return false;
    };
    let mut seen = 0usize;
    let mut good = 0usize;
    for chunk in buckets.chunks_exact(8) {
        let entry = u64::from_le_bytes(chunk.try_into().unwrap());
        if entry == 0 {
            continue;
        }
        seen += 1;
        if looks_like_string(process, entry) {
            good += 1;
        }
    }
    seen >= 4 && good * 2 >= seen
}

/// The thread whose `global` field names this VM. `lua_State.global` sits at
/// `+0x18`; nearby it, `top` and `base` bracket the stack.
pub fn find_thread(process: &Process, global: u64) -> Option<u64> {
    let block = process.read(global, 0x1000)?;
    for index in (0..block.len().saturating_sub(6 * 8)).step_by(8) {
        let candidate = qword(&block, index);
        if candidate <= 0x10000 || candidate & 7 != 0 {
            continue;
        }
        let Some(head) = process.read(candidate, 0x58) else {
            continue;
        };
        if qword(&head, OFF_GLOBAL) != global {
            continue;
        }
        let top = qword(&head, OFF_TOP);
        let base = qword(&head, OFF_BASE);
        let stack = qword(&head, OFF_STACK);
        let stack_last = qword(&head, OFF_STACK_LAST);
        if stack_span_ok(top, base, stack, stack_last).is_some() {
            return Some(candidate);
        }
    }
    None
}

/// Loose string test: some run of printable ASCII near the object. Used only to
/// score bucket arrays, never to prove anything on its own.
fn printable_near(process: &Process, address: u64) -> bool {
    let Some(bytes) = process.read(address, 0x40) else {
        return false;
    };
    let mut run = 0usize;
    let mut best = 0usize;
    for byte in &bytes {
        if (0x20..0x7F).contains(byte) {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best >= 6
}

/// Walk out from an object up to two pointer hops and report anything that
/// looks like a Luau VM: a `lua_State` whose `+0x18` names a block holding a
/// bucket array of interned strings.
pub struct VmPath {
    pub holder: u64,
    pub slot: usize,
    pub state: u64,
    pub global: u64,
    pub buckets: usize,
    pub nuse: u32,
}

pub fn probe_lua(process: &Process, root: u64, span: usize) -> Vec<VmPath> {
    let mut out = Vec::new();
    let Some(block) = process.read(root, span) else {
        return out;
    };
    for (index, chunk) in block.chunks_exact(8).enumerate() {
        let first = u64::from_le_bytes(chunk.try_into().unwrap());
        if first <= 0x10000 || first & 7 != 0 {
            continue;
        }
        let Some(inner) = process.read(first, 0x400) else {
            continue;
        };
        for (slot, chunk) in inner.chunks_exact(8).enumerate() {
            let state = u64::from_le_bytes(chunk.try_into().unwrap());
            if state <= 0x10000 || state & 7 != 0 {
                continue;
            }
            if let Some((global, buckets, nuse)) = vm_at(process, state) {
                out.push(VmPath {
                    holder: first,
                    slot: index * 8,
                    state,
                    global,
                    buckets,
                    nuse,
                });
            }
        }
    }
    out
}

/// `lua_State+0x18` -> `global_State`, whose first member is the string table.
fn vm_at(process: &Process, state: u64) -> Option<(u64, usize, u32)> {
    let head = process.read(state, 0x58)?;
    let global = qword(&head, OFF_GLOBAL);
    if global <= 0x10000 {
        return None;
    }
    let top = qword(&head, OFF_TOP);
    let base = qword(&head, OFF_BASE);
    let stack = qword(&head, OFF_STACK);
    let stack_last = qword(&head, OFF_STACK_LAST);
    stack_span_ok(top, base, stack, stack_last)?;

    let global_head = process.read(global, 0x28)?;
    let hash = qword(&global_head, 0);
    let nuse = u32::from_le_bytes(global_head[8..12].try_into().unwrap());
    let size = u32::from_le_bytes(global_head[12..16].try_into().unwrap());
    if hash <= 0x10000 || !is_pow2(size) || nuse < 1 || nuse > size * 8 {
        return None;
    }
    let sample = size.min(128) as usize;
    let buckets = process.read(hash, sample * 8)?;
    let mut hits = 0usize;
    for chunk in buckets.chunks_exact(8) {
        let entry = u64::from_le_bytes(chunk.try_into().unwrap());
        if entry > 0x10000 && entry & 7 == 0 && printable_near(process, entry) {
            hits += 1;
        }
    }
    if hits < 4 {
        return None;
    }
    Some((global, size as usize, nuse))
}

/// A real `TString` whose characters equal `needle`:
///
/// ```text
/// +0x00  tt (5 = LUA_TSTRING) / marked / memcat
/// +0x08  next   (0 or another TString)
/// +0x10  hash   (non-zero)
/// +0x14  len
/// +0x18  characters
/// ```
///
/// Reflection keeps plain `char*` name tables, so requiring the header cuts
/// those out and leaves only interned Lua strings.
pub fn find_string_objects(
    process: &Process,
    needle: &[u8],
    cap: usize,
    limit: usize,
) -> (Vec<u64>, usize) {
    let mut out = Vec::new();
    let mut scanned = 0usize;
    let len = needle.len();
    for (base, size) in regions(process) {
        if scanned >= cap || out.len() >= limit {
            break;
        }
        let span = size.min(cap - scanned);
        scanned += span;
        let mut offset = 0usize;
        while offset < span && out.len() < limit {
            let chunk = (span - offset).min(CHUNK);
            let Some(bytes) = process.read(base + offset as u64, chunk) else {
                offset += chunk;
                continue;
            };
            let mut index = 0usize;
            while index + len <= bytes.len() && out.len() < limit {
                if &bytes[index..index + len] == needle {
                    let data = base + offset as u64 + index as u64;
                    if string_header_ok(process, data, len) {
                        out.push(data - 0x18);
                    }
                }
                index += 1;
            }
            offset += chunk;
        }
    }
    (out, scanned)
}

fn string_header_ok(process: &Process, data: u64, len: usize) -> bool {
    let object = data.wrapping_sub(0x18);
    let Some(head) = process.read(object, 0x18) else {
        return false;
    };
    if head[0] & 0x0F != 5 {
        return false;
    }
    if u32::from_le_bytes(head[0x14..0x18].try_into().unwrap()) as usize != len {
        return false;
    }
    let next = qword(&head, 0x08);
    if next != 0 && (next < 0x10000 || next & 7 != 0) {
        return false;
    }
    qword(&head, 0x10) != 0
}

/// States found by the object tag alone. Roblox ships the 2021 fork of Luau,
/// where `LUA_TTHREAD` is 9 and a `lua_State` begins with
///
/// ```text
/// +0x00  tt = 9 / marked / memcat
/// +0x08  top        +0x28  stack_last
/// +0x10  base       +0x30  stack
/// +0x18  global
/// ```
///
/// so the tag plus five aligned heap pointers is enough to list candidates for
/// inspection.
pub fn find_states_by_tag(process: &Process, tag: u8, cap: usize, limit: usize) -> (Vec<u64>, usize) {
    let mut out = Vec::new();
    let mut scanned = 0usize;
    for (base, size) in regions(process) {
        if scanned >= cap || out.len() >= limit {
            break;
        }
        let span = size.min(cap - scanned);
        scanned += span;
        let mut offset = 0usize;
        while offset < span && out.len() < limit {
            let chunk = (span - offset).min(CHUNK);
            let Some(bytes) = process.read(base + offset as u64, chunk) else {
                offset += chunk;
                continue;
            };
            if bytes.len() < HEADER_SPAN {
                offset += chunk;
                continue;
            }
            let limit_index = bytes.len() - HEADER_SPAN;
            let mut index = 0usize;
            while index < limit_index && out.len() < limit {
                let state = base + (offset + index) as u64;
                if index & 0xF == 0
                    && bytes[index] == tag
                    && near(process, state, qword(&bytes, index + 0x08))
                    && near(process, state, qword(&bytes, index + 0x10))
                    && near(process, state, qword(&bytes, index + 0x18))
                    && near(process, state, qword(&bytes, index + 0x28))
                    && near(process, state, qword(&bytes, index + 0x30))
                {
                    out.push(state);
                }
                index += 8;
            }
            if chunk <= HEADER_SPAN {
                break;
            }
            offset += chunk - HEADER_SPAN;
        }
    }
    (out, scanned)
}

fn heap_ptr(value: u64) -> bool {
    value > 0x10000 && value < 0x0000_7FFF_FFFF_FFFF && value & 0xF == 0
}

/// A pointer that belongs to the same private heap as `state`: aligned, close
/// enough to be a real allocation, and inside a `MEM_PRIVATE` region.
fn near(process: &Process, state: u64, value: u64) -> bool {
    if !heap_ptr(value) {
        return false;
    }
    if value.abs_diff(state) > 0x4_0000_0000 {
        return false;
    }
    region_kind(process, value) == MEM_PRIVATE
}

/// A `TValue` stack found without knowing the thread layout: sixteen-byte
/// slots whose tag word (`+0x0C`) is a legal type for a long run. Any real
/// thread owns one of these, and the thread that owns it points at its base.
pub struct StackRun {
    pub base: u64,
    pub slots: usize,
}

pub fn find_stacks(process: &Process, cap: usize, limit: usize) -> (Vec<StackRun>, usize) {
    let mut out: Vec<StackRun> = Vec::new();
    let mut scanned = 0usize;
    for (base, size) in regions(process) {
        if scanned >= cap || out.len() >= limit {
            break;
        }
        let span = size.min(cap - scanned);
        scanned += span;
        let mut offset = 0usize;
        while offset < span && out.len() < limit {
            let chunk = (span - offset).min(CHUNK);
            let Some(bytes) = process.read(base + offset as u64, chunk) else {
                offset += chunk;
                continue;
            };
            let mut index = 0usize;
            let mut run = 0usize;
            let mut run_start = 0usize;
            let mut gc = 0usize;
            while index + 16 <= bytes.len() {
                let tag = u32::from_le_bytes(bytes[index + 12..index + 16].try_into().unwrap());
                let legal = tag < 0x10;
                if legal {
                    if run == 0 {
                        run_start = index;
                        gc = 0;
                    }
                    run += 1;
                    if tag as u8 >= 6 {
                        gc += 1;
                    }
                } else {
                    if run >= 32 && gc >= 6 {
                        out.push(StackRun {
                            base: base + (offset + run_start) as u64,
                            slots: run,
                        });
                    }
                    run = 0;
                }
                index += 16;
            }
            if run >= 32 && gc >= 6 {
                out.push(StackRun {
                    base: base + (offset + run_start) as u64,
                    slots: run,
                });
            }
            offset += chunk;
        }
    }
    out.sort_by_key(|run| std::cmp::Reverse(run.slots));
    out.truncate(limit);
    (out, scanned)
}

/// A `TValue` stack plus the two places in memory that reference it as a
/// `(stack, stack_last)` pair, found in one snapshot so addresses agree.
pub struct Hunt {
    pub stack: u64,
    pub slots: usize,
    pub pairs: Vec<(u64, u64)>,
}

/// One snapshot: find TValue-array runs, then for each place that references a
/// run base, look nearby for a larger pointer into the same run — that second
/// word is `stack_last`, and the struct holding both is the thread.
pub fn lua_hunt(process: &Process, cap: usize) -> Hunt {
    let (runs, _) = find_stacks(process, cap, 6);
    let mut pairs = Vec::new();
    let mut chosen = 0u64;
    let mut chosen_slots = 0usize;
    for run in &runs {
        let mut hits = Vec::new();
        for (base, size) in regions(process) {
            if hits.len() >= 16 {
                break;
            }
            hits.extend(find_value_in_region(process, base, size, run.base, 16));
        }
        for slot in hits {
            let from = slot.saturating_sub(0x200) & !0xF;
            let Some(window) = process.read(from, 0x400) else {
                continue;
            };
            for index in (0..window.len().saturating_sub(8)).step_by(8) {
                let value = qword(&window, index);
                if value > run.base
                    && value - run.base <= 0x8_0000
                    && value & 0xF == 0
                    && base_differs(value, &window, run.base)
                {
                    pairs.push((slot, from + index as u64));
                    chosen = run.base;
                    chosen_slots = run.slots;
                    break;
                }
            }
        }
        if !pairs.is_empty() {
            break;
        }
    }
    Hunt {
        stack: chosen,
        slots: chosen_slots,
        pairs,
    }
}

fn base_differs(value: u64, window: &[u8], base: u64) -> bool {
    value != base && value != 0 && !window.is_empty()
}

/// Threads found by the tag alone, then verified by looking for a `TValue`
/// array inside the object. Roblox ships a modified `lua_State`, so the field
/// offsets cannot be trusted; the stack a thread owns can.
pub struct ThreadHit {
    pub state: u64,
    pub stack_at: usize,
    pub stack: u64,
    pub slots: usize,
}

pub fn find_threads_by_tag(process: &Process, cap: usize, limit: usize) -> (Vec<ThreadHit>, usize) {
    let mut out = Vec::new();
    let mut scanned = 0usize;
    for (base, size) in regions(process) {
        if scanned >= cap || out.len() >= limit {
            break;
        }
        let span = size.min(cap - scanned);
        scanned += span;
        let mut offset = 0usize;
        while offset < span && out.len() < limit {
            let chunk = (span - offset).min(CHUNK);
            let Some(bytes) = process.read(base + offset as u64, chunk) else {
                offset += chunk;
                continue;
            };
            let mut index = 0usize;
            while index + 0x100 <= bytes.len() && out.len() < limit {
                if bytes[index] == 9 {
                    let state = base + (offset + index) as u64;
                    for slot in (0x08..0x100).step_by(8) {
                        let pointer = qword(&bytes, index + slot);
                        if !heap_ptr(pointer) {
                            continue;
                        }
                        if let Some(slots) = stack_like(process, pointer) {
                            out.push(ThreadHit {
                                state,
                                stack_at: slot,
                                stack: pointer,
                                slots,
                            });
                            break;
                        }
                    }
                }
                index += 8;
            }
            if chunk <= 0x100 {
                break;
            }
            offset += chunk;
        }
    }
    (out, scanned)
}

/// A run of at least eight sixteen-byte slots whose tag word is a legal type.
fn stack_like(process: &Process, pointer: u64) -> Option<usize> {
    if pointer & 0xF != 0 || region_kind(process, pointer) != MEM_PRIVATE {
        return None;
    }
    let bytes = process.read(pointer, 0x100)?;
    let mut slots = 0usize;
    let mut live = 0usize;
    for slot in bytes.chunks_exact(16) {
        let tag = u32::from_le_bytes(slot[12..16].try_into().unwrap());
        if tag >= 0x10 {
            break;
        }
        slots += 1;
        if tag != 0 {
            live += 1;
        }
    }
    if slots >= 8 && live >= 3 {
        Some(slots)
    } else {
        None
    }
}

pub fn hex(process: &Process, address: u64, len: usize) -> String {
    let Some(bytes) = process.read(address, len) else {
        return format!("  {address:#X}: <unreadable>\n");
    };
    let mut out = String::new();
    for (row, line) in bytes.chunks(16).enumerate() {
        out.push_str(&format!("  {:016X}  ", address + (row * 16) as u64));
        for byte in line {
            out.push_str(&format!("{byte:02X} "));
        }
        for _ in line.len()..16 {
            out.push_str("   ");
        }
        out.push_str(" |");
        for byte in line {
            let ch = if (0x20..0x7F).contains(byte) { *byte as char } else { '.' };
            out.push(ch);
        }
        out.push_str("|\n");
    }
    out
}

