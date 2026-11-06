//! zeno-hyperion — the detector rebuilt from the three shapes that already killed
//! the client.
//!
//! This is not an emulator of the compiled predicate; that predicate lives in
//! 100 MB of `.text` with no symbol we can name. This is a model of *what a
//! predicate can observe*: the finite set of differences between a clean
//! process and a tampered one. Every rule is derived from a verified fatality
//! against the live f0ea client, not from a guess about its source.
//!
//!   R1  an image view that no loader entry owns        (new SEC_IMAGE map)
//!   R2  a private executable region outside modules    (code in anonymous memory)
//!   R3  an image code page that stopped being shared   (private copy of .text)
//!
//! R3 is the only rule that sees a byte-identical rewrite. The content hash is
//! unchanged; the PTE lost `Shared`. That is why the check lives at the PTE and
//! not at the bytes — and why a hash-based detector would have missed it.
//!
//! Absolute counts are not verdicts. A clean CLR process has RWX JIT pages and
//! private copies of its own image; a clean Win32 process has one padding page
//! past the end of every module. Rules therefore report only relative to a
//! baseline recorded while the process was known clean, plus the shapes that
//! cannot occur innocently (an unowned image view carrying a real PE header).
//!
//! Exit codes: 0 clean, 2 tripped, 1 could not run.

#![allow(non_snake_case)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;

type Handle = *mut c_void;

const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;

const MEM_COMMIT: u32 = 0x1000;
const MEM_IMAGE: u32 = 0x0100_0000;
const MEM_PRIVATE: u32 = 0x0002_0000;

const PAGE_SIZE: u64 = 0x1000;
const MAX_REGIONS: usize = 1 << 20;
const WS_BATCH: usize = 4096;
const PRINT_LIMIT: usize = 24;

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
    fn VirtualQueryEx(
        process: Handle,
        address: *const c_void,
        buffer: *mut c_void,
        length: usize,
    ) -> usize;
    fn ReadProcessMemory(
        process: Handle,
        address: *const c_void,
        buffer: *mut c_void,
        length: usize,
        read: *mut usize,
    ) -> i32;
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn VirtualAllocEx(
        process: Handle,
        address: *mut c_void,
        size: usize,
        allocation: u32,
        protect: u32,
    ) -> *mut c_void;
    fn VirtualProtectEx(
        process: Handle,
        address: *mut c_void,
        size: usize,
        protect: u32,
        previous: *mut u32,
    ) -> i32;
    fn WriteProcessMemory(
        process: Handle,
        address: *mut c_void,
        buffer: *const c_void,
        length: usize,
        written: *mut usize,
    ) -> i32;
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

#[link(name = "ntdll")]
extern "system" {
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
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process: Handle,
        class: u32,
        info: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

type QueryWorkingSetExFn =
    unsafe extern "system" fn(Handle, *mut PsapiWorkingSetExInformation, u32) -> i32;

#[repr(C)]
#[derive(Clone, Copy)]
struct PsapiWorkingSetExInformation {
    virtual_address: u64,
    attributes: u64,
}

#[derive(Clone)]
struct Module {
    name: String,
    base: u64,
    size: u64,
}

impl Module {
    /// The view the loader maps is the section, not `SizeOfImage`: it is page
    /// aligned and commonly one page longer than the header claims. Measured on
    /// every module in a clean process — the trailing page is reported as its
    /// own region with the code protection.
    fn span_end(&self) -> u64 {
        align_up(self.base + self.size, PAGE_SIZE) + PAGE_SIZE
    }
}

#[derive(Clone, Copy)]
struct Region {
    base: u64,
    size: u64,
    state: u32,
    protect: u32,
    kind: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rule {
    R1,
    R2,
    R3,
}

impl Rule {
    fn tag(self) -> &'static str {
        match self {
            Rule::R1 => "R1",
            Rule::R2 => "R2",
            Rule::R3 => "R3",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Rule::R1 => "unowned image view with PE header",
            Rule::R2 => "private executable region",
            Rule::R3 => "image page lost its shared bit",
        }
    }

    fn index(self) -> usize {
        match self {
            Rule::R1 => 0,
            Rule::R2 => 1,
            Rule::R3 => 2,
        }
    }
}

struct Finding {
    rule: Rule,
    address: u64,
    size: u64,
    protect: u32,
    detail: String,
}

#[derive(Default)]
struct Baseline {
    modules: Vec<(u64, u64)>,
    pages: HashMap<u64, bool>,
    private_exec: Vec<u64>,
    unowned_image: Vec<u64>,
}

impl Baseline {
    /// A page inside a module that was already loaded when the baseline was
    /// taken can be judged; one inside a module that appeared later cannot,
    /// because its pages were never observed in a clean state.
    fn covers(&self, address: u64) -> bool {
        self.modules
            .iter()
            .any(|(base, size)| address >= *base && address < *base + *size)
    }
}

struct Report {
    findings: Vec<Finding>,
    counts: [u64; 3],
    informational: [u64; 3],
    modules: usize,
    image_regions: usize,
    private_regions: usize,
    code_pages: u64,
    shared_code_pages: u64,
}

impl Report {
    fn tripped(&self) -> bool {
        self.counts.iter().any(|count| *count > 0)
    }
}

struct Options {
    module: Option<String>,
    strict: bool,
}

fn main() {
    if let Err(message) = run() {
        eprintln!("hyperion    error: {message}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mode = argv.first().map(String::as_str).unwrap_or("help");

    let mut positional: Vec<&str> = Vec::new();
    let mut options = Options {
        module: None,
        strict: false,
    };
    let mut rest = argv.iter().skip(1).map(String::as_str).peekable();
    while let Some(arg) = rest.next() {
        match arg {
            "--module" => options.module = rest.next().map(|text| text.to_lowercase()),
            "--strict" => options.strict = true,
            _ => positional.push(arg),
        }
    }

    match mode {
        "scan" | "stats" | "watch" | "probe" | "baseline" | "modules" | "selftest" => {}
        _ => {
            usage();
            return Ok(());
        }
    }

    if mode == "selftest" {
        return selftest();
    }

    let pid = positional
        .first()
        .ok_or("missing pid")?
        .parse::<u32>()
        .map_err(|_| "pid is not a number".to_string())?;

    match mode {
        "scan" => {
            let handle = open(pid)?;
            let baseline = match positional.get(1) {
                Some(path) if *path != "-" => Some(load_baseline(Path::new(path))?),
                _ => None,
            };
            let report = scan(handle, baseline.as_ref(), &options);
            unsafe { CloseHandle(handle) };
            print_report(&report, baseline.is_some());
            std::process::exit(if report.tripped() { 2 } else { 0 });
        }
        "stats" => {
            let handle = open(pid)?;
            let report = scan(handle, None, &options);
            unsafe { CloseHandle(handle) };
            print_stats(&report);
        }
        "watch" => {
            let handle = open(pid)?;
            let seconds = positional
                .get(1)
                .and_then(|text| text.parse::<u64>().ok())
                .unwrap_or(60);
            let result = watch(handle, seconds);
            unsafe { CloseHandle(handle) };
            std::process::exit(match result {
                Ok(true) => 2,
                Ok(false) => 0,
                Err(message) => {
                    eprintln!("hyperion    error: {message}");
                    1
                }
            });
        }
        "probe" => {
            let handle = open(pid)?;
            let address = parse_hex(positional.get(1).ok_or("missing address")?)?;
            probe(handle, address);
            unsafe { CloseHandle(handle) };
        }
        "baseline" => {
            let handle = open(pid)?;
            let path = positional.get(1).ok_or("missing output path")?;
            let written = write_baseline(handle, Path::new(path))?;
            unsafe { CloseHandle(handle) };
            println!("hyperion    baseline {written} pages -> {path}");
        }
        "modules" => {
            let handle = open(pid)?;
            let modules = modules_of(handle);
            unsafe { CloseHandle(handle) };
            println!("hyperion    {} modules", modules.len());
            for module in &modules {
                println!(
                    "hyperion      {:016X} +{:08X}  {}",
                    module.base, module.size, module.name
                );
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn usage() {
    println!(
        "zeno-hyperion <mode> <pid> [args]\n\
         \n\
         scan <pid> [baseline|-]   one pass, exit 2 when tripped\n\
         watch <pid> [seconds]     baseline, then poll once a second\n\
         stats <pid>               aggregate counts, nothing printed per page\n\
         probe <pid> <addr>        decode one page's working-set entry\n\
         baseline <pid> <file>     record a clean process' observable state\n\
         modules <pid>             loader list as the scanner reads it\n\
         selftest                  spawn sacrificial processes, replay R1/R2/R3\n\
         \n\
         --module <name>           R3 only inside modules matching the substring\n\
         --strict                  absent baseline, treat counts as findings"
    );
}

fn open(pid: u32) -> Result<Handle, String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe {
            GetLastError()
        }));
    }
    Ok(handle)
}

fn parse_hex(text: &str) -> Result<u64, String> {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).map_err(|_| format!("bad hex {text}"))
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

fn modules_of(handle: Handle) -> Vec<Module> {
    // Toolhelp is refused on the protected client, so the loader list comes out
    // of the PEB directly: PEB -> Ldr -> InMemoryOrderModuleList.
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
        return Vec::new();
    }
    let peb = u64::from_le_bytes(info[8..16].try_into().unwrap());
    let ldr = read_u64(handle, peb + 0x18);
    if ldr == 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let list_head = ldr + 0x20;
    let mut link = read_u64(handle, list_head);
    for _ in 0..512 {
        if link == 0 || link == list_head {
            break;
        }
        let entry = link.wrapping_sub(0x10);
        let base = read_u64(handle, entry + 0x30);
        let size = read_u64(handle, entry + 0x40) & 0xFFFF_FFFF;
        let name_len = read_u64(handle, entry + 0x58) & 0xFFFF;
        let name_ptr = read_u64(handle, entry + 0x60);

        let mut name = String::new();
        if name_len > 0 && name_len < 0x400 && name_ptr != 0 {
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
                name = String::from_utf16_lossy(&units)
                    .trim_end_matches('\0')
                    .to_string();
            }
        }
        if base != 0 && size != 0 {
            out.push(Module { name, base, size });
        }
        link = read_u64(handle, link);
    }
    out
}

fn read_u64(handle: Handle, address: u64) -> u64 {
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
        value
    } else {
        0
    }
}

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
    if ok != 0 && got == length {
        Some(buffer)
    } else {
        None
    }
}

fn regions(handle: Handle) -> Vec<Region> {
    let mut out = Vec::new();
    let mut address = 0x10000u64;
    let mut info = [0u8; 48];

    while address < 0x7FFF_FFFF_0000 && out.len() < MAX_REGIONS {
        let got = unsafe {
            VirtualQueryEx(
                handle,
                address as *const c_void,
                info.as_mut_ptr() as *mut c_void,
                info.len(),
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
        out.push(Region {
            base,
            size,
            state,
            protect,
            kind,
        });
        let next = base + size;
        if next <= address {
            break;
        }
        address = next;
    }
    out
}

fn is_executable(protect: u32) -> bool {
    matches!(protect & 0xFF, 0x10 | 0x20 | 0x40 | 0x80)
}

fn owner<'a>(modules: &'a [Module], address: u64) -> Option<&'a Module> {
    modules
        .iter()
        .find(|module| address >= module.base && address < module.span_end())
}

fn describe(modules: &[Module], address: u64) -> String {
    match owner(modules, address) {
        Some(module) => format!(
            "{} +0x{:X}",
            module.name.rsplit(['\\', '/']).next().unwrap_or(&module.name),
            address - module.base
        ),
        None => "no module".to_string(),
    }
}

/// True when the page begins with an actual mapped PE image. A region past the
/// end of a module is padding from the section view and has no header; a view
/// mapped by an injector does, and that is the shape R1 exists to name.
fn pe_image_at(handle: Handle, address: u64) -> bool {
    let Some(header) = read_bytes(handle, address, 0x40) else {
        return false;
    };
    if &header[0..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes(header[0x3C..0x40].try_into().unwrap()) as u64;
    if e_lfanew < 0x40 || e_lfanew > 0x400 {
        return false;
    }
    match read_bytes(handle, address + e_lfanew, 4) {
        Some(signature) => &signature[..] == b"PE\0\0",
        None => false,
    }
}

fn query_working_set_ex() -> Option<QueryWorkingSetExFn> {
    for (library, symbol) in [
        ("kernel32.dll", "K32QueryWorkingSetEx"),
        ("psapi.dll", "QueryWorkingSetEx"),
    ] {
        let Some(module) = load_library(library) else {
            continue;
        };
        let mut name: Vec<u8> = symbol.bytes().collect();
        name.push(0);
        let address = unsafe { GetProcAddress(module, name.as_ptr()) };
        if !address.is_null() {
            return Some(unsafe { std::mem::transmute::<*mut c_void, QueryWorkingSetExFn>(address) });
        }
    }
    None
}

fn load_library(name: &str) -> Option<*mut c_void> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };
    if module.is_null() {
        None
    } else {
        Some(module)
    }
}

/// Per-page working-set attributes for one contiguous run of pages.
fn working_set(query: QueryWorkingSetExFn, handle: Handle, base: u64, pages: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(pages);
    let mut buffer: Vec<PsapiWorkingSetExInformation> = vec![
        PsapiWorkingSetExInformation {
            virtual_address: 0,
            attributes: 0,
        };
        pages.min(WS_BATCH)
    ];
    let mut done = 0usize;
    while done < pages {
        let batch = (pages - done).min(WS_BATCH);
        for slot in 0..batch {
            buffer[slot].virtual_address = base + ((done + slot) as u64) * PAGE_SIZE;
            buffer[slot].attributes = 0;
        }
        let ok = unsafe {
            query(
                handle,
                buffer.as_mut_ptr(),
                (batch * std::mem::size_of::<PsapiWorkingSetExInformation>()) as u32,
            )
        };
        if ok == 0 {
            break;
        }
        for slot in 0..batch {
            out.push(buffer[slot].attributes);
        }
        done += batch;
    }
    out
}

fn ws_valid(attributes: u64) -> bool {
    attributes & 1 != 0
}

fn ws_shared(attributes: u64) -> bool {
    (attributes >> 15) & 1 != 0
}

fn ws_protect(attributes: u64) -> u32 {
    ((attributes >> 4) & 0x7FF) as u32
}

fn scan(handle: Handle, baseline: Option<&Baseline>, options: &Options) -> Report {
    let query = query_working_set_ex();
    let modules = modules_of(handle);
    let memory = regions(handle);

    let mut report = Report {
        findings: Vec::new(),
        counts: [0; 3],
        informational: [0; 3],
        modules: modules.len(),
        image_regions: 0,
        private_regions: 0,
        code_pages: 0,
        shared_code_pages: 0,
    };

    let in_scope = |module: &Module| match options.module.as_deref() {
        Some(pattern) => module.name.to_lowercase().contains(pattern),
        None => true,
    };

    for region in &memory {
        if region.state != MEM_COMMIT {
            continue;
        }
        match region.kind {
            MEM_IMAGE => {
                report.image_regions += 1;
                match owner(&modules, region.base) {
                    None => {
                        // Padding past a module is unowned but headerless. Only a
                        // mapped image carries an MZ/PE signature.
                        if pe_image_at(handle, region.base) {
                            let known = baseline
                                .map(|base| base.unowned_image.contains(&region.base))
                                .unwrap_or(false);
                            if known {
                                continue;
                            }
                            report.counts[Rule::R1.index()] += 1;
                            push(
                                &mut report,
                                Finding {
                                    rule: Rule::R1,
                                    address: region.base,
                                    size: region.size,
                                    protect: region.protect,
                                    detail: describe(&modules, region.base),
                                },
                            );
                        } else {
                            report.informational[Rule::R1.index()] += 1;
                        }
                        continue;
                    }
                    Some(module) => {
                        if !in_scope(module) || !is_executable(region.protect) {
                            continue;
                        }
                    }
                }

                let Some(query) = query else { continue };
                let pages = (region.size / PAGE_SIZE) as usize;
                let attributes = working_set(query, handle, region.base, pages);
                for (index, entry) in attributes.iter().enumerate() {
                    if !ws_valid(*entry) {
                        continue;
                    }
                    report.code_pages += 1;
                    let shared = ws_shared(*entry);
                    if shared {
                        report.shared_code_pages += 1;
                        continue;
                    }
                    let address = region.base + (index as u64) * PAGE_SIZE;
                    let detail = describe(&modules, address);
                    let reported = match baseline {
                        None => options.strict && options.module.is_some(),
                        Some(base) => {
                            if !base.covers(address) {
                                continue;
                            }
                            // Shared then, private now — the footprint of a
                            // rewrite. A page absent from the baseline was not
                            // resident yet: resident image code is always the
                            // file view, so private still means written.
                            !matches!(base.pages.get(&address), Some(false))
                        }
                    };
                    if !reported {
                        report.informational[Rule::R3.index()] += 1;
                        continue;
                    }
                    report.counts[Rule::R3.index()] += 1;
                    push(
                        &mut report,
                        Finding {
                            rule: Rule::R3,
                            address,
                            size: PAGE_SIZE,
                            protect: ws_protect(*entry),
                            detail,
                        },
                    );
                }
            }
            MEM_PRIVATE => {
                report.private_regions += 1;
                if !is_executable(region.protect) || owner(&modules, region.base).is_some() {
                    continue;
                }
                let known = baseline
                    .map(|base| base.private_exec.contains(&region.base))
                    .unwrap_or(false);
                if known {
                    continue;
                }
                let reportable = baseline.is_some() || options.strict;
                if !reportable {
                    report.informational[Rule::R2.index()] += 1;
                    continue;
                }
                report.counts[Rule::R2.index()] += 1;
                push(
                    &mut report,
                    Finding {
                        rule: Rule::R2,
                        address: region.base,
                        size: region.size,
                        protect: region.protect,
                        detail: format!("{} bytes anonymous", region.size),
                    },
                );
            }
            _ => {}
        }
    }

    report
}

fn push(report: &mut Report, finding: Finding) {
    if report.findings.len() < 512 {
        report.findings.push(finding);
    }
}

fn print_report(report: &Report, differential: bool) {
    println!(
        "hyperion    {} modules, {} image regions, {} private regions, {}/{} code pages shared",
        report.modules,
        report.image_regions,
        report.private_regions,
        report.shared_code_pages,
        report.code_pages
    );

    for rule in [Rule::R1, Rule::R2, Rule::R3] {
        let count = report.counts[rule.index()];
        let noise = report.informational[rule.index()];
        let shown = report
            .findings
            .iter()
            .filter(|finding| finding.rule == rule)
            .count();
        println!(
            "hyperion    {} {:<38} {:>6}{}{}",
            rule.tag(),
            rule.label(),
            count,
            if noise > 0 {
                format!("  (+{noise} known)")
            } else {
                String::new()
            },
            if count as usize > shown {
                format!("  (showing {shown})")
            } else {
                String::new()
            }
        );
        for finding in report
            .findings
            .iter()
            .filter(|finding| finding.rule == rule)
            .take(PRINT_LIMIT)
        {
            println!(
                "hyperion      {:016X} +{:08X} prot 0x{:02X}  {}",
                finding.address, finding.size, finding.protect, finding.detail
            );
        }
    }

    println!(
        "hyperion    verdict: {}{}",
        if report.tripped() { "tripped" } else { "clean" },
        if differential {
            " (against baseline)"
        } else {
            ""
        }
    );
}

fn print_stats(report: &Report) {
    println!("hyperion    modules           {}", report.modules);
    println!("hyperion    image regions     {}", report.image_regions);
    println!("hyperion    private regions   {}", report.private_regions);
    println!(
        "hyperion    code pages        {} ({} shared, {} private)",
        report.code_pages,
        report.shared_code_pages,
        report.code_pages.saturating_sub(report.shared_code_pages)
    );
    println!(
        "hyperion    R1 unowned images  {} finding, {} padding pages",
        report.counts[0], report.informational[0]
    );
    println!(
        "hyperion    R2 private exec   {} finding, {} known-shape",
        report.counts[1], report.informational[1]
    );
    println!(
        "hyperion    R3 private code   {} finding, {} known-shape",
        report.counts[2], report.informational[2]
    );
}

fn snapshot(handle: Handle) -> Result<Baseline, String> {
    let query = query_working_set_ex().ok_or("QueryWorkingSetEx unavailable")?;
    let modules = modules_of(handle);
    let memory = regions(handle);

    let mut baseline = Baseline {
        modules: modules
            .iter()
            .map(|module| (module.base, module.span_end() - module.base))
            .collect(),
        ..Default::default()
    };

    for region in &memory {
        if region.state != MEM_COMMIT {
            continue;
        }
        match region.kind {
            MEM_IMAGE => {
                if owner(&modules, region.base).is_none() {
                    if pe_image_at(handle, region.base) {
                        baseline.unowned_image.push(region.base);
                    }
                    continue;
                }
                let count = (region.size / PAGE_SIZE) as usize;
                let attributes = working_set(query, handle, region.base, count);
                for (index, entry) in attributes.iter().enumerate() {
                    if !ws_valid(*entry) {
                        continue;
                    }
                    baseline.pages.insert(
                        region.base + (index as u64) * PAGE_SIZE,
                        ws_shared(*entry),
                    );
                }
            }
            MEM_PRIVATE => {
                if is_executable(region.protect) && owner(&modules, region.base).is_none() {
                    baseline.private_exec.push(region.base);
                }
            }
            _ => {}
        }
    }
    Ok(baseline)
}

fn write_baseline(handle: Handle, path: &Path) -> Result<usize, String> {
    let baseline = snapshot(handle)?;
    let mut text = String::from("# zeno-hyperion baseline v2\n");
    for (base, size) in &baseline.modules {
        text.push_str(&format!("M {base:016X} {size:016X}\n"));
    }
    for (address, shared) in &baseline.pages {
        text.push_str(&format!("P {address:016X} {}\n", *shared as u8));
    }
    for base in &baseline.private_exec {
        text.push_str(&format!("E {base:016X}\n"));
    }
    for base in &baseline.unowned_image {
        text.push_str(&format!("I {base:016X}\n"));
    }
    std::fs::write(path, text.as_bytes()).map_err(|error| error.to_string())?;
    Ok(baseline.pages.len())
}

fn load_baseline(path: &Path) -> Result<Baseline, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let mut baseline = Baseline::default();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(tag) = parts.next() else { continue };
        match tag {
            "M" => {
                let base = parse_hex(parts.next().ok_or("bad module line")?)?;
                let size = parse_hex(parts.next().ok_or("bad module line")?)?;
                baseline.modules.push((base, size));
            }
            "P" => {
                let address = parse_hex(parts.next().ok_or("bad page line")?)?;
                let shared = parts.next().ok_or("bad page line")? == "1";
                baseline.pages.insert(address, shared);
            }
            "E" => baseline
                .private_exec
                .push(parse_hex(parts.next().ok_or("bad exec line")?)?),
            "I" => baseline
                .unowned_image
                .push(parse_hex(parts.next().ok_or("bad image line")?)?),
            _ => {}
        }
    }
    Ok(baseline)
}

fn probe(handle: Handle, address: u64) {
    let Some(query) = query_working_set_ex() else {
        println!("hyperion    QueryWorkingSetEx unavailable");
        return;
    };
    let modules = modules_of(handle);
    let page = address & !(PAGE_SIZE - 1);
    let attributes = working_set(query, handle, page, 1);
    let Some(entry) = attributes.first() else {
        println!("hyperion    page {page:016X} not queryable");
        return;
    };
    println!(
        "hyperion    page {:016X}  {}  valid {} shared {} protect 0x{:02X}  raw {:016X}",
        page,
        describe(&modules, page),
        ws_valid(*entry) as u8,
        ws_shared(*entry) as u8,
        ws_protect(*entry),
        entry
    );
    if let Some(bytes) = read_bytes(handle, page, 32) {
        println!(
            "hyperion    bytes {}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    let memory = regions(handle);
    if let Some(region) = memory
        .iter()
        .find(|region| page >= region.base && page < region.base + region.size)
    {
        println!(
            "hyperion    region base {:016X} +{:08X} state 0x{:X} kind 0x{:X} protect 0x{:02X}",
            region.base, region.size, region.state, region.kind, region.protect
        );
    }
}

fn watch(handle: Handle, seconds: u64) -> Result<bool, String> {    let baseline = snapshot(handle)?;
    println!(
        "hyperion    baseline: {} modules, {} pages, {} private exec, {} unowned images",
        baseline.modules.len(),
        baseline.pages.len(),
        baseline.private_exec.len(),
        baseline.unowned_image.len()
    );
    let options = Options {
        module: None,
        strict: false,
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let mut tick = 0u64;

    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_secs(1));
        tick += 1;
        let report = scan(handle, Some(&baseline), &options);
        if report.tripped() {
            println!("hyperion    t+{tick}s TRIPPED");
            print_report(&report, true);
            return Ok(true);
        }
        if tick % 5 == 0 {
            println!("hyperion    t+{tick}s clean");
        }
    }
    println!("hyperion    t+{tick}s clean, window closed");
    Ok(false)
}

// ---------------------------------------------------------------------------
// selftest — replay the three shapes against sacrificial processes.
//
// The detector is only worth using as a gate if it actually fires on the cases
// that already killed the client, and stays quiet on an untouched process. Each
// case spawns its own target, takes a baseline, applies exactly one shape, and
// scans. No execution happens in the R2 case: the region is allocated RWX and
// written, which is all the scanner needs to see.
// ---------------------------------------------------------------------------

fn open_full(pid: u32) -> Result<Handle, String> {
    let handle = unsafe { OpenProcess(0x001F_0FFF, 0, pid) };
    if handle.is_null() || handle == -1isize as Handle {
        return Err(format!("OpenProcess({pid}) failed ({})", unsafe {
            GetLastError()
        }));
    }
    Ok(handle)
}

fn spawn_sacrifice() -> Result<std::process::Child, String> {
    let child = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "Start-Sleep -Seconds 45",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| format!("spawn failed: {error}"))?;
    std::thread::sleep(std::time::Duration::from_millis(1500));
    Ok(child)
}

fn selftest() -> Result<(), String> {
    println!("hyperion    selftest — one negative control, three replayed positives");
    let mut failures = 0usize;

    failures += case("negative", None, |_, _| Ok(()));
    failures += case("shape R1", Some(Rule::R1), shape_image_view);
    failures += case("shape R2", Some(Rule::R2), shape_private_exec);
    failures += case("shape R3", Some(Rule::R3), shape_private_code);

    if failures == 0 {
        println!("hyperion    selftest passed");
        Ok(())
    } else {
        println!("hyperion    selftest failed: {failures}/4");
        std::process::exit(2);
    }
}

fn case(
    label: &str,
    expected: Option<Rule>,
    inject: impl FnOnce(Handle, u32) -> Result<(), String>,
) -> usize {
    let mut failures = 0usize;
    let child = match spawn_sacrifice() {
        Ok(child) => child,
        Err(error) => {
            println!("hyperion    {label:<10} ERROR {error}");
            return 1;
        }
    };
    let mut child = child;
    let pid = child.id();

    let outcome = (|| -> Result<(), String> {
        let handle = open_full(pid)?;
        let baseline = snapshot(handle)?;
        inject(handle, pid)?;
        let report = scan(
            handle,
            Some(&baseline),
            &Options {
                module: None,
                strict: false,
            },
        );
        unsafe { CloseHandle(handle) };

        let hit = match expected {
            Some(rule) => report.counts[rule.index()] > 0,
            None => !report.tripped(),
        };
        println!(
            "hyperion    {label:<10} {}  R1 {} R2 {} R3 {}",
            if hit { "PASS" } else { "FAIL" },
            report.counts[0],
            report.counts[1],
            report.counts[2]
        );
        if !hit {
            print_report(&report, true);
            failures += 1;
        }
        Ok(())
    })();

    if let Err(error) = outcome {
        println!("hyperion    {label:<10} ERROR {error}");
        failures += 1;
    }
    let _ = child.kill();
    let _ = child.wait();
    failures
}

/// R1 — a fresh `SEC_IMAGE` view. The header page carries a real PE signature,
/// which is what separates it from the headerless padding page every module has
/// past its end.
fn shape_image_view(handle: Handle, _pid: u32) -> Result<(), String> {
    let path = std::env::current_exe().map_err(|error| error.to_string())?;
    let absolute = std::fs::canonicalize(&path).map_err(|error| error.to_string())?;
    let wide: Vec<u16> = absolute
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let file = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0x8000_0000,
            0x0000_0007,
            std::ptr::null_mut(),
            3,
            0x80,
            std::ptr::null_mut(),
        )
    };
    if file.is_null() || file == -1isize as Handle {
        return Err(format!("CreateFileW failed ({})", unsafe { GetLastError() }));
    }

    let mut section: Handle = std::ptr::null_mut();
    let mut max_size: i64 = 0;
    let status = unsafe {
        NtCreateSection(
            &mut section,
            0x000F_001F,
            std::ptr::null_mut(),
            &mut max_size,
            0x02,
            0x0100_0000,
            file,
        )
    };
    unsafe { CloseHandle(file) };
    if status != 0 {
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
            1,
            0,
            0x02,
        )
    };
    if status != 0 {
        return Err(format!("NtMapViewOfSection failed 0x{:X}", status as u32));
    }
    println!(
        "hyperion    shape R1 image view at 0x{:X} (+0x{:X})",
        base as u64, size
    );
    Ok(())
}

/// R2 — executable anonymous memory. Written once, never entered.
fn shape_private_exec(handle: Handle, _pid: u32) -> Result<(), String> {
    let remote = unsafe {
        VirtualAllocEx(
            handle,
            std::ptr::null_mut(),
            PAGE_SIZE as usize,
            0x3000,
            0x40,
        )
    };
    if remote.is_null() {
        return Err(format!("VirtualAllocEx failed ({})", unsafe { GetLastError() }));
    }
    let stub: [u8; 6] = [0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3];
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            handle,
            remote,
            stub.as_ptr() as *const c_void,
            stub.len(),
            &mut written,
        )
    };
    if ok == 0 {
        return Err(format!(
            "WriteProcessMemory failed ({})",
            unsafe { GetLastError() }
        ));
    }
    println!(
        "hyperion    shape R2 private RWX at 0x{:X} (never executed)",
        remote as u64
    );
    Ok(())
}

/// R3 — the interesting one. The bytes written are the bytes already there; the
/// only lasting difference is that the code page stops being the shared file
/// view. On the client this exact shape was fatal at t+15 s.
fn shape_private_code(handle: Handle, _pid: u32) -> Result<(), String> {
    let modules = modules_of(handle);
    let executable = modules
        .iter()
        .find(|module| module.name.to_lowercase().ends_with(".exe"))
        .ok_or("no executable module")?;
    let memory = regions(handle);
    let region = memory
        .iter()
        .find(|region| {
            region.state == MEM_COMMIT
                && region.kind == MEM_IMAGE
                && region.protect == 0x20
                && region.size >= PAGE_SIZE
                && region.base >= executable.base
                && region.base < executable.base + executable.size
        })
        .ok_or("no executable image region")?;
    let page = region.base;
    let original = read_bytes(handle, page, 16).ok_or("cannot read code page")?;

    let mut previous = 0u32;
    let mut protected = 0;
    for want in [0x40u32, 0x80, 0x04] {
        protected = unsafe {
            VirtualProtectEx(
                handle,
                page as *mut c_void,
                PAGE_SIZE as usize,
                want,
                &mut previous,
            )
        };
        if protected != 0 {
            break;
        }
    }
    if protected == 0 {
        return Err(format!("VirtualProtectEx failed ({})", unsafe {
            GetLastError()
        }));
    }

    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            handle,
            page as *mut c_void,
            original.as_ptr() as *const c_void,
            original.len(),
            &mut written,
        )
    };
    unsafe {
        VirtualProtectEx(
            handle,
            page as *mut c_void,
            PAGE_SIZE as usize,
            previous,
            &mut previous,
        )
    };
    if ok == 0 {
        return Err(format!(
            "WriteProcessMemory failed ({})",
            unsafe { GetLastError() }
        ));
    }
    println!(
        "hyperion    shape R3 identical rewrite of {} bytes at 0x{page:X}",
        original.len()
    );
    Ok(())
}
