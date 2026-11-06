//! zenoscope — resolve Roblox engine offsets without trusting hardcoded
//! addresses.
//!
//! Two sources:
//!   * a live client's mapped image (the only one that works on the shipped
//!     client — its `.text` is encrypted on disk)
//!   * the file on disk (fallback, and how the tool is exercised in tests)

mod dump;
mod hpp;
mod image;
mod live;
mod scan;

use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;

use image::{Image, PeImage};
use live::Process;
use scan::{find_task_scheduler_pointer, resolve_rtti, scan_rip_refs, TypeInfo};

const CLIENT_EXE: &str = "RobloxPlayerBeta.exe";
const CLIENT_MODULE: &str = "RobloxPlayerBeta.exe";
const SCHEDULER_MESSAGE: &str = "Default job arbiter must always be valid";
const RTTI_TARGETS: [&str; 2] = [".?AVDataModel@RBX@@", ".?AVVisualEngine@Graphics@RBX@@"];

struct Args {
    exe: Option<PathBuf>,
    pid: Option<u32>,
    probe: Option<u32>,
    verify: Option<PathBuf>,
    module: Option<String>,
    json: Option<PathBuf>,
    dump: bool,
    force: bool,
    rebuild: bool,
    out: Option<PathBuf>,
    inspect: Option<usize>,
    watch: Option<u64>,
    base: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        exe: None,
        pid: None,
        probe: None,
        verify: None,
        module: None,
        json: None,
        dump: false,
        force: false,
        rebuild: false,
        out: None,
        inspect: None,
        watch: None,
        base: None,
    };
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--exe" => args.exe = Some(PathBuf::from(argv.next().ok_or("--exe needs a path")?)),
            "--pid" => {
                let value = argv.next().ok_or("--pid needs a number")?;
                args.pid = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--pid expects a number, got {value}"))?,
                );
            }
            "--json" => args.json = Some(PathBuf::from(argv.next().ok_or("--json needs a path")?)),
            "--module" => {
                args.module = Some(argv.next().ok_or("--module needs a name")?);
            }
            "--probe" => {
                let value = argv.next().ok_or("--probe needs a pid")?;
                args.probe = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--probe expects a number, got {value}"))?,
                );
            }
            "--verify" => {
                args.verify = Some(PathBuf::from(argv.next().ok_or("--verify needs a path")?));
            }
            "--dump" => args.dump = true,
            "--force-dump" => args.force = true,
            "--rebuild" => args.rebuild = true,
            "--watch" => {
                let value = argv.next().ok_or("--watch needs a duration in seconds")?;
                args.watch = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--watch expects seconds, got {value}"))?,
                );
            }
            "--base" => {
                args.base = Some(PathBuf::from(argv.next().ok_or("--base needs a path")?));
            }
            "--inspect" => {
                let value = argv.next().ok_or("--inspect needs a page count")?;
                args.inspect = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--inspect expects a number, got {value}"))?,
                );
            }
            "--out" => {
                args.out = Some(PathBuf::from(argv.next().ok_or("--out needs a path")?));
            }
            "-h" | "--help" => {
                println!("zenoscope [--pid <n> | --exe <path>] [--module <name>] [--json <out>]");
                println!("zenoscope --probe <pid>     report which access masks the target grants");
                println!("zenoscope --verify <hpp>    check an offsets pack against this client");
                println!("zenoscope --dump            rebuild a decrypted client image (elevated)");
                println!("           [--pid <n>] [--module <name>] [--out <path>] [--rebuild]");
                println!("zenoscope --inspect <n>     lift protection on n .text pages and report");
                println!("zenoscope --force-dump      run a copy stub inside the client so its own");
                println!("                            handler decrypts .text; visible to the anti-tamper");
                println!("zenoscope --watch <secs>    sample .text and keep every decrypted page");
                println!("           [--base <image>] [--out <path>]");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
}

fn local_app_data() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
}

fn find_client_file() -> Option<PathBuf> {
    let root = local_app_data()?.join("Roblox").join("Versions");
    let entries = std::fs::read_dir(root).ok()?;

    let mut best: Option<(SystemTime, PathBuf)> = None;
    for entry in entries.flatten() {
        let candidate = entry.path().join(CLIENT_EXE);
        if !candidate.is_file() {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if best.as_ref().map(|(t, _)| modified > *t).unwrap_or(true) {
            best = Some((modified, candidate));
        }
    }

    best.map(|(_, path)| path)
}

fn client_version(path: &str) -> String {
    path.split(['\\', '/'])
        .find(|part| part.starts_with("version-"))
        .unwrap_or("unknown")
        .to_string()
}

fn describe_error(code: u32) -> &'static str {
    match code {
        5 => "access denied",
        87 => "invalid parameter",
        1168 => "not found",
        _ => "error",
    }
}

pub fn thousands(mut n: u64) -> String {
    if n == 0 {
        return "0".into();
    }
    let mut digits = Vec::new();
    while n > 0 {
        digits.push((n % 10) as u8);
        n /= 10;
    }
    digits.reverse();
    let mut out = String::new();
    for (i, d) in digits.iter().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push((b'0' + d) as char);
    }
    out
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn type_info_json(info: &TypeInfo) -> String {
    let quote = |v: &u32| format!("\"0x{v:X}\"");
    let locators: Vec<String> = info.locator_rvas.iter().map(quote).collect();
    let vtables: Vec<String> = info.vtable_rvas.iter().map(quote).collect();
    format!(
        "{{\"mangled\":\"{}\",\"type_descriptor\":\"0x{:X}\",\"locators\":[{}],\"vtables\":[{}]}}",
        json_escape(&info.mangled),
        info.type_descriptor_rva,
        locators.join(","),
        vtables.join(",")
    )
}

struct Loaded {
    source: String,
    origin: String,
    version: String,
    bytes: u64,
    image: Box<dyn Image>,
    unreadable: usize,
    notes: Vec<String>,
}

fn load_file(path: PathBuf) -> Result<Loaded, String> {
    let data = std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let bytes = data.len() as u64;
    let origin = path.display().to_string();
    let version = client_version(&origin);
    let image = PeImage::parse(data)?;

    Ok(Loaded {
        source: "file".into(),
        origin,
        version,
        bytes,
        image: Box::new(image),
        unreadable: 0,
        notes: Vec::new(),
    })
}

fn load(args: &Args) -> Result<Loaded, String> {
    let mut notes = Vec::new();

    let live_pid = match args.pid {
        Some(pid) => Some(pid),
        None if args.exe.is_none() => match Process::open_by_name(CLIENT_EXE) {
            Ok(process) => Some(process.pid),
            Err(because) => {
                notes.push(format!("live client not usable: {because}"));
                None
            }
        },
        None => None,
    };

    if let Some(pid) = live_pid {
        let module = args.module.as_deref().unwrap_or(CLIENT_MODULE);
        let process = Process::open_pid(pid)?;
        let image = process.image(module)?;
        let version = client_version(image.path());
        let bytes = image.size_of_image as u64;
        let unreadable = image.unreadable;
        let origin = image.path().to_string();
        return Ok(Loaded {
            source: format!("live pid {pid}"),
            origin,
            version,
            bytes,
            image: Box::new(image),
            unreadable,
            notes,
        });
    }

    let path = match &args.exe {
        Some(path) => path.clone(),
        None => find_client_file().ok_or_else(|| {
            format!("{CLIENT_EXE} not found; pass --exe <path> or --pid <n>")
        })?,
    };

    let mut loaded = load_file(path)?;
    loaded.notes = notes;
    Ok(loaded)
}

// ------------------------------------------------------------------- verify

/// A pack entry whose value is a module-relative address rather than a struct
/// offset. Anything past 1 MiB is past the largest sensible member offset.
const RVA_FLOOR: u64 = 0x10_0000;

struct SlotReport {
    namespace: String,
    name: String,
    rva: u64,
    section: Option<String>,
    writable: bool,
    aligned: bool,
    at_rest: String,
}

fn at_rest(image: &dyn Image, rva: u64) -> String {
    let rva = match u32::try_from(rva) {
        Ok(v) => v,
        Err(_) => return "outside the image".into(),
    };
    match image.read_u64(rva) {
        None => "not file-backed (zeroed at load)".into(),
        Some(0) => "zero at rest".into(),
        Some(value) => {
            let inside = image.rva_of_va(value).is_some();
            if inside {
                format!("live value 0x{value:X} (points into this image)")
            } else {
                format!("live value 0x{value:X} (points outside this image)")
            }
        }
    }
}

fn slot_report(image: &dyn Image, entry: &hpp::Entry) -> SlotReport {
    let rva32 = u32::try_from(entry.value).ok();
    let section = rva32.and_then(|rva| image.section_for_rva(rva));
    SlotReport {
        namespace: entry.namespace.clone(),
        name: entry.name.clone(),
        rva: entry.value,
        section: section.map(|s| s.name.clone()),
        writable: section.map(|s| s.is_writable()).unwrap_or(false),
        aligned: entry.value % 8 == 0,
        at_rest: at_rest(image, entry.value),
    }
}

fn value_of(pack: &hpp::Pack, namespace: &str, name: &str) -> Option<u64> {
    pack.entries
        .iter()
        .find(|e| e.namespace == namespace && e.name == name)
        .map(|e| e.value)
}

fn verify_pack(path: &PathBuf, image: &dyn Image, client: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let pack = hpp::Pack::parse(&text);

    let pack_version = pack.client_version.clone().unwrap_or_else(|| "unknown".into());
    let version_match = pack_version == client;

    println!("zenoscope verify  {}", path.display());
    println!("  client on disk    {client}");
    println!("  pack version      {pack_version}");
    println!(
        "  version match     {}",
        if version_match { "yes" } else { "NO — offsets are for another build" }
    );
    println!("  entries           {}", pack.entries.len());

    let slots: Vec<&hpp::Entry> = pack
        .entries
        .iter()
        .filter(|e| e.value >= RVA_FLOOR)
        .collect();

    println!();
    println!("module-relative slots");
    if slots.is_empty() {
        println!("  none — every entry is a struct offset");
    }
    let mut slots_ok = 0usize;
    for entry in &slots {
        let report = slot_report(image, entry);
        let usable = report.writable && report.aligned && report.section.is_some();
        if usable {
            slots_ok += 1;
        }
        println!(
            "  {}::{:<22} rva 0x{:<9X} {:<8} {:<3} {:<9} {}",
            report.namespace,
            report.name,
            report.rva,
            report.section.as_deref().unwrap_or("none"),
            if report.writable { "rw" } else { "ro" },
            if report.aligned { "aligned" } else { "MISALIGNED" },
            report.at_rest
        );
    }
    if !slots.is_empty() {
        println!("  {slots_ok}/{} resolve to a writable, aligned global", slots.len());
    }

    // ------------------------------------------------------------ structure
    println!();
    println!("structure");
    let mut problems: Vec<String> = Vec::new();
    let mut checks = 0usize;

    let mut check = |label: String, passed: bool, detail: String| {
        checks += 1;
        if !passed {
            problems.push(label.clone());
        }
        println!("  {:<40} {} {}", label, if passed { "ok  " } else { "WARN" }, detail);
    };

    match (value_of(&pack, "Instance", "Name"), value_of(&pack, "Instance", "ChildrenStart"), value_of(&pack, "Instance", "ChildrenEnd")) {
        (Some(name), Some(start), Some(end)) => {
            check(
                "Instance::Name is offset zero".into(),
                name == 0,
                format!("0x{name:X}"),
            );
            check(
                "ChildrenEnd is past ChildrenStart".into(),
                end > start,
                format!("0x{start:X} -> 0x{end:X}"),
            );
            check(
                "ChildrenStart is pointer aligned".into(),
                start % 8 == 0,
                format!("0x{start:X}"),
            );
        }
        _ => check(
            "Instance layout is complete".into(),
            false,
            "missing keys".into(),
        ),
    }

    for (namespace, name) in [
        ("DataModel", "Workspace"),
        ("DataModel", "ScriptContext"),
        ("FakeDataModel", "RealDataModel"),
        ("VisualEngine", "FakeDataModel"),
    ] {
        match value_of(&pack, namespace, name) {
            Some(v) => check(
                format!("{namespace}::{name} is a member offset"),
                v < RVA_FLOOR,
                format!("0x{v:X}"),
            ),
            None => check(
                format!("{namespace}::{name} present"),
                false,
                "missing".into(),
            ),
        }
    }

    for mangled in RTTI_TARGETS {
        let known = resolve_rtti(image, mangled).is_some();
        check(
            format!("RTTI contains {mangled}"),
            known,
            if known { "resolved".into() } else { "absent".into() },
        );
    }

    println!();
    println!(
        "  checks            {}/{} passed",
        checks.saturating_sub(problems.len()),
        checks
    );
    println!(
        "  verdict           {}",
        if version_match && problems.is_empty() {
            "compatible with this client"
        } else if !version_match {
            "incompatible: pack targets a different client build"
        } else {
            "version matches but the layout has oddities"
        }
    );

    Ok(())
}


fn run_inspect(args: &Args, count: usize) -> Result<(), String> {
    let module = args.module.as_deref().unwrap_or(CLIENT_MODULE);
    let probes = dump::inspect(args.pid, module, count)?;

    println!("zenoscope inspect  {module}");
    println!();
    println!(
        "  {:<10} {:>8} {:>6} {:>6} {:>8} {:>16} {}",
        "rva", "protect", "lifted", "read", "equals-disk", "head", "prologue"
    );
    for probe in &probes {
        println!(
            "  0x{:<8X} {:>8} {:>6} {:>6} {:>8} {:>16} {}",
            probe.rva,
            format!("0x{:X}", probe.protect_before),
            if probe.lifted { "yes" } else { "no" },
            match (probe.read_ok, probe.error) {
                (true, _) => "ok".to_string(),
                (false, Some(error)) => format!("err {error}"),
                (false, None) => "no".to_string(),
            },
            if probe.same_as_disk { "yes" } else { "no" },
            probe.head,
            probe.prologue.unwrap_or("-")
        );
    }

    let lifted = probes.iter().filter(|p| p.lifted).count();
    let readable = probes.iter().filter(|p| p.read_ok).count();
    let identical = probes.iter().filter(|p| p.same_as_disk).count();
    let code = probes.iter().filter(|p| p.prologue.is_some()).count();

    println!();
    println!("  pages        {} probed, {lifted} unprotected, {readable} read, {identical} identical to disk", probes.len());
    println!();
    println!(
        "  verdict      {}",
        if code > 0 {
            "protection lift reveals real code — PAGE_NOACCESS is the only wall"
        } else if readable > 0 && identical == readable {
            "the bytes under the lifted protection are still the on-disk ciphertext"
        } else if readable > 0 {
            "readable under the lift but not identical to disk — inspect the head bytes"
        } else {
            "the protection cannot be lifted from outside"
        }
    );

    Ok(())
}

fn run_watch(args: &Args, seconds: u64) -> Result<(), String> {
    let module = args.module.as_deref().unwrap_or(CLIENT_MODULE);
    println!("zenoscope watch  {module}  {seconds}s");
    let report = dump::watch(
        args.pid,
        module,
        args.base.clone(),
        seconds,
        args.out.clone(),
        args.rebuild,
    )?;

    println!();
    println!("  process      pid {}", report.pid);
    println!("  module       {}  base 0x{:X}", report.module_path, report.base);
    for note in &report.notes {
        println!("  note         {note}");
    }
    println!(
        "  pages        {} total, {} decrypted, {} newly captured in this pass ({}s)",
        thousands(report.pages_total),
        thousands(report.pages_readable),
        thousands(report.new_pages),
        report.seconds
    );

    println!();
    println!("  prologues");
    for (index, label) in ["48 89 5C 24", "48 83 EC   ", "int3 pad   ", "zeros      "]
        .iter()
        .enumerate()
    {
        println!(
            "    {label} {:>10} -> {}",
            thousands(report.prologues_before[index] as u64),
            thousands(report.prologues_after[index] as u64)
        );
    }

    let coverage = if report.pages_total == 0 {
        0.0
    } else {
        report.pages_readable as f64 * 100.0 / report.pages_total as f64
    };
    println!();
    println!("  coverage     {coverage:.1}% of .text captured");
    println!(
        "  wrote        {} ({} bytes)",
        report.output.display(),
        thousands(report.output_bytes)
    );
    if let Some(rebuilt) = &report.rebuilt {
        let bytes = std::fs::metadata(rebuilt).map(|m| m.len()).unwrap_or(0);
        println!("  rebuilt      {} ({} bytes)", rebuilt.display(), thousands(bytes));
    }

    Ok(())
}

fn run_force(args: &Args) -> Result<(), String> {
    let module = args.module.as_deref().unwrap_or(CLIENT_MODULE);
    let report = dump::force(args.pid, module, args.out.clone())?;

    println!("zenoscope force-dump");
    println!("  process      pid {}", report.pid);
    println!("  module       {}  base 0x{:X}", report.module_path, report.base);
    for note in &report.notes {
        println!("  note         {note}");
    }

    println!();
    println!("  {:<12} {:>12} {:>6} {:>8} {:>10} {:>12}", "rva", "bytes", "ran", "wait", "changed", "exit");
    for chunk in &report.chunks {
        println!(
            "  0x{:<10X} {:>12} {:>6} {:>8} {:>10} {:>12}",
            chunk.rva,
            thousands(chunk.len),
            if chunk.ran { "yes" } else { "NO" },
            format!("0x{:X}", chunk.waited),
            thousands(chunk.changed_bytes),
            format!("0x{:08X}", chunk.exit_code)
        );
    }

    let captured: u64 = report.chunks.iter().map(|c| c.len).sum();
    let changed: u64 = report.chunks.iter().map(|c| c.changed_bytes).sum();
    let finished = report.chunks.iter().filter(|c| c.ran).count();

    println!();
    println!("  chunks       {}/{} completed", finished, report.chunks.len());
    println!("  captured     {} bytes, {} differed from disk", thousands(captured), thousands(changed));

    println!();
    println!("  prologues");
    for (index, label) in ["48 89 5C 24", "48 83 EC   ", "int3 pad   ", "zeros      "]
        .iter()
        .enumerate()
    {
        println!(
            "    {label} {:>10} -> {}",
            thousands(report.prologues_before[index] as u64),
            thousands(report.prologues_after[index] as u64)
        );
    }

    println!();
    println!(
        "  verdict      {}",
        if report.prologues_after[0] > 5000 {
            "the client decrypted on read; .text is in the clear"
        } else if report.prologues_after[0] > report.prologues_before[0] {
            "some pages decrypted, the read fault is handled only part of the way"
        } else {
            "no new pages — the fault did not reach the client's handler"
        }
    );
    println!(
        "  wrote        {} ({} bytes)",
        report.output.display(),
        thousands(report.output_bytes)
    );

    Ok(())
}

fn run_dump(args: &Args) -> Result<(), String> {
    let module = args.module.as_deref().unwrap_or(CLIENT_MODULE);
    let report = dump::dump(args.pid, module, args.out.clone(), args.rebuild)?;

    println!("zenoscope dump");
    println!("  process      pid {}", report.pid);
    println!(
        "  module       {}  base 0x{:X}  size 0x{:X}",
        report.module_path, report.base, report.size
    );
    println!("  on disk      {} bytes", thousands(report.image_bytes));
    for note in &report.notes {
        println!("  note         {note}");
    }

    println!();
    println!(
        "  {:<10} {:>10} {:>8} {:>8} {:>10} {:>5}",
        "section", "span", "flushed", "read", "changed", "exec"
    );
    for section in &report.sections {
        println!(
            "  {:<10} {:>10} {:>8} {:>8} {:>10} {:>5}",
            section.name,
            thousands(section.span),
            thousands(section.flushed),
            thousands(section.read),
            thousands(section.changed_bytes),
            if section.runtime_executable { "x" } else { "-" }
        );
        if section.unreadable > 0 {
            println!(
                "             {} pages refused by the kernel (first error {})",
                thousands(section.unreadable),
                section
                    .first_read_error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "?".into())
            );
            for (key, count) in &section.denied_protect {
                let protect = key & 0xFF;
                let state = key >> 16;
                println!(
                    "             {} pages state 0x{:X} protect 0x{:X}",
                    thousands(*count),
                    state,
                    protect
                );
            }
        }
        if section.flush_errors > 0 {
            println!(
                "             {} flush calls failed, first status 0x{:X}",
                thousands(section.flush_errors),
                section.first_flush_status.unwrap_or(0) as u32
            );
        }
    }

    let (flushed, read, unreadable, changed) = report.totals();
    println!();
    println!("  pages        {} flushed, {} read, {} refused", thousands(flushed), thousands(read), thousands(unreadable));
    println!("  bytes        {} replaced with live contents", thousands(changed));

    println!();
    println!("  prologues");
    for (index, label) in [
        "48 89 5C 24",
        "48 83 EC   ",
        "int3 pad   ",
        "zeros      ",
    ]
    .iter()
    .enumerate()
    {
        println!(
            "    {label} {:>10} -> {}",
            thousands(report.prologues_before[index] as u64),
            thousands(report.prologues_after[index] as u64)
        );
    }

    let code_before = report.prologues_before[0];
    let code_after = report.prologues_after[0];
    println!();
    println!(
        "  verdict      {}",
        if code_after > 100 {
            "code pages decrypted; the dump is analysable"
        } else if code_after > code_before {
            "partial decrypt — some pages stayed encrypted"
        } else {
            "nothing decrypted — the flush no longer forces a fault"
        }
    );
    println!("  wrote        {} ({} bytes)", report.output.display(), thousands(report.output_bytes));
    if let Some(rebuilt) = &report.rebuilt {
        let bytes = std::fs::metadata(rebuilt).map(|m| m.len()).unwrap_or(0);
        println!("  rebuilt      {} ({} bytes)", rebuilt.display(), thousands(bytes));
    }

    Ok(())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("zenoscope: {message}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    if args.dump {
        return run_dump(&args);
    }

    if args.force {
        return run_force(&args);
    }

    if let Some(seconds) = args.watch {
        return run_watch(&args, seconds);
    }

    if let Some(count) = args.inspect {
        return run_inspect(&args, count);
    }

    if let Some(pid) = args.probe {
        println!("zenoscope probe  pid {pid}");
        println!();
        println!("  access masks");
        for (mask, name, opened, error) in live::probe_access(pid) {
            let status = if opened {
                "granted".to_string()
            } else {
                format!("denied ({}: {})", error, describe_error(error))
            };
            println!("    0x{mask:05X}  {name:<34} {status}");
        }
        println!();
        match live::probe_modules(pid) {
            Ok((count, names)) => println!(
                "  module list    {count} modules, e.g. {}",
                names.join(", ")
            ),
            Err(error) => println!(
                "  module list    denied ({}: {})",
                error,
                describe_error(error)
            ),
        }
        return Ok(());
    }

    if let Some(path) = &args.verify {
        let exe = match &args.exe {
            Some(path) => path.clone(),
            None => find_client_file()
                .ok_or_else(|| format!("{CLIENT_EXE} not found; pass --exe <path>"))?,
        };
        let loaded = load_file(exe)?;
        return verify_pack(path, loaded.image.as_ref(), &loaded.version);
    }

    let loaded = load(&args)?;
    let image = loaded.image.as_ref();

    println!("zenoscope");
    println!("  source      {}  {}", loaded.source, loaded.origin);
    println!("  client      {}", loaded.version);
    println!(
        "  image base  0x{:X}   size 0x{:X}   {} bytes",
        image.image_base(),
        image.size_of_image(),
        thousands(loaded.bytes)
    );
    if loaded.unreadable > 0 {
        println!(
            "  unreadable  {} bytes of the mapping were refused by the kernel",
            thousands(loaded.unreadable as u64)
        );
    }
    if let Some(note) = loaded.notes.first() {
        println!("  note        {note}");
    }
    println!("  sections    {}", image.sections().len());
    for section in image.sections() {
        let flags = format!(
            "{}{}",
            if image.is_code_section(section) { "x" } else { "-" },
            if section.is_writable() { "w" } else { "-" }
        );
        println!(
            "    {:<8} rva 0x{:<9X} span 0x{:<9X} read 0x{:<9X} {}",
            section.name,
            section.virtual_address,
            section.span(),
            image.section_data(section).len(),
            flags
        );
    }

    let refs = scan_rip_refs(image);
    let counts = scan::count_patterns(image, &scan::PROLOGUES);
    let leas = refs.iter().filter(|r| r.kind == scan::RefKind::Lea).count();
    let movs = refs.len() - leas;
    let packed = counts[0] == 0 && counts[1] < 100;

    println!();
    println!("code");
    println!("  readable bytes        {}", thousands(image.code_bytes() as u64));
    println!(
        "  rip refs              {} (lea {}, mov {})",
        thousands(refs.len() as u64),
        thousands(leas as u64),
        thousands(movs as u64)
    );
    println!(
        "  prologues 48 89 5C 24 {}   48 83 EC {}   int3 pad {}   zeros {}",
        thousands(counts[0] as u64),
        thousands(counts[1] as u64),
        thousands(counts[2] as u64),
        thousands(counts[3] as u64)
    );
    if packed {
        println!("  verdict              no function prologues; this image is packed");
        println!("                       .text is only readable from inside the client");
        if loaded.source == "file" {
            println!("                       an external VM_READ handle is refused (see --probe)");
        }
    }

    // ---------------------------------------------------- TaskScheduler::Pointer
    let (string_hits, slots) = find_task_scheduler_pointer(image, &refs, SCHEDULER_MESSAGE, 200);

    println!();
    println!("TaskScheduler::Pointer");
    if string_hits.is_empty() {
        println!("  anchor string not found in this image");
    } else {
        for rva in &string_hits {
            println!(
                "  anchor \"{SCHEDULER_MESSAGE}\" rva 0x{rva:X}  va 0x{:X}",
                image.va(*rva)
            );
        }
    }
    for slot in &slots {
        println!(
            "  candidate global rva 0x{:<9X} va 0x{:<12X} via lea 0x{:<9X}",
            slot.global_rva,
            image.va(slot.global_rva),
            slot.via_lea_rva
        );
    }
    if slots.is_empty() && !string_hits.is_empty() {
        println!("  no writable pointer slot found near the xref");
    }

    // ---------------------------------------------------------------- RTTI
    println!();
    println!("RTTI");
    let mut resolved: Vec<TypeInfo> = Vec::new();
    for mangled in RTTI_TARGETS {
        match resolve_rtti(image, mangled) {
            Some(info) => {
                let vtable = info
                    .vtable_rvas
                    .first()
                    .map(|v| format!("0x{:X}", image.va(*v)))
                    .unwrap_or_else(|| "unresolved".into());
                println!(
                    "  {:<34} td 0x{:<9X} locators {} vtable {}",
                    info.mangled,
                    info.type_descriptor_rva,
                    info.locator_rvas.len(),
                    vtable
                );
                resolved.push(info);
            }
            None => println!("  {mangled:<34} not present in this image"),
        }
    }

    let scheduler = slots.first();
    println!();
    println!("summary");
    println!(
        "  TaskScheduler::Pointer  {}",
        scheduler
            .map(|s| format!("0x{:X}", s.global_rva))
            .unwrap_or_else(|| "unresolved".into())
    );
    println!(
        "  RTTI types resolved     {}/{}",
        resolved.len(),
        RTTI_TARGETS.len()
    );
    if let Some(slot) = scheduler {
        println!(
            "  scheduler global va     0x{:X}   (stable for {})",
            image.va(slot.global_rva),
            loaded.version
        );
    }
    println!();
    println!("  instance offsets (Name, ChildrenStart, ClassDescriptor) describe a");
    println!("  live object graph and still need a joined session to resolve.");

    if let Some(path) = args.json {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str("  \"tool\": \"zenoscope\",\n");
        out.push_str("  \"schema\": 1,\n");
        out.push_str(&format!(
            "  \"target\": {{\"source\": \"{}\", \"origin\": \"{}\", \"bytes\": {}, \"image_base\": \"0x{:X}\", \"size_of_image\": \"0x{:X}\"}},\n",
            json_escape(&loaded.source),
            json_escape(&loaded.origin),
            loaded.bytes,
            image.image_base(),
            image.size_of_image()
        ));
        out.push_str(&format!(
            "  \"client_version\": \"{}\",\n",
            json_escape(&loaded.version)
        ));
        out.push_str(&format!("  \"packed\": {packed},\n"));
        match scheduler {
            Some(slot) => out.push_str(&format!(
                "  \"task_scheduler\": {{\"global_rva\": \"0x{:X}\", \"global_va\": \"0x{:X}\", \"string_rva\": \"0x{:X}\"}},\n",
                slot.global_rva,
                image.va(slot.global_rva),
                slot.string_rva
            )),
            None => out.push_str("  \"task_scheduler\": null,\n"),
        }
        let rtti: Vec<String> = resolved
            .iter()
            .map(|info| {
                format!(
                    "\"{}\": {}",
                    json_escape(&info.mangled),
                    type_info_json(info)
                )
            })
            .collect();
        out.push_str(&format!("  \"rtti\": {{{}}},\n", rtti.join(", ")));
        out.push_str("  \"pending_runtime\": [\"VisualEngine::Pointer\", \"FakeDataModel::Pointer\", \"RealDataModel\", \"Instance::Name\", \"Instance::ChildrenStart\", \"Instance::ClassDescriptor\"]\n");
        out.push_str("}\n");

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
        }
        let mut handle = std::fs::File::create(&path)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        handle
            .write_all(out.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        println!();
        println!("  wrote {}", path.display());
    }

    Ok(())
}
