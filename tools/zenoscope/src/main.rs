//! zenoscope â€” resolve Roblox engine offsets without trusting hardcoded
//! addresses.
//!
//! Two sources:
//!   * a live client's mapped image (the only one that works on the shipped
//!     client â€” its `.text` is encrypted on disk)
//!   * the file on disk (fallback, and how the tool is exercised in tests)

mod dump;
mod hpp;
mod image;
mod live;
mod scan;
mod state;

use std::collections::HashMap;
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
    chain: Option<PathBuf>,
    vtable: Option<PathBuf>,
    children: Option<PathBuf>,
    count: usize,
    follow: bool,
    find_state: bool,
    state_cap_mb: usize,
    pack: Option<PathBuf>,
    find_value: Option<u64>,
    find_vm: bool,
    find_text: Option<String>,
    read: Option<u64>,
    probe_lua: Option<u64>,
    find_string: Option<String>,
    find_tt: Option<u8>,
    find_stack: bool,
    hunt: bool,
    pair: Option<(u64, u64)>,
    threads: bool,
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
        chain: None,
        vtable: None,
        children: None,
        count: 64,
        follow: false,
        find_state: false,
        state_cap_mb: 4096,
        pack: None,
        find_value: None,
        find_vm: false,
        find_text: None,
        read: None,
        probe_lua: None,
        find_string: None,
        find_tt: None,
        find_stack: false,
        hunt: false,
        pair: None,
        threads: false,
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
            "--chain" => {
                args.chain = Some(PathBuf::from(argv.next().ok_or("--chain needs a pack")?));
            }
            "--vtable" => {
                args.vtable = Some(PathBuf::from(argv.next().ok_or("--vtable needs a pack")?));
            }
            "--children" => {
                args.children = Some(PathBuf::from(argv.next().ok_or("--children needs a pack")?));
            }
            "--count" => {
                let value = argv.next().ok_or("--count needs a number")?;
                args.count = value
                    .parse()
                    .map_err(|_| format!("--count expects a number, got {value}"))?;
            }
            "--follow" => {
                args.follow = true;
            }
            "--findstate" => {
                args.find_state = true;
            }
            "--pack" => {
                args.pack = Some(PathBuf::from(argv.next().ok_or("--pack needs a pack")?));
            }
            "--read" => {
                let value = argv.next().ok_or("--read needs an address")?;
                let cleaned = value.trim_start_matches("0x").trim_start_matches("0X");
                args.read = Some(u64::from_str_radix(cleaned, 16).map_err(|_| format!("--read expects hex, got {value}"))?);
            }
            "--findtext" => {
                args.find_text = Some(argv.next().ok_or("--findtext needs text")?);
            }
            "--threads" => {
                args.threads = true;
            }
            "--pair" => {
                let first = argv.next().ok_or("--pair needs two addresses")?;
                let second = argv.next().ok_or("--pair needs two addresses")?;
                let parse = |value: &str| -> Result<u64, String> {
                    let cleaned = value.trim_start_matches("0x").trim_start_matches("0X");
                    u64::from_str_radix(cleaned, 16)
                        .map_err(|_| format!("--pair expects hex, got {value}"))
                };
                args.pair = Some((parse(&first)?, parse(&second)?));
            }
            "--hunt" => {
                args.hunt = true;
            }
            "--findstack" => {
                args.find_stack = true;
            }
            "--findtt" => {
                let value = argv.next().ok_or("--findtt needs a tag")?;
                args.find_tt = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--findtt expects a number, got {value}"))?,
                );
            }
            "--findstring" => {
                args.find_string = Some(argv.next().ok_or("--findstring needs text")?);
            }
            "--probe-lua" => {
                let value = argv.next().ok_or("--probe-lua needs an address")?;
                let cleaned = value.trim_start_matches("0x").trim_start_matches("0X");
                args.probe_lua = Some(
                    u64::from_str_radix(cleaned, 16)
                        .map_err(|_| format!("--probe-lua expects hex, got {value}"))?,
                );
            }
            "--findvm" => {
                args.find_vm = true;
            }
            "--findvalue" => {
                let value = argv.next().ok_or("--findvalue needs an address")?;
                let cleaned = value.trim_start_matches("0x").trim_start_matches("0X");
                args.find_value = Some(
                    u64::from_str_radix(cleaned, 16)
                        .map_err(|_| format!("--findvalue expects hex, got {value}"))?,
                );
            }
            "--state-cap-mb" => {
                let value = argv.next().ok_or("--state-cap-mb needs a number")?;
                args.state_cap_mb = value
                    .parse()
                    .map_err(|_| format!("--state-cap-mb expects a number, got {value}"))?;
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
                println!("           [--base <image>] [--out <path>] [--follow]");
                println!("           --follow re-attaches when the client restarts");
                println!("zenoscope --chain <hpp>     walk VisualEngine -> FakeDataModel -> DataModel");
                println!("                            through the live client and print names");
                println!("zenoscope --vtable <hpp>    print ScriptContext vtable slots with their page");
                println!("           [--count <n>]    protection â€” plaintext entry points, live");
                println!("zenoscope --findstate       search the live client's private memory for a");
                println!("           [--state-cap-mb <n>]  lua_State whose global_State points back");
                println!("zenoscope --probe-lua <hex> walk out from an object two pointer hops looking");
                println!("           [--count <n>]  for a lua_State + global_State string table");
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
        if version_match { "yes" } else { "NO â€” offsets are for another build" }
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
        println!("  none â€” every entry is a struct offset");
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
            "protection lift reveals real code â€” PAGE_NOACCESS is the only wall"
        } else if readable > 0 && identical == readable {
            "the bytes under the lifted protection are still the on-disk ciphertext"
        } else if readable > 0 {
            "readable under the lift but not identical to disk â€” inspect the head bytes"
        } else {
            "the protection cannot be lifted from outside"
        }
    );

    Ok(())
}

fn run_children(args: &Args, pack_path: PathBuf) -> Result<(), String> {
    let text = std::fs::read_to_string(&pack_path)
        .map_err(|e| format!("cannot read {}: {e}", pack_path.display()))?;
    let pack = hpp::Pack::parse(&text);

    let mut offsets: HashMap<String, u64> = HashMap::new();
    for entry in &pack.entries {
        offsets.insert(format!("{}::{}", entry.namespace, entry.name), entry.value);
    }

    let module = args.module.as_deref().unwrap_or(CLIENT_MODULE);
    let listing = dump::children_tree(args.pid, module, &offsets, args.count)?;

    println!("zenoscope children  {module}  {} listed", listing.len());
    for (index, (name, class, address)) in listing.iter().enumerate() {
        println!("  {:>3}  0x{:<12X} {:<34} [{}]", index, address, name, class);
    }

    Ok(())
}


fn run_findstate(args: &Args) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };

    let (datamodel, context) = match &args.pack {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let pack = hpp::Pack::parse(&text);
            let mut offsets: HashMap<String, u64> = HashMap::new();
            for entry in &pack.entries {
                offsets.insert(format!("{}::{}", entry.namespace, entry.name), entry.value);
            }
            let module = args.module.as_deref().unwrap_or(CLIENT_MODULE);
            let report = dump::vtable(args.pid, module, &offsets, 1)?;
            println!(
                "  world  DataModel 0x{:X}  ScriptContext 0x{:X}",
                report.datamodel, report.context
            );
            (Some(report.datamodel), Some(report.context))
        }
        None => (None, None),
    };

    let cap = args.state_cap_mb.saturating_mul(1024 * 1024);
    println!("zenoscope findstate  pid {}", process.pid);
    let mut last = 0usize;
    let (hits, scanned) = state::find_threads(&process, cap, |bytes| {
        if bytes - last >= 128 * 1024 * 1024 {
            last = bytes;
            println!("  scanned {:.0} MiB", bytes as f64 / (1024.0 * 1024.0));
        }
    });
    println!(
        "  scanned {:.1} MiB  states {}",
        scanned as f64 / (1024.0 * 1024.0),
        hits.len()
    );

    let mut tag_counts = [0usize; 256];
    for hit in &hits {
        tag_counts[hit.tag as usize] += 1;
    }
    print!("  tags");
    for (tag, count) in tag_counts.iter().enumerate() {
        if *count > 0 {
            print!(" 0x{tag:02X}:{count}");
        }
    }
    println!();

    struct Ranked<'a> {
        hit: &'a state::Hit,
        tags: usize,
        world: usize,
        world_at: u64,
        arena: u64,
        arena_size: usize,
    }

    let mut ranked: Vec<Ranked> = Vec::new();
    for hit in &hits {
        if hit.tag != 8 {
            continue;
        }
        let kind = state::region_kind(&process, hit.state);
        let kind_name = match kind {
            0x20000 => "private",
            0x40000 => "mapped",
            0x1000000 => "image",
            _ => "other",
        };
        println!(
            "    tag8  state 0x{:X}  global 0x{:X}  stack 0x{:X}+{:#X}  kind {kind_name}  tags {}/16",
            hit.state,
            hit.global,
            hit.stack,
            hit.stack_size,
            state::stack_tags(&process, hit.stack, 16)
        );
        let tags = state::stack_tags(&process, hit.stack, 16);
        if kind != 0x20000 {
            continue;
        }
        let (arena, arena_size) = state::region_of(&process, hit.state);
        let mut world = 0usize;
        let mut world_at = 0u64;
        if ranked.len() < 32 && arena_size <= 256 * 1024 * 1024 {
            for needle in [datamodel, context].into_iter().flatten() {
                if let Some(address) =
                    state::find_value_in_region(&process, arena, arena_size, needle, 1).first()
                {
                    world += 1;
                    world_at = *address;
                }
            }
        }
        ranked.push(Ranked {
            hit,
            tags,
            world,
            world_at,
            arena,
            arena_size,
        });
    }

    ranked.sort_by_key(|entry| (std::cmp::Reverse(entry.world), std::cmp::Reverse(entry.tags)));
    println!("  validated threads {}", ranked.len());
    for entry in ranked.iter().take(12) {
        println!(
            "    world {}/2  tags {}/16  state 0x{:X}  global 0x{:X}  stack 0x{:X}+{:#X}  arena 0x{:X} ({} KiB){}",
            entry.world,
            entry.tags,
            entry.hit.state,
            entry.hit.global,
            entry.hit.stack,
            entry.hit.stack_size,
            entry.arena,
            entry.arena_size / 1024,
            if entry.world > 0 {
                format!("  hit 0x{:X}", entry.world_at)
            } else {
                String::new()
            }
        );
    }

    if let Some(entry) = ranked.first() {
        println!();
        println!("  state  0x{:X}", entry.hit.state);
        println!("  global 0x{:X}", entry.hit.global);
        println!("  stack  0x{:X}", entry.hit.stack);
        print!("{}", state::hex(&process, entry.hit.state, 0x90));
        print!("{}", state::hex(&process, entry.hit.stack, 0x60));
        print!("{}", state::hex(&process, entry.hit.global, 0x60));
    }

    Ok(())
}

fn run_read(args: &Args, address: u64) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };
    let len = args.count.max(16);
    println!("zenoscope read  pid {}  0x{address:X}  {len:#X} bytes", process.pid);
    print!("{}", state::hex(&process, address, len));
    Ok(())
}

fn run_findtext(args: &Args, needle: &[u8]) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };
    let cap = args.state_cap_mb.saturating_mul(1024 * 1024);
    let mut scanned = 0usize;
    let mut shown = 0usize;
    println!("zenoscope findtext  pid {}  needle {:?}", process.pid, String::from_utf8_lossy(needle));
    for (base, size) in state::regions(&process) {
        if scanned >= cap || shown >= args.count {
            break;
        }
        let len = size.min(cap - scanned);
        scanned += len;
        let mut offset = 0usize;
        while offset < len && shown < args.count {
            let chunk = (len - offset).min(state::CHUNK);
            let Some(bytes) = process.read(base + offset as u64, chunk) else {
                offset += chunk;
                continue;
            };
            let mut index = 0usize;
            while index + needle.len() <= bytes.len() && shown < args.count {
                if &bytes[index..index + needle.len()] == needle {
                    let address = base + offset as u64 + index as u64;
                    println!();
                    println!("  text 0x{address:X}  region 0x{base:X}");
                    let start = address.saturating_sub(0x40);
                    print!("{}", state::hex(&process, start, 0xA0));
                    shown += 1;
                }
                index += 1;
            }
            offset += chunk;
        }
    }
    println!();
    println!("  scanned {:.1} MiB  shown {shown}", scanned as f64 / (1024.0 * 1024.0));
    Ok(())
}

fn run_findthreads(args: &Args) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };
    let cap = args.state_cap_mb.saturating_mul(1024 * 1024);
    let (hits, scanned) = state::find_threads_by_tag(&process, cap, args.count);
    println!(
        "zenoscope threads  pid {}  scanned {:.1} MiB  hits {}",
        process.pid,
        scanned as f64 / (1024.0 * 1024.0),
        hits.len()
    );
    for hit in &hits {
        println!(
            "  state 0x{:X}  stack+0x{:X} -> 0x{:X}  slots {}",
            hit.state, hit.stack_at, hit.stack, hit.slots
        );
        print!("{}", state::hex(&process, hit.state, 0x80));
    }
    Ok(())
}

fn run_pair(args: &Args, first: u64, second: u64) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };
    let mut a = Vec::new();
    let mut b = Vec::new();
    for (base, size) in state::regions(&process) {
        if a.len() < 12 {
            a.extend(state::find_value_in_region(&process, base, size, first, 12));
        }
        if b.len() < 12 {
            b.extend(state::find_value_in_region(&process, base, size, second, 12));
        }
        if a.len() >= 12 && b.len() >= 12 {
            break;
        }
    }
    println!(
        "zenoscope pair  pid {}  first {} hits  second {} hits",
        process.pid,
        a.len(),
        b.len()
    );
    for one in &a {
        for two in &b {
            if one.abs_diff(*two) > 0x200 {
                continue;
            }
            println!();
            println!("  first slot 0x{one:X}  second slot 0x{two:X}");
            let from = (*one).min(*two).saturating_sub(0x100) & !0xF;
            print!("{}", state::hex(&process, from, 0x200));
        }
    }
    Ok(())
}

fn run_hunt(args: &Args) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };
    let cap = args.state_cap_mb.saturating_mul(1024 * 1024);
    let hunt = state::lua_hunt(&process, cap);
    println!(
        "zenoscope hunt  pid {}  stack 0x{:X}  slots {}  pairs {}",
        process.pid,
        hunt.stack,
        hunt.slots,
        hunt.pairs.len()
    );
    if hunt.stack == 0 {
        return Ok(());
    }
    print!("{}", state::hex(&process, hunt.stack, 0x80));
    for (base_slot, last_slot) in &hunt.pairs {
        println!();
        println!("  stack slot 0x{base_slot:X}  last-ish 0x{last_slot:X}");
        let from = (*base_slot).saturating_sub(0x100) & !0xF;
        print!("{}", state::hex(&process, from, 0x240));
    }
    Ok(())
}

fn run_findstack(args: &Args) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };
    let cap = args.state_cap_mb.saturating_mul(1024 * 1024);
    let (runs, scanned) = state::find_stacks(&process, cap, args.count);
    println!(
        "zenoscope findstack  pid {}  scanned {:.1} MiB  runs {}",
        process.pid,
        scanned as f64 / (1024.0 * 1024.0),
        runs.len()
    );
    for run in runs.iter().take(6) {
        println!();
        println!("  stack 0x{:X}  slots {}", run.base, run.slots);
        print!("{}", state::hex(&process, run.base, 0x80));
        let mut referrers = Vec::new();
        for (base, size) in state::regions(&process) {
            if referrers.len() >= 4 {
                break;
            }
            let hits = state::find_value_in_region(&process, base, size, run.base, 4 - referrers.len());
            referrers.extend(hits);
        }
        for address in referrers {
            println!("    ref 0x{address:X}");
            let start = address.saturating_sub(0x38);
            print!("{}", state::hex(&process, start, 0x90));
        }
    }
    Ok(())
}

fn run_findtt(args: &Args, tag: u8) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };
    let cap = args.state_cap_mb.saturating_mul(1024 * 1024);
    let (states, scanned) = state::find_states_by_tag(&process, tag, cap, args.count);
    println!(
        "zenoscope findtt  pid {}  tag {}  scanned {:.1} MiB  states {}",
        process.pid,
        tag,
        scanned as f64 / (1024.0 * 1024.0),
        states.len()
    );
    for state in &states {
        println!();
        println!("  state 0x{state:X}");
        print!("{}", state::hex(&process, *state - 8, 0x80));
    }
    Ok(())
}

fn run_findstring(args: &Args, needle: &[u8]) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };
    let cap = args.state_cap_mb.saturating_mul(1024 * 1024);
    let (objects, scanned) = state::find_string_objects(&process, needle, cap, args.count);
    println!(
        "zenoscope findstring  pid {}  {:?}",
        process.pid,
        String::from_utf8_lossy(needle)
    );
    println!(
        "  scanned {:.1} MiB  objects {}",
        scanned as f64 / (1024.0 * 1024.0),
        objects.len()
    );
    for object in objects.iter().take(args.count) {
        println!();
        println!("  tstring 0x{object:X}");
        print!("{}", state::hex(&process, *object, 0x20 + needle.len()));
    }
    Ok(())
}

fn run_probe_lua(args: &Args, root: u64) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };
    println!(
        "zenoscope probe-lua  pid {}  root 0x{root:X}",
        process.pid
    );
    print!("{}", state::hex(&process, root, 0x80));

    let paths = state::probe_lua(&process, root, args.count.max(0x40));
    println!("  paths {}", paths.len());
    for path in &paths {
        println!(
            "    holder 0x{:X} slot +0x{:X}  state 0x{:X}  global 0x{:X}  buckets {}  nuse {}",
            path.holder, path.slot, path.state, path.global, path.buckets, path.nuse
        );
    }
    for path in paths.iter().take(3) {
        println!();
        println!("  state  0x{:X}", path.state);
        print!("{}", state::hex(&process, path.state, 0x80));
        println!("  global 0x{:X}", path.global);
        print!("{}", state::hex(&process, path.global, 0x40));
    }
    Ok(())
}

fn run_findvm(args: &Args) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };
    let cap = args.state_cap_mb.saturating_mul(1024 * 1024);
    println!("zenoscope findvm  pid {}", process.pid);
    let (vms, scanned) = state::find_vms(&process, cap);
    println!(
        "  scanned {:.1} MiB  string tables {}",
        scanned as f64 / (1024.0 * 1024.0),
        vms.len()
    );
    for vm in &vms {
        println!(
            "  global 0x{:X}  nuse {:>6}  buckets {:>7}  thread {}",
            vm.global,
            vm.nuse,
            vm.size,
            match vm.thread {
                Some(thread) => format!("0x{thread:X}"),
                None => "?".into(),
            }
        );
    }
    for vm in vms.iter().filter(|vm| vm.thread.is_some()).take(2) {
        let thread = vm.thread.unwrap();
        println!();
        println!("  global 0x{:X}", vm.global);
        print!("{}", state::hex(&process, thread, 0x90));
        print!("{}", state::hex(&process, vm.global, 0x40));
    }
    Ok(())
}

fn run_findvalue(args: &Args, needle: u64) -> Result<(), String> {
    let process = match args.pid {
        Some(pid) => Process::open_pid(pid)?,
        None => Process::open_by_name(CLIENT_EXE)?,
    };
    let cap = args.state_cap_mb.saturating_mul(1024 * 1024);
    let mut scanned = 0usize;
    let mut shown = 0usize;
    println!("zenoscope findvalue  pid {}  needle 0x{needle:X}", process.pid);
    for (base, size) in state::regions(&process) {
        if scanned >= cap || shown >= args.count {
            break;
        }
        let len = size.min(cap - scanned);
        let hits = state::find_value_in_region(&process, base, len, needle, 16);
        scanned += len;
        for address in hits {
            if shown >= args.count {
                break;
            }
            let kind = state::region_kind(&process, address);
            println!();
            println!(
                "  hit 0x{address:X}  region 0x{base:X}  kind 0x{kind:X}"
            );
            let start = address.saturating_sub(0x40);
            print!("{}", state::hex(&process, start, 0x80));
            shown += 1;
        }
    }
    println!();
    println!("  scanned {:.1} MiB  shown {shown}", scanned as f64 / (1024.0 * 1024.0));
    Ok(())
}

fn run_vtable(args: &Args, pack_path: PathBuf) -> Result<(), String> {
    let text = std::fs::read_to_string(&pack_path)
        .map_err(|e| format!("cannot read {}: {e}", pack_path.display()))?;
    let pack = hpp::Pack::parse(&text);

    let mut offsets: HashMap<String, u64> = HashMap::new();
    for entry in &pack.entries {
        offsets.insert(format!("{}::{}", entry.namespace, entry.name), entry.value);
    }

    let module = args.module.as_deref().unwrap_or(CLIENT_MODULE);
    let report = dump::vtable(args.pid, module, &offsets, args.count)?;

    println!("zenoscope vtable  {module}  pid {}", report.pid);
    println!("  module base  0x{:X}", report.base);
    println!("  FakeDataModel 0x{:X}", report.fake);
    println!("  DataModel     0x{:X}", report.datamodel);
    println!("  ScriptContext 0x{:X}  (via {})", report.context, report.via);
    println!("  vtable        0x{:X}", report.vptr);
    println!();
    println!("  slot  address            page       readable  in module");

    let mut page_hits = 0usize;
    for (index, address, readable, in_module) in &report.entries {
        if *readable {
            page_hits += 1;
        }
        println!(
            "  {:<4}  0x{:<16X} 0x{:<8X} {:<9} {}",
            index,
            address,
            address & !0xFFF,
            if *readable { "yes" } else { "NO" },
            if *in_module { "yes" } else { "no" }
        );
    }

    println!();
    println!(
        "  readable slots  {page_hits}/{} â€” these pages are decrypted right now",
        report.entries.len()
    );

    Ok(())
}

fn run_chain(args: &Args, pack_path: PathBuf) -> Result<(), String> {
    let text = std::fs::read_to_string(&pack_path)
        .map_err(|e| format!("cannot read {}: {e}", pack_path.display()))?;
    let pack = hpp::Pack::parse(&text);

    let mut offsets: HashMap<String, u64> = HashMap::new();
    for entry in &pack.entries {
        offsets.insert(format!("{}::{}", entry.namespace, entry.name), entry.value);
    }

    let module = args.module.as_deref().unwrap_or(CLIENT_MODULE);
    println!("zenoscope chain  {module}");
    println!("  pack         {} ({} entries)", pack_path.display(), pack.entries.len());
    println!();

    let hops = dump::chain(args.pid, module, &offsets)?;
    for hop in &hops {
        let summary = match (hop.name.is_empty(), hop.class.is_empty()) {
            (true, true) => String::new(),
            (false, true) => format!("  name \"{}\"", hop.name),
            (true, false) => format!("  class {}", hop.class),
            (false, false) => format!("  {} [{}]", hop.name, hop.class),
        };
        println!(
            "  {:<32} 0x{:<12X} -> 0x{:<12X}{}",
            hop.label, hop.address, hop.value, summary
        );
    }

    let datamodel = hops
        .iter()
        .find(|h| h.label == "VisualEngine -> FakeDataModel")
        .map(|h| h.value)
        .unwrap_or(0);
    let direct = hops
        .iter()
        .find(|h| h.label == "FakeDataModel::Pointer")
        .map(|h| h.value)
        .unwrap_or(0);

    println!();
    if datamodel != 0 && direct != 0 {
        println!(
            "  cross-check  VisualEngine::FakeDataModel {} FakeDataModel::Pointer",
            if datamodel == direct {
                "matches"
            } else {
                "DIFFERS from"
            }
        );
    } else {
        println!("  cross-check  one of the two fake-data-model paths is null");
    }

    let real = hops
        .iter()
        .find(|h| h.label == "FakeDataModel -> RealDataModel")
        .map(|h| h.value)
        .unwrap_or(0);

    if real != 0 {
        println!();
        println!("  data model children");
        // The handle is opened inside `chain`; reopen for the walk.
        let listing = dump::children_of(args.pid, module, &offsets, real, 16)?;
        for (name, class, address) in &listing {
            println!("    0x{:<12X} {:<28} [{}]", address, name, class);
        }
    }

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
        args.follow,
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
            "no new pages â€” the fault did not reach the client's handler"
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
            "partial decrypt â€” some pages stayed encrypted"
        } else {
            "nothing decrypted â€” the flush no longer forces a fault"
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

    if args.threads {
        return run_findthreads(&args);
    }

    if let Some((first, second)) = args.pair {
        return run_pair(&args, first, second);
    }

    if args.hunt {
        return run_hunt(&args);
    }

    if args.find_stack {
        return run_findstack(&args);
    }

    if let Some(tag) = args.find_tt {
        return run_findtt(&args, tag);
    }

    if let Some(text) = args.find_string.clone() {
        return run_findstring(&args, text.as_bytes());
    }

    if let Some(address) = args.probe_lua {
        return run_probe_lua(&args, address);
    }

    if let Some(address) = args.read {
        return run_read(&args, address);
    }

    if let Some(text) = args.find_text.clone() {
        return run_findtext(&args, text.as_bytes());
    }

    if args.find_vm {
        return run_findvm(&args);
    }

    if let Some(needle) = args.find_value {
        return run_findvalue(&args, needle);
    }

    if args.find_state {
        return run_findstate(&args);
    }

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

    if let Some(pack) = args.children.clone() {
        return run_children(&args, pack);
    }

    if let Some(pack) = args.vtable.clone() {
        return run_vtable(&args, pack);
    }

    if let Some(pack) = args.chain.clone() {
        return run_chain(&args, pack);
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



