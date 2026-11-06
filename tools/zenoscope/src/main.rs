//! zenoscope — resolve Roblox engine offsets without trusting hardcoded
//! addresses.
//!
//! Two sources:
//!   * a live client's mapped image (the only one that works on the shipped
//!     client — its `.text` is encrypted on disk)
//!   * the file on disk (fallback, and how the tool is exercised in tests)

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

const PROLOGUES: [&[u8]; 4] = [
    &[0x48, 0x89, 0x5C, 0x24],
    &[0x48, 0x83, 0xEC],
    &[0xCC, 0xCC, 0xCC, 0xCC],
    &[0x00, 0x00, 0x00, 0x00],
];

struct Args {
    exe: Option<PathBuf>,
    pid: Option<u32>,
    probe: Option<u32>,
    verify: Option<PathBuf>,
    module: Option<String>,
    json: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        exe: None,
        pid: None,
        probe: None,
        verify: None,
        module: None,
        json: None,
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
            "-h" | "--help" => {
                println!("zenoscope [--pid <n> | --exe <path>] [--module <name>] [--json <out>]");
                println!("zenoscope --probe <pid>     report which access masks the target grants");
                println!("zenoscope --verify <hpp>    check an offsets pack against this client");
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

fn thousands(mut n: u64) -> String {
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
        notes,
    })
}

fn main() {
    if let Err(message) = run() {
        eprintln!("zenoscope: {message}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

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
    let counts = scan::count_patterns(image, &PROLOGUES);
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
