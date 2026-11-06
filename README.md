# Zeno

[![build](https://github.com/0xLLVEL/zeno/actions/workflows/build.yml/badge.svg)](https://github.com/0xLLVEL/zeno/actions/workflows/build.yml)

Roblox script executor. Tauri 2 + React 18 shell, Rust injector, Luau runtime
inside the client, named-pipe bridge between them.

```
┌────────────────────────────┐        ┌──────────────────────────────┐
│  Zeno.exe (Tauri/Rust)     │        │  RobloxPlayerBeta.exe        │
│                            │        │                              │
│  React UI ──invoke──▶ cmd  │        │  zeno_inject.dll             │
│                            │        │   ├─ Luau VM + scheduler     │
│  pipe server               │        │   ├─ prelude (task/Instance) │
│   \\.\pipe\zeno_in ────────┼───────▶│   └─ pipe client             │
│   \\.\pipe\zeno_out ◀──────┼────────│                              │
│  injector (LL/map/sect/apc/hijack)│  │                              │
└────────────────────────────┘        └──────────────────────────────┘
```

## Layout

```
src/                 React UI (editor, console, hub, settings)
src-tauri/           Tauri shell + injector + pipe server
zeno-core/           injected DLL: Luau runtime + bridge client
tools/gen-icon.cjs   generates icons with zero deps
```

## Build

One script does the whole chain on Windows:

```powershell
.\build.ps1 -Test          # payload, frontend, tests, app (no installer)
.\build.ps1 -Bundle -Test  # same, plus the NSIS installer
```

`-SkipPayload` skips CMake, `-SkipUi` skips the frontend build — useful when
you already have either side built.

Manual equivalent:

```bash
npm install

# 1. the injected payload (MSVC 2022 + CMake >= 3.20, x64)
cmake -S zeno-core -B zeno-core/build -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build zeno-core/build --config Release
copy zeno-core\build\zeno_inject.dll    src-tauri\resources\
copy zeno-core\build\zeno_offsets.json  src-tauri\resources\

# 2. run the app
npm run tauri:dev

# 3. or build it
npm run tauri:build
```

### Building without a local toolchain

`.github/workflows/build.yml` runs on `windows-latest`, which already has MSVC
and CMake:

| job | what it does |
|---|---|
| `payload` | CMake build of `zeno_inject.dll`, verified to exist and be non-trivial, uploaded as an artifact |
| `tests` | `npm run build` then `cargo test --lib` — the syscall and stub tests run here |
| `app` | downloads the payload into `src-tauri/resources`, then `tauri build --no-bundle`, uploads `zeno.exe` |

The Luau checkout is cached under `zeno-core/build/_deps`, keyed `luau-0.653`,
so repeat builds skip the clone.

## Features

- **Editor** — Monaco, Luau grammar + `zeno` theme, tabs, multi-file, Ctrl+Enter
  to run, dirty markers.
- **Console** — levelled output (`info/ok/warn/error/out`), per-level filters,
  text search, follow-tail, inline REPL line.
- **Script Hub** — bundled scripts, tag filter, search, open-into-tab / copy.
- **Attach** — process scan, one-click attach, `LoadLibrary` or manual-map
  injection, live bridge status.
- **Settings** — auto-attach, injection method, custom DLL injection, editor
  font/minimap/wrap, console buffer, accent colour. Persisted via `zustand`.

## Injection

`src-tauri/src/injector.rs` dispatches on the method chosen in settings.

- `loadlibrary` — `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`.
- `manualmap` (`src-tauri/src/manualmap.rs`) — maps the PE by hand: headers,
  sections, base relocations (`IMAGE_REL_BASED_DIR64`), import resolution by
  name and ordinal, then a remote `DllMain(DLL_PROCESS_ATTACH)` thread. The
  module never touches the loader list.
- `section` (`src-tauri/src/section.rs`) — `NtCreateSection(SEC_IMAGE)` on the
  payload file, then `NtMapViewOfSection` into the target. The kernel applies
  relocations and resolves imports, and the mapping is **file-backed**, so it
  does not trip unbacked-executable-memory scans.
- `apc` (`src-tauri/src/apc.rs`) — same section map, but no thread is created.
  A 33-byte `DllMain(base, DLL_PROCESS_ATTACH, NULL)` stub is written into the
  target and queued with `NtQueueApcThread` on up to 16 existing threads. Since
  no thread is created, thread-creation notification never fires. Caveat: a
  user-mode APC only runs when the target thread enters an alertable wait, and
  Roblox threads rarely do — this method can queue cleanly and never execute.
- `hijack` (`src-tauri/src/hijack.rs`) — same section map, then an existing
  thread is suspended, its `Rip` is redirected into a stub, and the thread is
  resumed. The stub calls `DllMain` on a private scratch stack, then restores
  every volatile register, `RFLAGS` and the original `Rip` via a
  `jmp qword ptr [rip+0]`, so the interrupted thread continues where it
  stopped. No thread is created, nothing is queued, and there is no alertable-
  wait precondition.

Every ntdll entry point used by `section` and `apc` goes through
`src-tauri/src/nt.rs`, the direct-syscall layer:

- SSNs are recovered at runtime from ntdll's own stubs (Hell's Gate:
  `4C 8B D1 B8 <imm32>`), with a Halo's Gate walk over address-sorted neighbours
  when a stub is hooked.
- Each SSN becomes an 11-byte `mov r10, rcx / mov eax, ssn / syscall / ret`
  trampoline in this process, so the call never enters a hooked ntdll prologue.
- If a stub cannot be resolved, `section` falls back to resolved ntdll exports
  and `apc` refuses rather than silently degrading.

`process::probe_write` runs before every map and turns a denied write handle
into an explicit error — that denial is what a kernel-level handle filter looks
like from usermode.

### Stub placement (`src-tauri/src/stub.rs`)

`apc` and `hijack` both need a few dozen bytes of executable code inside the
target. Allocating one with `NtAllocateVirtualMemory` + `PAGE_EXECUTE_READ`
works, but that region has no file backing — the one signature an unbacked-
executable scan is built to find.

`stub::place` avoids it by writing the stub into space that is already inside
the mapped image:

1. **Real gaps between sections** — the loader-relevant data ends at
   `VirtualAddress + max(VirtualSize, SizeOfRawData)`; anything up to the next
   section's `VirtualAddress` is padding. Powered by measured numbers: kernel32
   has 2384 bytes, user32 3440, dxgi 696.
2. **Header padding** — the bytes between the end of the section table and the
   first section (`RVA 0x1000`). Always present, always zero, never referenced
   by the loader. ntdll has ~0xB00 bytes here.

The page is flipped with `NtProtectVirtualMemory` (RWX, then RW if RWX is
refused), written, and set back to `PAGE_EXECUTE_READ`. The VAD entry stays the
image section; only the touched page becomes privately dirty, which is the same
state any loader-patched import thunk is in.

When neither candidate fits, `stub::place_or_allocate` falls back to a private
RX allocation rather than failing the injection.

## Anti-cheat scope

Be clear about what the injection layer does and does not cover:

| vector | covered |
|---|---|
| unbacked executable memory | yes — payload is image-backed, stubs go into image slack |
| remote module list (LoadLibrary) | yes, by `manualmap` / `section` / `apc` / `hijack` |
| ntdll hooks on NT calls | yes, by `nt` direct syscalls |
| thread-creation notification (kernel) | yes — `apc` and `hijack` create no thread |
| APC / alertable-wait dependency | n/a for `hijack` |
| handle filtering (kernel) | **no** — needs a driver or a signed loader |
| image-load notification (kernel) | partially — section maps are real image views |
| `.text` integrity checks | **no** |

The remaining open vector is the fallback allocation, which only runs when the
image has no gap wide enough for the stub.

Hyperion (Byfron) on the Windows client ships a kernel component that owns
handle filtering and `.text` page integrity. Usermode-only injection does not
get past those two; the practical routes are a signed vulnerable driver, or
injecting inside the window before Hyperion initialises. Everything above that
— the bridge, the Luau runtime, the scheduler — is unaffected and works as soon
as injection succeeds.

## Bridge

Rust owns both pipe servers; the DLL connects as a client.

| pipe | direction | payload |
|---|---|---|
| `zeno_in` | Rust → DLL | `[u32 len][utf-8 source]` |
| `zeno_out` | DLL → Rust | newline-delimited console lines |

`drain_output` is polled by the UI every 900 ms.

## Luau runtime

`zeno-core/src/executor.cpp`

- One owner thread for the Lua state; scripts arrive through a queue.
- Each script runs on its own coroutine so `task.wait` is a real yield, not a
  busy loop. The worker resumes expired threads every 4 ms.
- Prelude installs `print`, `warn`, `task.{wait,spawn,delay,defer}`, `wait`,
  `spawn`, `delay`, `tick`, `time`, `Instance.new`, `game`, `workspace`,
  `script`, `shared`.
- Native helpers: `zeno_capability`, `zeno_read_ptr`, `zeno_datamodel`,
  `zeno_offsets`.

## Offsets

`zeno-core/config/zeno_offsets.json` carries per-build offsets and byte
signatures. It is copied next to the DLL and read at load — no rebuild when a
client build shifts. `rbx::datamodel()` resolves through the `DataModelScan`
signature; with a valid one the runtime reports `attached`, otherwise it runs in
offline mode with the prelude's service table.

See `zeno-core/README.md` for the DLL's own notes.

## Keyboard

| key | action |
|---|---|
| `Ctrl+Enter` | execute current tab |
| `Ctrl+T` | new tab |
| middle-click tab | close tab |
