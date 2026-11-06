# Zeno

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
│  injector (LL / manual map)│        │                              │
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

```bash
npm install

# 1. the injected payload (MSVC 2022 + CMake ≥ 3.20, x64)
cd zeno-core
cmake -S . -B build -A x64
cmake --build build --config Release
cd ..

# 2. run the app
npm run tauri:dev
```

For a release bundle:

```bash
copy zeno-core\build\zeno_inject.dll     src-tauri\resources\
copy zeno-core\config\zeno_offsets.json  src-tauri\resources\
npm run tauri:build
```

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
  does not trip unbacked-executable-memory scans. Thread creation goes through
  `NtCreateThreadEx`. All three ntdll entry points are resolved at runtime, not
  linked.

`process::probe_write` runs before the section map and turns a denied write
handle into an explicit error — that denial is what a kernel-level handle filter
looks like from usermode.

## Anti-cheat scope

Be clear about what the injection layer does and does not cover:

| vector | covered |
|---|---|
| unbacked executable memory | yes, by `section` |
| remote module list (LoadLibrary) | yes, by `manualmap` / `section` |
| ntdll hook on thread creation | partially — dynamic resolution, no direct syscalls yet |
| handle filtering (kernel) | **no** — needs a driver or a signed loader |
| thread-creation notification (kernel) | **no** |
| image-load notification (kernel) | **no** |
| `.text` integrity checks | **no** |

Hyperion (Byfron) on the Windows client ships a kernel component that enforces
the last four. Usermode-only injection does not get past it; the practical
routes are a signed vulnerable driver, or injecting inside the window before
Hyperion initialises. Everything above that — the bridge, the Luau runtime, the
scheduler — is unaffected and works as soon as injection succeeds.

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
