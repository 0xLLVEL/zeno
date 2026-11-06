# zeno-core

The injected half of Zeno: a Luau runtime plus the named-pipe bridge that hangs
off `RobloxPlayerBeta.exe`.

## What's in here

| file | role |
|---|---|
| `src/dllmain.cpp` | entry point, bootstrap order (rbx → luau → bridge) |
| `src/bridge.cpp` | pipe client: `\\.\pipe\zeno_in` (scripts in) / `zeno_out` (console out) |
| `src/executor.cpp` | Luau state, scheduler, prelude, script lifecycle |
| `src/roblox.cpp` | module base, pattern scan, offset config loader |
| `config/zeno_offsets.json` | per-build offsets + signatures — edit, no rebuild |

## Build

Requires CMake ≥ 3.20 and MSVC 2022 (x64).

```bash
cmake -S . -B build -A x64
cmake --build build --config Release
```

Output: `build/zeno_inject.dll` (next to `zeno_offsets.json`).

Luau is pulled by `FetchContent` at tag `0.653`. For offline builds, point
`LUAU_SRC_DIR` at a local checkout:

```bash
set LUAU_SRC_DIR=C:\src\luau
cmake -S . -B build -A x64
```

## Protocol

Rust → DLL (`zeno_in`):

```
[u32 little-endian length][utf-8 source bytes]
```

DLL → Rust (`zeno_out`): newline-delimited UTF-8, one console line per message.
Prefixes `[error]` / `[warn]` are mapped to log levels by the UI.

## Offsets

`zeno_offsets.json` sits beside the DLL. It carries numeric offsets and byte
signatures. When a Roblox build shifts, only that file changes.

```json
{
  "offsets": { "DataModel": 0, "Workspace": 0 },
  "patterns": { "DataModelScan": "48 8B 05 ? ? ? ? ..." }
}
```

With a valid `DataModelScan` signature, `rbx::datamodel()` resolves the live
DataModel pointer at load time and `zeno_capability("attached")` turns true.
Without it the runtime still boots, the scheduler still works, and scripts get
the offline service table from the prelude.

## Luau surface

Globals installed by the prelude: `print`, `warn`, `task.wait`, `task.spawn`,
`task.delay`, `task.defer`, `wait`, `spawn`, `delay`, `tick`, `time`,
`Instance.new`, `game`, `workspace`, `script`, `shared`.

Native helpers: `zeno_capability`, `zeno_read_ptr`, `zeno_datamodel`,
`zeno_offsets` (table of resolved values).

## Threading

One owner thread for the Lua state. `execute()` queues; the worker drains the
queue, resumes any threads whose `task.wait` expired, and never blocks on I/O.
`task.spawn` / `task.delay` create coroutines that are resumed by the same
worker, so yields are real yields rather than busy waits.
