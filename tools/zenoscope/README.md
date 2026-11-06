# zenoscope

Offline and live inspection for the Roblox client. Reads the PE on disk, probes
the running process, and reconstructs a readable `.text` from what Hyperion
decrypts at execution time.

Most commands need elevation: attaching with `PROCESS_ALL_ACCESS` and reading
protected pages requires `SeDebugPrivilege`.

## Commands

```text
zenoscope --exe <path> --verify <pack.hpp>
    Check an offsets pack against an image: version, pointer slots, structure,
    RTTI.

zenoscope --dump
    Flush every `.text` page of the live client and copy the ones that come back
    readable.

zenoscope --inspect <n>
    Look at the first n `.text` pages: protection, state, and whether the bytes
    differ from disk.

zenoscope --force-dump
    Copy pages from a thread inside the target, for pages RPM refuses.

zenoscope --watch <secs> [--base <image>] [--out <path>] [--rebuild] [--follow]
    Sample `.text` repeatedly and keep every page the client has decrypted.

zenoscope --chain <pack.hpp>
    Walk VisualEngine -> FakeDataModel -> RealDataModel through the live client
    and print each object's name and class, plus the data model's children.
```

## `--watch` and `--follow`

Hyperion keeps a page in the clear only while it is being executed, so a single
snapshot is a slice of `.text`. `--watch` samples on a loop and merges each
decrypted page into an image; coverage accumulates across runs because pages
already harvested differ from the on-disk ciphertext and are skipped.

`--follow` keeps the harvest alive across client restarts. On most game switches
the client spawns a fresh process with a new base address; the harvester notices
the dead pid, re-attaches, and keeps merging into the same image. If the module
path changes, it refuses to merge two builds into one file.

Progress prints every 5s, the image is checkpointed every 60s, and the final
write happens on exit. Coverage is reported as the merged total, not the number
of pages captured in the last pass.

```powershell
# one hour of rotation across games, merged into a single image
zenoscope --watch 3600 --follow --base dumped.exe --out dumped.exe --rebuild
```

## Layout

| File | Role |
|---|---|
| `src/image.rs` | PE parsing, RVA mapping |
| `src/live.rs` | process/module enumeration, kernel32 FFI |
| `src/hpp.rs` | offsets pack parser |
| `src/scan.rs` | prologue and RTTI scanning |
| `src/dump.rs` | dump, inspect, force, watch/follow, rebuild, chain |
| `src/main.rs` | CLI |
