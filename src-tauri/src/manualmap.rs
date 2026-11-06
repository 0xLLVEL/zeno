#![cfg(windows)]

use std::path::Path;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE, VirtualProtectEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, WaitForSingleObject, LPTHREAD_START_ROUTINE,
};

fn u16_at(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[o..o + 8]);
    u64::from_le_bytes(b)
}

struct Section {
    va: u32,
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
}

pub fn map(pid: u32, dll: &Path) -> Result<(), String> {
    let data = std::fs::read(dll).map_err(|e| format!("read payload: {e}"))?;
    if data.len() < 0x100 {
        return Err("payload too small".into());
    }

    let e_lfanew = u32_at(&data, 0x3C) as usize;
    if u32_at(&data, e_lfanew) != 0x0000_4550 {
        return Err("bad PE signature".into());
    }

    let file_header = e_lfanew + 4;
    let num_sections = u16_at(&data, file_header + 2) as usize;
    let opt_size = u16_at(&data, file_header + 16) as usize;
    let opt = file_header + 20;

    if u16_at(&data, opt) != 0x020B {
        return Err("only x64 payloads supported".into());
    }

    let entry_rva = u32_at(&data, opt + 16);
    let image_base = u64_at(&data, opt + 24);
    let size_of_image = u32_at(&data, opt + 56) as usize;
    let size_of_headers = u32_at(&data, opt + 60) as usize;
    let dir_count = u32_at(&data, opt + 108) as usize;
    let dirs = opt + 112;

    let dir = |idx: usize| -> (u32, u32) {
        if idx >= dir_count {
            return (0, 0);
        }
        (u32_at(&data, dirs + idx * 8), u32_at(&data, dirs + idx * 8 + 4))
    };

    let mut sections = Vec::with_capacity(num_sections);
    let sec_table = opt + opt_size;
    for i in 0..num_sections {
        let s = sec_table + i * 40;
        sections.push(Section {
            vsize: u32_at(&data, s + 8),
            va: u32_at(&data, s + 12),
            raw_size: u32_at(&data, s + 16),
            raw_ptr: u32_at(&data, s + 20),
        });
    }

    let rva_to_off = |rva: u32| -> usize {
        for s in &sections {
            let span = s.vsize.max(s.raw_size);
            if rva >= s.va && rva < s.va + span {
                return (rva - s.va) as usize + s.raw_ptr as usize;
            }
        }
        rva as usize
    };

    unsafe {
        let process = crate::process::open_for_injection(pid)
            .map_err(|e| format!("OpenProcess failed: {e}"))?;

        let remote = VirtualAllocEx(
            process,
            None,
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if remote.is_null() {
            let _ = CloseHandle(process);
            return Err("VirtualAllocEx failed (image too large?)".into());
        }
        let base = remote as u64;

        let fail = |process, remote, msg: String| -> Result<(), String> {
            let _ = VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            let _ = CloseHandle(process);
            Err(msg)
        };

        let mut written = 0usize;
        if WriteProcessMemory(
            process,
            remote,
            data.as_ptr() as *const _,
            size_of_headers.min(data.len()),
            Some(&mut written),
        )
        .is_err()
        {
            return fail(process, remote, "write headers failed".into());
        }

        for s in &sections {
            if s.raw_size == 0 {
                continue;
            }
            let src = s.raw_ptr as usize;
            let len = s.raw_size as usize;
            if src + len > data.len() {
                continue;
            }
            let dst = (base + s.va as u64) as *mut core::ffi::c_void;
            if WriteProcessMemory(
                process,
                dst,
                data[src..src + len].as_ptr() as *const _,
                len,
                Some(&mut written),
            )
            .is_err()
            {
                return fail(process, remote, format!("write section @{:#x} failed", s.va));
            }
        }

        let delta = base.wrapping_sub(image_base);

        if delta != 0 {
            let (reloc_rva, reloc_size) = dir(5);
            if reloc_rva != 0 && reloc_size != 0 {
                let mut off = rva_to_off(reloc_rva);
                let end = off + reloc_size as usize;
                while off + 8 <= end && off + 8 <= data.len() {
                    let page_rva = u32_at(&data, off);
                    let block_size = u32_at(&data, off + 4);
                    if block_size < 8 {
                        break;
                    }
                    let count = (block_size as usize - 8) / 2;
                    for i in 0..count {
                        let entry = u16_at(&data, off + 8 + i * 2);
                        let kind = entry >> 12;
                        let ofs = (entry & 0x0FFF) as u32;
                        if kind == 0 {
                            continue;
                        }
                        if kind != 10 {
                            return fail(
                                process,
                                remote,
                                format!("unsupported relocation type {kind}"),
                            );
                        }
                        let patch_addr = (base + page_rva as u64 + ofs as u64)
                            as *mut core::ffi::c_void;
                        let mut current: u64 = 0;
                        let mut read = 0usize;
                        if ReadProcessMemory(
                            process,
                            patch_addr,
                            &mut current as *mut u64 as *mut _,
                            8,
                            Some(&mut read),
                        )
                        .is_err()
                        {
                            return fail(process, remote, "reloc read failed".into());
                        }
                        current = current.wrapping_add(delta);
                        if WriteProcessMemory(
                            process,
                            patch_addr,
                            &current as *const u64 as *const _,
                            8,
                            Some(&mut written),
                        )
                        .is_err()
                        {
                            return fail(process, remote, "reloc write failed".into());
                        }
                    }
                    off += block_size as usize;
                }
            }
        }

        let (import_rva, import_size) = dir(1);
        if import_rva != 0 && import_size != 0 {
            let mut off = rva_to_off(import_rva);
            loop {
                let name_rva = u32_at(&data, off + 12);
                if name_rva == 0 {
                    break;
                }
                let first_thunk = u32_at(&data, off + 16);
                if first_thunk == 0 {
                    break;
                }
                let name_off = rva_to_off(name_rva);
                let dll_name = read_cstr(&data, name_off);
                let module = crate::injector::resolve_module(&dll_name)
                    .ok_or_else(|| format!("cannot resolve module {dll_name}"))?;

                let thunk_rva = first_thunk;
                let mut idx = 0usize;
                loop {
                    let thunk_off = rva_to_off(thunk_rva + idx as u32 * 8);
                    if thunk_off + 8 > data.len() {
                        break;
                    }
                    let thunk = u64_at(&data, thunk_off);
                    if thunk == 0 {
                        break;
                    }
                    let resolved = if thunk & 0x8000_0000_0000_0000 != 0 {
                        let ordinal = (thunk & 0xFFFF) as u16;
                        resolve_ordinal(module, ordinal)
                    } else {
                        let hint_rva = (thunk & 0x7FFF_FFFF) as u32;
                        let hint_off = rva_to_off(hint_rva);
                        let func_name = read_cstr(&data, hint_off + 2);
                        crate::injector::resolve_export(module, func_name.as_bytes())
                    };
                    let resolved = resolved.ok_or_else(|| {
                        format!("unresolved import #{} in {dll_name}", idx)
                    })?;
                    let dest = (base + first_thunk as u64 + idx as u64 * 8)
                        as *mut core::ffi::c_void;
                    if WriteProcessMemory(
                        process,
                        dest,
                        &resolved as *const usize as *const _,
                        8,
                        Some(&mut written),
                    )
                    .is_err()
                    {
                        return fail(process, remote, "import write failed".into());
                    }
                    idx += 1;
                }
                off += 20;
            }
        }

        let mut old = PAGE_READWRITE;
        let _ = VirtualProtectEx(process, remote, size_of_image, PAGE_EXECUTE_READWRITE, &mut old);

        let entry = (base + entry_rva as u64) as *const core::ffi::c_void;
        let start: LPTHREAD_START_ROUTINE = std::mem::transmute(entry);

        let thread = CreateRemoteThread(
            process,
            None,
            0,
            start,
            Some(1 as *const core::ffi::c_void), // DLL_PROCESS_ATTACH
            Default::default(),
            None,
        );

        match thread {
            Ok(h) => {
                WaitForSingleObject(h, 5000);
                let _ = CloseHandle(h);
            }
            Err(e) => return fail(process, remote, format!("entry thread failed: {e}")),
        }

        let _ = CloseHandle(process);
        Ok(())
    }
}

fn read_cstr(data: &[u8], off: usize) -> String {
    let mut end = off;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[off..end]).to_string()
}

fn resolve_ordinal(module: usize, ordinal: u16) -> Option<usize> {
    unsafe {
        let base = module as *const u8;
        if base.is_null() {
            return None;
        }
        let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
        let opt = base.add(e_lfanew + 24);
        let export_rva = *(opt.add(112 + 8 * 0) as *const u32);
        if export_rva == 0 {
            return None;
        }
        let export = base.add(export_rva as usize);
        let ordinal_base = *(export.add(16) as *const u32);
        let funcs = base.add(*(export.add(28) as *const u32) as usize) as *const u32;
        let index = ordinal.wrapping_sub(ordinal_base as u16) as isize;
        let rva = *funcs.offset(index);
        if rva == 0 {
            None
        } else {
            Some(base.add(rva as usize) as usize)
        }
    }
}
