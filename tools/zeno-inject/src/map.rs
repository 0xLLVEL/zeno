//! Manual mapping: build the payload image locally, then write it as one blob.
//!
//! `LoadLibraryW` inside the client is refused, so nothing here touches the
//! target's loader. Imports are resolved against this process (system DLLs sit
//! at the same addresses in both), relocations are applied against the target
//! base, and the result is a plain byte range the injector writes once.

use std::ffi::c_void;

type Handle = *mut c_void;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(name: *const u16) -> Handle;
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `SizeOfImage` from the optional header.
pub fn image_size(file: &[u8]) -> Result<u32, String> {
    let pe = u32_at(file, 0x3C).ok_or("truncated DOS header")? as usize;
    let optional = pe + 24;
    u32_at(file, optional + 56).ok_or_else(|| "truncated optional header".into())
}

fn sections(file: &[u8]) -> Result<Vec<(u32, u32, u32, u32)>, String> {
    let pe = u32_at(file, 0x3C).ok_or("truncated DOS header")? as usize;
    let count = u16_at(file, pe + 6).ok_or("truncated COFF")? as usize;
    let optional_size = u16_at(file, pe + 20).ok_or("truncated COFF")? as usize;
    let table = pe + 24 + optional_size;

    let mut out = Vec::new();
    for index in 0..count {
        let at = table + index * 40;
        let virtual_size = u32_at(file, at + 8).ok_or("truncated section")?;
        let virtual_address = u32_at(file, at + 12).ok_or("truncated section")?;
        let raw_size = u32_at(file, at + 16).ok_or("truncated section")?;
        let raw_pointer = u32_at(file, at + 20).ok_or("truncated section")?;
        out.push((virtual_address, virtual_size, raw_pointer, raw_size));
    }
    Ok(out)
}

fn rva_to_offset(
    sections: &[(u32, u32, u32, u32)],
    rva: u32,
) -> Option<usize> {
    for (virtual_address, virtual_size, raw_pointer, raw_size) in sections {
        let span = (*virtual_size).max(*raw_size);
        if rva >= *virtual_address && rva < virtual_address + span {
            let delta = rva - virtual_address;
            if delta < *raw_size {
                return Some((*raw_pointer + delta) as usize);
            }
            return None;
        }
    }
    None
}

/// Imported libraries and symbol names, read straight from the file.
pub fn list_imports(file: &[u8]) -> Result<Vec<(String, Vec<String>)>, String> {
    let sections = sections(file)?;
    let pe = u32_at(file, 0x3C).ok_or("truncated DOS header")? as usize;
    let optional = pe + 24;
    let import_rva = u32_at(file, optional + 112 + 8).ok_or("truncated data directory")?;
    if import_rva == 0 {
        return Ok(Vec::new());
    }
    let mut descriptor = rva_to_offset(&sections, import_rva).ok_or("import table unmapped")?;

    let mut out = Vec::new();
    loop {
        let original =
            u32_at(file, descriptor).ok_or("truncated import descriptor")? as usize;
        let name_rva =
            u32_at(file, descriptor + 12).ok_or("truncated import descriptor")? as usize;
        let first_thunk =
            u32_at(file, descriptor + 16).ok_or("truncated import descriptor")? as usize;
        if original == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let Some(name_at) = rva_to_offset(&sections, name_rva as u32) else {
            break;
        };
        let library = cstr_in(file, name_at);

        let mut names = Vec::new();
        if let Some(mut thunk) = rva_to_offset(&sections, original as u32) {
            loop {
                let Some(value) = u64_at(file, thunk) else { break };
                if value == 0 {
                    break;
                }
                if value & (1 << 63) == 0 {
                    if let Some(at) = rva_to_offset(&sections, value as u32) {
                        names.push(cstr_in(file, at + 2));
                    }
                }
                thunk += 8;
            }
        }

        out.push((library, names));
        descriptor += 20;
    }
    Ok(out)
}

/// RVA of a named export, read from the image's own export directory.
pub fn export_rva(image: &[u8], name: &str) -> Option<u32> {
    let pe = u32_at(image, 0x3C)? as usize;
    let optional = pe + 24;
    let export_rva = u32_at(image, optional + 112)?;
    if export_rva == 0 {
        return None;
    }
    let dir = export_rva as usize;
    let count = u32_at(image, dir + 24)? as usize;
    let functions = u32_at(image, dir + 28)? as usize;
    let names = u32_at(image, dir + 32)? as usize;
    let ordinals = u32_at(image, dir + 36)? as usize;

    for index in 0..count {
        let name_rva = u32_at(image, names + index * 4)? as usize;
        let candidate = cstr_in(image, name_rva);
        if candidate == name {
            let ordinal = u16_at(image, ordinals + index * 2)? as usize;
            return u32_at(image, functions + ordinal * 4);
        }
    }
    None
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn put_u64(data: &mut [u8], offset: usize, value: u64) {
    if offset + 8 <= data.len() {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}

fn cstr_in(data: &[u8], offset: usize) -> String {
    let mut out = String::new();
    let mut index = offset;
    while let Some(byte) = data.get(index) {
        if *byte == 0 {
            break;
        }
        out.push(*byte as char);
        index += 1;
    }
    out
}

pub struct Mapping {
    pub image: Vec<u8>,
    pub entry: u32,
    pub preferred: u64,
}

/// Copy the file into a virtual layout with the given base baked in.
pub fn prepare(file: &[u8], base: u64) -> Result<Mapping, String> {
    let pe = u32_at(file, 0x3C).ok_or("truncated DOS header")? as usize;
    if file.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("not a PE image".into());
    }

    let section_count = u16_at(file, pe + 6).ok_or("truncated COFF")? as usize;
    let optional_size = u16_at(file, pe + 20).ok_or("truncated COFF")? as usize;
    let optional = pe + 24;
    if u16_at(file, optional) != Some(0x20B) {
        return Err("only 64-bit images are supported".into());
    }

    let entry = u32_at(file, optional + 16).ok_or("truncated optional header")?;
    let preferred = u64_at(file, optional + 24).ok_or("truncated optional header")?;
    let size = u32_at(file, optional + 56).ok_or("truncated optional header")?;
    let headers_size = u32_at(file, optional + 60).ok_or("truncated optional header")?;

    let mut image = vec![0u8; size as usize];
    let copy = (headers_size as usize).min(file.len()).min(image.len());
    image[..copy].copy_from_slice(&file[..copy]);

    let table = optional + optional_size;
    let mut sections = Vec::new();
    for index in 0..section_count {
        let at = table + index * 40;
        let virtual_size = u32_at(file, at + 8).ok_or("truncated section")?;
        let virtual_address = u32_at(file, at + 12).ok_or("truncated section")?;
        let raw_size = u32_at(file, at + 16).ok_or("truncated section")?;
        let raw_pointer = u32_at(file, at + 20).ok_or("truncated section")?;
        sections.push((virtual_address, virtual_size, raw_pointer, raw_size));
    }

    for (virtual_address, virtual_size, raw_pointer, raw_size) in &sections {
        let start = *virtual_address as usize;
        let len = (*virtual_size).min(*raw_size) as usize;
        let source = *raw_pointer as usize;
        if start >= image.len() || source >= file.len() {
            continue;
        }
        let len = len.min(image.len() - start).min(file.len() - source);
        image[start..start + len].copy_from_slice(&file[source..source + len]);
    }

    let directory = optional + 112;
    let reloc_rva = u32_at(file, directory + 5 * 8).ok_or("truncated data directory")?;
    let reloc_size = u32_at(file, directory + 5 * 8 + 4).ok_or("truncated data directory")?;
    let import_rva = u32_at(file, directory + 8).ok_or("truncated data directory")?;

    relocate(&mut image, reloc_rva, reloc_size, preferred, base)?;
    imports(&mut image, import_rva)?;

    Ok(Mapping {
        image,
        entry,
        preferred,
    })
}

fn relocate(image: &mut [u8], rva: u32, size: u32, preferred: u64, base: u64) -> Result<(), String> {
    if rva == 0 || size == 0 || preferred == base {
        return Ok(());
    }
    let delta = base.wrapping_sub(preferred);
    let start = rva as usize;
    let end = start + size as usize;
    let mut cursor = start;

    while cursor + 8 <= end {
        let page = u32_at(image, cursor).ok_or("truncated relocation block")? as usize;
        let block = u32_at(image, cursor + 4).ok_or("truncated relocation block")? as usize;
        if block < 8 {
            break;
        }
        let mut entry = cursor + 8;
        while entry + 2 <= cursor + block {
            let value = u16_at(image, entry).ok_or("truncated relocation entry")?;
            let kind = value >> 12;
            let offset = (value & 0x0FFF) as usize;
            if kind == 10 {
                let at = page + offset;
                if let Some(existing) = u64_at(image, at) {
                    put_u64(image, at, existing.wrapping_add(delta));
                }
            }
            entry += 2;
        }
        cursor += block;
    }

    Ok(())
}

fn imports(image: &mut [u8], rva: u32) -> Result<(), String> {
    if rva == 0 {
        return Ok(());
    }

    let mut descriptor = rva as usize;
    loop {
        let original = u32_at(image, descriptor).ok_or("truncated import descriptor")? as usize;
        let name_rva = u32_at(image, descriptor + 12).ok_or("truncated import descriptor")? as usize;
        let first_thunk = u32_at(image, descriptor + 16).ok_or("truncated import descriptor")? as usize;
        if original == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let library = cstr_in(image, name_rva);
        let module = unsafe {
            let handle = LoadLibraryW(wide(&library).as_ptr());
            if handle.is_null() {
                GetModuleHandleW(wide(&library).as_ptr())
            } else {
                handle
            }
        };
        if module.is_null() {
            return Err(format!("cannot load {library} locally"));
        }

        let mut thunk = if original != 0 { original } else { first_thunk };
        let mut slot = first_thunk;
        loop {
            let value = u64_at(image, thunk).ok_or("truncated thunk")?;
            if value == 0 {
                break;
            }
            let address = if value & (1 << 63) != 0 {
                unsafe { GetProcAddress(module, (value & 0xFFFF) as usize as *const u8) }
            } else {
                let name = cstr_in(image, (value as usize) + 2);
                unsafe { GetProcAddress(module, ansi_name(&name).as_ptr()) }
            };
            if address.is_null() {
                return Err(format!("missing import in {library}"));
            }
            put_u64(image, slot, address as u64);
            thunk += 8;
            slot += 8;
        }

        descriptor += 20;
    }

    Ok(())
}

fn ansi_name(name: &str) -> Vec<u8> {
    let mut out = name.as_bytes().to_vec();
    out.push(0);
    out
}
