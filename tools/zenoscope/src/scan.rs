//! Offset discovery from a PE image — file-backed or live.
//!
//! Two independent techniques, both derived from the shape of the shipped
//! client rather than from hardcoded addresses:
//!
//! * string xref -> `mov r64, [rip+disp]` : resolves a module-level *pointer
//!   slot* (a global that holds a heap pointer at runtime). The slot's RVA is
//!   stable for a given client build.
//! * RTTI : the MSVC type descriptor for a mangled class name gives us the
//!   complete object locator, which gives us the vtable. That verifies a
//!   class's identity instead of guessing it.

use crate::image::Image;

/// Byte patterns a real MSVC x64 code section is full of. Used to tell a
/// decrypted image from a packed one.
pub const PROLOGUES: [&[u8]; 4] = [
    &[0x48, 0x89, 0x5C, 0x24],
    &[0x48, 0x83, 0xEC],
    &[0xCC, 0xCC, 0xCC, 0xCC],
    &[0x00, 0x00, 0x00, 0x00],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    Lea,
    Mov,
}

#[derive(Debug, Clone, Copy)]
pub struct RipRef {
    pub at_rva: u32,
    pub target_rva: u32,
    pub kind: RefKind,
}

#[derive(Debug, Clone)]
pub struct PointerSlot {
    pub global_rva: u32,
    pub via_lea_rva: u32,
    pub string_rva: u32,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub mangled: String,
    pub type_descriptor_rva: u32,
    pub locator_rvas: Vec<u32>,
    pub vtable_rvas: Vec<u32>,
}

pub fn find_string(image: &dyn Image, needle: &[u8]) -> Vec<u32> {
    let mut hits = Vec::new();
    if needle.is_empty() {
        return hits;
    }

    for section in image.sections() {
        let raw = image.section_data(section);
        if raw.len() < needle.len() {
            continue;
        }
        let mut i = 0usize;
        while i + needle.len() <= raw.len() {
            if &raw[i..i + needle.len()] == needle {
                hits.push(section.virtual_address + i as u32);
                i += needle.len();
            } else {
                i += 1;
            }
        }
    }

    hits
}

/// Byte-pattern counts inside code sections. A section that is mostly zeroes
/// or high-entropy bytes is not code we can disassemble, and every scan below
/// it would be meaningless.
pub fn count_patterns(image: &dyn Image, patterns: &[&[u8]]) -> Vec<usize> {
    let mut counts = vec![0usize; patterns.len()];

    for section in image.sections() {
        if !image.is_code_section(section) {
            continue;
        }
        let raw = image.section_data(section);
        for (index, needle) in patterns.iter().enumerate() {
            if needle.is_empty() || raw.len() < needle.len() {
                continue;
            }
            let mut i = 0usize;
            while i + needle.len() <= raw.len() {
                if &raw[i..i + needle.len()] == *needle {
                    counts[index] += 1;
                    i += needle.len();
                } else {
                    i += 1;
                }
            }
        }
    }

    counts
}

/// Every RIP-relative `lea` and `mov` in code sections.
///
/// Encoding matched: `REX.W 8B/8D modrm=mod00 rm=101 disp32` — seven bytes.
/// Scanning every byte means a few false positives land mid-instruction; every
/// caller validates the computed target, which is what filters them out.
pub fn scan_rip_refs(image: &dyn Image) -> Vec<RipRef> {
    let mut refs = Vec::new();

    for section in image.sections() {
        if !image.is_code_section(section) {
            continue;
        }
        let raw = image.section_data(section);
        if raw.len() < 7 {
            continue;
        }

        for i in 0..=raw.len() - 7 {
            let rex = raw[i];
            if rex & 0x48 != 0x48 {
                continue;
            }
            let kind = match raw[i + 1] {
                0x8D => RefKind::Lea,
                0x8B => RefKind::Mov,
                _ => continue,
            };
            if raw[i + 2] & 0xC7 != 0x05 {
                continue;
            }

            let disp = i32::from_le_bytes([raw[i + 3], raw[i + 4], raw[i + 5], raw[i + 6]]);
            let at_rva = section.virtual_address + i as u32;
            let target = (at_rva as i64) + 7 + disp as i64;
            let Ok(target_rva) = u32::try_from(target) else {
                continue;
            };
            if image.section_for_rva(target_rva).is_none() {
                continue;
            }

            refs.push(RipRef {
                at_rva,
                target_rva,
                kind,
            });
        }
    }

    refs
}

/// `TaskScheduler::Pointer` — the global that holds the scheduler at runtime.
///
/// The scheduler's constructor is the only code that references the string
/// "Default job arbiter must always be valid". That string's xref leads to a
/// `lea`, and the first rip-relative `mov` after it loads the pointer slot.
pub fn find_task_scheduler_pointer(
    image: &dyn Image,
    refs: &[RipRef],
    message: &str,
    window: u32,
) -> (Vec<u32>, Vec<PointerSlot>) {
    let strings = find_string(image, message.as_bytes());
    let mut slots = Vec::new();

    for &string_rva in &strings {
        for reference in refs {
            if reference.kind != RefKind::Lea || reference.target_rva != string_rva {
                continue;
            }
            let limit = reference.at_rva.saturating_add(window);
            let mut seen = Vec::new();
            for candidate in refs.iter().filter(|r| {
                r.kind == RefKind::Mov && r.at_rva > reference.at_rva && r.at_rva <= limit
            }) {
                if seen.contains(&candidate.target_rva) {
                    continue;
                }
                seen.push(candidate.target_rva);
                let Some(section) = image.section_for_rva(candidate.target_rva) else {
                    continue;
                };
                if !section.is_writable() {
                    continue;
                }
                slots.push(PointerSlot {
                    global_rva: candidate.target_rva,
                    via_lea_rva: reference.at_rva,
                    string_rva,
                });
            }
        }
    }

    (strings, slots)
}

/// MSVC `TypeDescriptor` is `{ vftable ptr, spare, char name[] }`, so the
/// mangled name sits 0x10 bytes past the descriptor itself.
pub fn resolve_rtti(image: &dyn Image, mangled: &str) -> Option<TypeInfo> {
    let name_rva = *find_string(image, mangled.as_bytes()).first()?;
    let type_descriptor_rva = name_rva.checked_sub(0x10)?;

    let locator_rvas = find_locators(image, type_descriptor_rva);
    let mut vtable_rvas = Vec::new();
    for &locator in &locator_rvas {
        vtable_rvas.extend(find_vtables(image, locator));
    }
    vtable_rvas.sort_unstable();
    vtable_rvas.dedup();

    Some(TypeInfo {
        mangled: mangled.to_string(),
        type_descriptor_rva,
        locator_rvas,
        vtable_rvas,
    })
}

/// `RTTICompleteObjectLocator`: signature 1, then the type descriptor RVA at
/// +0x0C. Both have to line up for the hit to count.
fn find_locators(image: &dyn Image, type_descriptor_rva: u32) -> Vec<u32> {
    let mut hits = Vec::new();

    for section in image.sections() {
        if image.is_code_section(section) {
            continue;
        }
        let raw = image.section_data(section);
        if raw.len() < 24 {
            continue;
        }
        let mut i = 0usize;
        while i + 24 <= raw.len() {
            if raw[i..i + 4] == [1, 0, 0, 0] {
                let td = u32::from_le_bytes([raw[i + 12], raw[i + 13], raw[i + 14], raw[i + 15]]);
                if td == type_descriptor_rva {
                    hits.push(section.virtual_address + i as u32);
                }
            }
            i += 4;
        }
    }

    hits
}

/// The vtable stores `&locator` in the slot immediately before its first
/// virtual function. So: find the qword equal to the locator's VA, and the
/// vtable begins eight bytes later. The entry there must point into code.
fn find_vtables(image: &dyn Image, locator_rva: u32) -> Vec<u32> {
    let wanted = image.va(locator_rva).to_le_bytes();
    let mut hits = Vec::new();

    for section in image.sections() {
        let raw = image.section_data(section);
        if raw.len() < 16 {
            continue;
        }
        let mut i = 0usize;
        while i + 8 <= raw.len() {
            if raw[i..i + 8] == wanted {
                let rva = section.virtual_address + i as u32;
                if let Some(start) = rva.checked_add(8) {
                    let first_entry_is_code = image
                        .read_u64(start)
                        .and_then(|va| image.rva_of_va(va))
                        .map(|rva| image.is_executable_rva(rva))
                        .unwrap_or(false);
                    if first_entry_is_code {
                        hits.push(start);
                    }
                }
            }
            i += 8;
        }
    }

    hits
}
