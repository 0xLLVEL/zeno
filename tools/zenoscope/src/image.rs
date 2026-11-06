//! A PE image, whether it comes from a file on disk or from a live process.
//!
//! Everything above this layer works in RVAs, so the same scan code serves both
//! sources. That matters here because the shipped client is packed: on disk
//! `.text` is encrypted, and only the live mapping holds real instructions.

pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_pointer: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn span(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.virtual_size
        }
    }

    pub fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.virtual_address && rva - self.virtual_address < self.span()
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    pub fn has_execute_flag(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
}

pub trait Image {
    fn image_base(&self) -> u64;
    fn size_of_image(&self) -> u32;
    fn base_of_code(&self) -> u32;
    fn sections(&self) -> &[Section];

    /// Bytes at `rva`, or None when the range is not readable.
    fn read_rva(&self, rva: u32, len: usize) -> Option<Vec<u8>>;

    /// Best-effort contents of a section. Short reads are allowed: a live
    /// process can have pages the kernel refuses to hand over.
    fn section_data(&self, section: &Section) -> &[u8];

    fn section_for_rva(&self, rva: u32) -> Option<&Section> {
        self.sections().iter().find(|s| s.contains_rva(rva))
    }

    fn va(&self, rva: u32) -> u64 {
        self.image_base().wrapping_add(rva as u64)
    }

    fn rva_of_va(&self, va: u64) -> Option<u32> {
        u32::try_from(va.checked_sub(self.image_base())?).ok()
    }

    /// The shipped client does not set `IMAGE_SCN_MEM_EXECUTE` on `.text`
    /// (its characteristics read `0x20`, code only). Trust `BaseOfCode` and
    /// fall back to the flag for ordinary binaries.
    fn is_code_section(&self, section: &Section) -> bool {
        section.has_execute_flag() || section.contains_rva(self.base_of_code())
    }

    fn is_executable_rva(&self, rva: u32) -> bool {
        self.section_for_rva(rva)
            .map(|s| self.is_code_section(s))
            .unwrap_or(false)
    }

    fn read_u64(&self, rva: u32) -> Option<u64> {
        let b = self.read_rva(rva, 8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn code_bytes(&self) -> usize {
        self.sections()
            .iter()
            .filter(|s| self.is_code_section(s))
            .map(|s| self.section_data(s).len())
            .sum()
    }
}

// ---------------------------------------------------------------- file image

fn rd16(d: &[u8], off: usize) -> Result<u16, String> {
    let s = d
        .get(off..off + 2)
        .ok_or_else(|| format!("truncated read of u16 at 0x{off:X}"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn rd32(d: &[u8], off: usize) -> Result<u32, String> {
    let s = d
        .get(off..off + 4)
        .ok_or_else(|| format!("truncated read of u32 at 0x{off:X}"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd64(d: &[u8], off: usize) -> Result<u64, String> {
    let s = d
        .get(off..off + 8)
        .ok_or_else(|| format!("truncated read of u64 at 0x{off:X}"))?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

pub struct PeImage {
    pub data: Vec<u8>,
    pub image_base: u64,
    pub size_of_image: u32,
    pub base_of_code: u32,
    pub sections: Vec<Section>,
}

impl PeImage {
    pub fn parse(data: Vec<u8>) -> Result<PeImage, String> {
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return Err("not a PE file (missing MZ)".into());
        }

        let pe_off = rd32(&data, 0x3C)? as usize;
        if data.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
            return Err("not a PE file (missing PE signature)".into());
        }

        let coff = pe_off + 4;
        let section_count = rd16(&data, coff + 2)? as usize;
        let optional_size = rd16(&data, coff + 16)? as usize;
        let optional = coff + 20;

        let is_64 = match rd16(&data, optional)? {
            0x20B => true,
            0x10B => false,
            other => return Err(format!("unknown optional header magic 0x{other:X}")),
        };

        let base_of_code = rd32(&data, optional + 20)?;
        let image_base = if is_64 {
            rd64(&data, optional + 24)?
        } else {
            rd32(&data, optional + 28)? as u64
        };
        let size_of_image = rd32(&data, optional + 56)?;

        let table = optional + optional_size;
        let mut sections = Vec::with_capacity(section_count);
        for i in 0..section_count {
            let base = table + i * 40;
            let name_bytes = data
                .get(base..base + 8)
                .ok_or_else(|| format!("truncated section header {i}"))?;
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8_lossy(&name_bytes[..name_end]).into_owned(),
                virtual_size: rd32(&data, base + 8)?,
                virtual_address: rd32(&data, base + 12)?,
                raw_size: rd32(&data, base + 16)?,
                raw_pointer: rd32(&data, base + 20)?,
                characteristics: rd32(&data, base + 36)?,
            });
        }

        Ok(PeImage {
            data,
            image_base,
            size_of_image,
            base_of_code,
            sections,
        })
    }

}

impl Image for PeImage {
    fn image_base(&self) -> u64 {
        self.image_base
    }

    fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    fn base_of_code(&self) -> u32 {
        self.base_of_code
    }

    fn sections(&self) -> &[Section] {
        &self.sections
    }

    fn read_rva(&self, rva: u32, len: usize) -> Option<Vec<u8>> {
        let section = self.section_for_rva(rva)?;
        let delta = rva - section.virtual_address;
        if delta as u64 + len as u64 > section.raw_size as u64 {
            return None;
        }
        let off = section.raw_pointer as usize + delta as usize;
        let end = off.checked_add(len)?;
        (end <= self.data.len()).then(|| self.data[off..end].to_vec())
    }

    fn section_data(&self, section: &Section) -> &[u8] {
        let start = section.raw_pointer as usize;
        if start >= self.data.len() {
            return &[];
        }
        let available = (section.span() as usize).min(section.raw_size as usize);
        let end = (start + available).min(self.data.len());
        &self.data[start..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One PE32+ image with a single .text section, built by hand so the test
    /// does not depend on anything on disk.
    fn synthetic() -> Vec<u8> {
        let mut data = vec![0u8; 0x800];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        let pe = 0x80;
        data[pe..pe + 4].copy_from_slice(b"PE\0\0");
        let coff = pe + 4;
        data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        data[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());

        let opt = coff + 20;
        data[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        data[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        data[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        data[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        data[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());

        let table = opt + 0xF0;
        data[table..table + 5].copy_from_slice(b".text");
        data[table + 8..table + 12].copy_from_slice(&0x100u32.to_le_bytes());
        data[table + 12..table + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[table + 16..table + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[table + 20..table + 24].copy_from_slice(&0x400u32.to_le_bytes());
        data[table + 36..table + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        for byte in &mut data[0x400..0x600] {
            *byte = 0xAA;
        }

        data
    }

    #[test]
    fn parses_header_and_sections() {
        let image = PeImage::parse(synthetic()).expect("parse");
        assert_eq!(image.image_base(), 0x1_4000_0000);
        assert_eq!(image.size_of_image(), 0x2000);
        assert_eq!(image.sections().len(), 1);
        assert_eq!(image.sections()[0].name, ".text");
        assert!(image.is_code_section(&image.sections()[0]));
    }

    #[test]
    fn maps_rva_through_the_section() {
        let image = PeImage::parse(synthetic()).expect("parse");
        assert_eq!(image.read_rva(0x1000, 4).unwrap(), vec![0xAA; 4]);
        assert_eq!(image.va(0x1000), 0x1_4000_1000);
        assert_eq!(image.rva_of_va(0x1_4000_1000), Some(0x1000));
        // inside the virtual span but past the raw data
        assert!(image.read_rva(0x1150, 4).is_none());
        // outside every section
        assert!(image.section_for_rva(0x9000).is_none());
    }

    #[test]
    fn section_data_is_capped_to_the_virtual_span() {
        let image = PeImage::parse(synthetic()).expect("parse");
        let section = &image.sections()[0];
        assert_eq!(image.section_data(section).len(), 0x100);
        assert_eq!(image.code_bytes(), 0x100);
    }

    #[test]
    fn rejects_non_pe_input() {
        assert!(PeImage::parse(vec![0u8; 0x100]).is_err());
        assert!(PeImage::parse(b"MZ".to_vec()).is_err());
    }
}
