//! Live-process reader. Same PE layout, but the bytes come from the mapped
//! image — which is the only place the shipped client's `.text` exists in the
//! clear.

use std::ffi::c_void;

use crate::image::{Image, PeImage, Section};

type Handle = *mut c_void;

const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;

const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

#[repr(C)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

#[repr(C)]
struct ModuleEntry32W {
    dw_size: u32,
    th32_module_id: u32,
    th32_process_id: u32,
    glblcnt_usage: u32,
    proccnt_usage: u32,
    mod_base_addr: *mut u8,
    mod_base_size: u32,
    h_module: *mut c_void,
    sz_module: [u16; 256],
    sz_exe_path: [u16; 260],
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
    fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn Module32FirstW(snapshot: Handle, entry: *mut ModuleEntry32W) -> i32;
    fn Module32NextW(snapshot: Handle, entry: *mut ModuleEntry32W) -> i32;
    fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
    fn ReadProcessMemory(
        process: Handle,
        address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;
}

fn wide_to_string(wide: &[u16]) -> String {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

pub struct Process {
    handle: Handle,
    pub pid: u32,
}

impl Process {
    /// Newest process whose executable name matches, case-insensitively.
    pub fn open_by_name(exe_name: &str) -> Result<Process, String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err("CreateToolhelp32Snapshot failed".into());
        }

        let mut entry: ProcessEntry32W = unsafe { std::mem::zeroed() };
        entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;

        let mut found = None;
        let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while ok {
            let name = wide_to_string(&entry.sz_exe_file);
            if name.eq_ignore_ascii_case(exe_name) {
                found = Some(entry.th32_process_id);
                break;
            }
            ok = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        unsafe { CloseHandle(snapshot) };

        let pid = found.ok_or_else(|| format!("{exe_name} is not running"))?;
        Process::open_pid(pid)
    }

    pub fn open_pid(pid: u32) -> Result<Process, String> {
        let handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "OpenProcess({pid}) failed — the process is protected or runs as another user"
            ));
        }

        Ok(Process { handle, pid })
    }

    pub fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        let mut buffer = vec![0u8; len];
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                len,
                &mut read,
            )
        };
        if ok == 0 {
            return None;
        }
        buffer.truncate(read);
        Some(buffer)
    }

    /// Base address and size of a loaded module.
    pub fn module(&self, module_name: &str) -> Option<(u64, u32, String)> {
        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid) };
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: ModuleEntry32W = unsafe { std::mem::zeroed() };
        entry.dw_size = std::mem::size_of::<ModuleEntry32W>() as u32;

        let mut result = None;
        let mut ok = unsafe { Module32FirstW(snapshot, &mut entry) } != 0;
        while ok {
            if wide_to_string(&entry.sz_module).eq_ignore_ascii_case(module_name) {
                result = Some((
                    entry.mod_base_addr as u64,
                    entry.mod_base_size,
                    wide_to_string(&entry.sz_exe_path),
                ));
                break;
            }
            ok = unsafe { Module32NextW(snapshot, &mut entry) } != 0;
        }
        unsafe { CloseHandle(snapshot) };
        result
    }

    /// Section bytes read out of the live mapping.
    pub fn image(&self, module_name: &str) -> Result<MemImage, String> {
        let (base, size, path) = self
            .module(module_name)
            .ok_or_else(|| format!("module {module_name} not found in pid {}", self.pid))?;

        let header = self
            .read(base, 0x1000)
            .ok_or("cannot read the remote PE headers")?;
        let parsed = PeImage::parse(header)?;

        let mut blocks = Vec::with_capacity(parsed.sections.len());
        let mut unreadable = 0usize;

        for section in &parsed.sections {
            let span = (section.span() as usize).min(section.raw_size.max(section.span()) as usize);
            let start = base + section.virtual_address as u64;
            let mut block = Vec::with_capacity(span);
            let mut offset = 0usize;
            while offset < span {
                let chunk = (span - offset).min(0x10_0000);
                match self.read(start + offset as u64, chunk) {
                    Some(bytes) if bytes.len() == chunk => block.extend_from_slice(&bytes),
                    _ => {
                        block.resize(block.len() + chunk, 0);
                        unreadable += chunk;
                    }
                }
                offset += chunk;
            }
            blocks.push(block);
        }

        Ok(MemImage {
            module_path: path,
            base,
            size_of_image: size.max(parsed.size_of_image),
            base_of_code: parsed.base_of_code,
            sections: parsed.sections,
            blocks,
            unreadable,
        })
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

/// Which access masks the target will actually hand out. A protected process
/// answers this honestly where a failing read does not explain itself.
pub fn probe_access(pid: u32) -> Vec<(u32, &'static str, bool, u32)> {
    const MASKS: [(u32, &str); 10] = [
        (0x0001, "PROCESS_TERMINATE"),
        (0x0008, "PROCESS_VM_OPERATION"),
        (0x0010, "PROCESS_VM_READ"),
        (0x0020, "PROCESS_VM_WRITE"),
        (0x0400, "PROCESS_QUERY_INFORMATION"),
        (0x1000, "PROCESS_QUERY_LIMITED_INFORMATION"),
        (0x100000, "SYNCHRONIZE"),
        (0x0410, "QUERY_INFORMATION | VM_READ"),
        (0x1010, "QUERY_LIMITED | VM_READ"),
        (0x1F0FFF, "PROCESS_ALL_ACCESS"),
    ];

    let mut results = Vec::new();
    for (mask, name) in MASKS {
        let handle = unsafe { OpenProcess(mask, 0, pid) };
        let opened = !handle.is_null() && handle != INVALID_HANDLE_VALUE;
        let error = if opened {
            0
        } else {
            unsafe { GetLastError() }
        };
        if opened {
            unsafe { CloseHandle(handle) };
        }
        results.push((mask, name, opened, error));
    }
    results
}

pub fn probe_modules(pid: u32) -> Result<(usize, Vec<String>), u32> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(unsafe { GetLastError() });
    }

    let mut entry: ModuleEntry32W = unsafe { std::mem::zeroed() };
    entry.dw_size = std::mem::size_of::<ModuleEntry32W>() as u32;

    let mut names = Vec::new();
    let mut count = 0usize;
    let mut ok = unsafe { Module32FirstW(snapshot, &mut entry) } != 0;
    while ok {
        count += 1;
        if names.len() < 6 {
            names.push(wide_to_string(&entry.sz_module));
        }
        ok = unsafe { Module32NextW(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };

    Ok((count, names))
}

pub struct MemImage {
    pub module_path: String,
    pub base: u64,
    pub size_of_image: u32,
    pub base_of_code: u32,
    pub sections: Vec<Section>,
    blocks: Vec<Vec<u8>>,
    pub unreadable: usize,
}

impl MemImage {
    pub fn path(&self) -> &str {
        &self.module_path
    }

    fn block_index(&self, section: &Section) -> Option<usize> {
        self.sections
            .iter()
            .position(|s| s.virtual_address == section.virtual_address)
    }
}

impl Image for MemImage {
    fn image_base(&self) -> u64 {
        self.base
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
        let index = self.block_index(section)?;
        let block = &self.blocks[index];
        let delta = (rva - section.virtual_address) as usize;
        let end = delta.checked_add(len)?;
        (end <= block.len()).then(|| block[delta..end].to_vec())
    }

    fn section_data(&self, section: &Section) -> &[u8] {
        match self.block_index(section) {
            Some(index) => &self.blocks[index],
            None => &[],
        }
    }
}
