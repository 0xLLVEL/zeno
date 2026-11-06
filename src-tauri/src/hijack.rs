#![cfg(windows)]

//! Thread hijack injection.
//!
//! The payload is mapped as a file-backed image section, then an existing
//! thread is suspended and its `Rip` redirected into a stub. The stub calls
//! `DllMain(base, DLL_PROCESS_ATTACH, NULL)` on a private scratch stack, then
//! restores every volatile register, the flags and the original `Rip`, so the
//! interrupted thread resumes exactly where it stopped.
//!
//! Nothing is created and nothing is queued: no thread-creation notification,
//! no APC. `NtQueueApcThread` (the `apc` method) only fires when the target
//! thread enters an alertable wait, which Roblox threads rarely do; hijack has
//! no such precondition.
//!
//! Not covered: handle filtering and `.text` integrity. The stub is written
//! into image slack via `crate::stub`, so it does not add an unbacked RX page.

use std::path::Path;

use windows::Win32::Foundation::CloseHandle;

use crate::nt;

const STUB_SIZE: usize = 0x200;
const SCRATCH_SIZE: usize = 0x20000;

/// Stub layout, patched with real addresses at build time.
///
/// ```text
/// pushfq / push rax / rcx / rdx / r8..r11
/// mov  [rip+RSP_SLOT], rsp
/// mov  rsp, [rip+STACK_SLOT]
/// and  rsp, -16
/// sub  rsp, 0x20
/// mov  rcx, base / mov rdx, 1 / xor r8d, r8d / mov rax, entry / call rax
/// mov  rsp, [rip+RSP_SLOT]
/// pop  r11..r8 / rdx / rcx / rax / popfq
/// jmp  qword ptr [rip+0]
/// ```
fn build_stub(base: usize, entry: usize, original_rip: u64, scratch_top: usize) -> Vec<u8> {
    let mut code: Vec<u8> = Vec::with_capacity(128);
    let mut fixups: Vec<(usize, usize)> = Vec::new();

    // pushfq, rax, rcx, rdx, r8, r9, r10, r11
    code.extend_from_slice(&[0x9C, 0x50, 0x51, 0x52]);
    code.extend_from_slice(&[0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53]);

    // mov [rip+disp], rsp
    code.extend_from_slice(&[0x48, 0x89, 0x25, 0, 0, 0, 0]);
    fixups.push((code.len() - 4, code.len()));

    // mov rsp, [rip+disp]  -> scratch stack
    code.extend_from_slice(&[0x48, 0x8B, 0x25, 0, 0, 0, 0]);
    fixups.push((code.len() - 4, code.len()));

    code.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]); // and rsp, -16
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20 (shadow space)

    code.extend_from_slice(&[0x48, 0xB9]); // mov rcx, imm64
    code.extend_from_slice(&(base as u64).to_le_bytes());
    code.extend_from_slice(&[0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00]); // mov rdx, 1
    code.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d
    code.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    code.extend_from_slice(&(entry as u64).to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0]); // call rax

    // mov rsp, [rip+disp]  -> saved rsp
    code.extend_from_slice(&[0x48, 0x8B, 0x25, 0, 0, 0, 0]);
    fixups.push((code.len() - 4, code.len()));

    code.extend_from_slice(&[0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58]);
    code.extend_from_slice(&[0x5A, 0x59, 0x58, 0x9D]); // pop rdx, rcx, rax, popfq
    code.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // jmp [rip+0]

    let rip_slot = code.len();
    let rsp_slot = rip_slot + 8;
    let stack_slot = rip_slot + 16;

    let slot_of = [rsp_slot, stack_slot, rsp_slot];
    for (index, (disp_pos, next_pos)) in fixups.iter().enumerate() {
        let delta = slot_of[index] as i64 - *next_pos as i64;
        code[*disp_pos..*disp_pos + 4].copy_from_slice(&(delta as i32).to_le_bytes());
    }

    code.extend_from_slice(&original_rip.to_le_bytes());
    code.extend_from_slice(&0u64.to_le_bytes()); // written by the stub before the call
    code.extend_from_slice(&(scratch_top as u64).to_le_bytes());
    code
}

pub fn inject(pid: u32, dll: &Path) -> Result<String, String> {
    if !nt::available() {
        return Err("thread hijack needs the direct-syscall layer; SSN table unresolved".into());
    }
    if !crate::process::probe_write(pid) {
        return Err("handle rejected — kernel filter (Hyperion) is active".into());
    }

    let entry_rva = crate::section::entry_rva(dll)?;
    let file = crate::section::open_payload(dll)?;

    let result = (|| -> Result<String, String> {
        let section = nt::create_section(file.0 as usize, nt::PAGE_RO, nt::SEC_IMAGE)?;
        let process = nt::open_process(pid, nt::PROCESS_ALL)?;

        let outcome = (|| -> Result<String, String> {
            let base = nt::map_view(process, section, nt::PAGE_RO)?;
            let entry = base + entry_rva as usize;

            let candidates = crate::apc::threads_of(pid);
            if candidates.is_empty() {
                return Err("no thread to hijack".into());
            }

            let mut last_error = String::from("no thread accepted the hijack");
            for tid in candidates.iter().take(32) {
                match hijack_one(process, *tid, base, entry, dll) {
                    Ok(()) => return Ok(format!("hijacked thread {tid}")),
                    Err(e) => last_error = format!("thread {tid}: {e}"),
                }
            }
            Err(last_error)
        })();

        unsafe {
            let _ = CloseHandle(windows::Win32::Foundation::HANDLE(section as *mut _));
            let _ = CloseHandle(windows::Win32::Foundation::HANDLE(process as *mut _));
        }
        outcome
    })();

    unsafe {
        let _ = CloseHandle(file);
    }

    result
}

fn hijack_one(process: usize, tid: u32, base: usize, entry: usize, dll: &Path) -> Result<(), String> {
    let access = nt::THREAD_SUSPEND_RESUME
        | nt::THREAD_GET_CONTEXT
        | nt::THREAD_SET_CONTEXT
        | nt::THREAD_QUERY_LIMITED;
    let thread = nt::open_thread(tid, access)?;

    let result = (|| -> Result<(), String> {
        let previous = nt::suspend_thread(thread)?;

        let step = (|| -> Result<(), String> {
            let mut context = [0u8; nt::CONTEXT_SIZE];
            nt::get_thread_context(thread, &mut context)?;

            let original_rip = nt::context_rip(&context);
            if original_rip < 0x10_000 {
                return Err(format!("implausible Rip {original_rip:#x}"));
            }

            let scratch = nt::allocate(process, SCRATCH_SIZE)?;

            let stub = build_stub(base, entry, original_rip, scratch + SCRATCH_SIZE);
            let stub_mem = crate::stub::place_or_allocate(process, base, dll, &stub, STUB_SIZE)?;

            nt::set_context_rip(&mut context, stub_mem as u64);
            nt::set_thread_context(thread, &context)?;
            Ok(())
        })();

        // Always bring the thread back up: a thread left suspended is a hang.
        let resumed = nt::resume_thread(thread);
        match (step, resumed) {
            (Ok(()), Ok(_)) => Ok(()),
            (Err(e), _) => Err(e),
            (Ok(()), Err(e)) => Err(e),
        }
        .map(|_| {
            let _ = previous;
        })
    })();

    unsafe {
        let _ = CloseHandle(windows::Win32::Foundation::HANDLE(thread as *mut _));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::build_stub;

    fn read_u64(code: &[u8], at: usize) -> u64 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&code[at..at + 8]);
        u64::from_le_bytes(raw)
    }

    fn read_i32(code: &[u8], at: usize) -> i32 {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&code[at..at + 4]);
        i32::from_le_bytes(raw)
    }

    #[test]
    fn stub_layout_is_exact() {
        let stub = build_stub(0x7FF6_0000_0000, 0x7FF6_0000_1234, 0x7FFB_1111_2222, 0x5000_0000);
        assert_eq!(stub.len(), 115);
        assert_eq!(read_u64(&stub, 91), 0x7FFB_1111_2222);
        assert_eq!(read_u64(&stub, 107), 0x5000_0000);

        // mov [rip+d], rsp at 12, ends 19, must land on the rsp slot (99)
        assert_eq!(19 + read_i32(&stub, 15) as usize, 99);
        // mov rsp, [rip+d] at 19, ends 26, must land on the stack slot (107)
        assert_eq!(26 + read_i32(&stub, 22) as usize, 107);
        // mov rsp, [rip+d] at 66, ends 73, must land on the rsp slot (99)
        assert_eq!(73 + read_i32(&stub, 69) as usize, 99);

        assert_eq!(&stub[85..91], &[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
    }
}
