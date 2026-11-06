#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Mutex, OnceLock};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    ReadFile, WriteFile, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
};
use windows::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_TYPE_BYTE};

pub const IN_PIPE: &str = r"\\.\pipe\zeno_in";
pub const OUT_PIPE: &str = r"\\.\pipe\zeno_out";

static SCRIPT_TX: OnceLock<Mutex<Option<Sender<Vec<u8>>>>> = OnceLock::new();
static OUTPUT: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
static RUNNING: AtomicBool = AtomicBool::new(false);
static LINKED: AtomicBool = AtomicBool::new(false);

fn tx_slot() -> &'static Mutex<Option<Sender<Vec<u8>>>> {
    SCRIPT_TX.get_or_init(|| Mutex::new(None))
}

fn output_buf() -> &'static Mutex<Vec<String>> {
    OUTPUT.get_or_init(|| Mutex::new(Vec::new()))
}

struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}

pub fn is_linked() -> bool {
    LINKED.load(Ordering::Relaxed)
}

pub fn start() {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let (tx, rx) = channel::<Vec<u8>>();
    *tx_slot().lock().unwrap() = Some(tx);

    std::thread::spawn(move || writer_loop(rx));
    std::thread::spawn(reader_loop);
}

pub fn send_script(script: &str) -> Result<(), String> {
    let guard = tx_slot().lock().unwrap();
    let tx = guard.as_ref().ok_or_else(|| "bridge not started".to_string())?;
    let body = script.as_bytes();
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body);
    tx.send(frame).map_err(|_| "bridge writer offline".to_string())
}

pub fn drain() -> Vec<String> {
    let mut buf = output_buf().lock().unwrap();
    std::mem::take(&mut *buf)
}

fn create_pipe(name: &str, outbound: bool) -> Option<SendHandle> {
    let wide = crate::injector::wide(name);
    let mode = if outbound { PIPE_ACCESS_OUTBOUND } else { PIPE_ACCESS_INBOUND };
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide.as_ptr()),
            mode,
            PIPE_TYPE_BYTE,
            1,
            1 << 16,
            1 << 16,
            0,
            None,
        )
    };
    if handle.is_invalid() {
        None
    } else {
        Some(SendHandle(handle))
    }
}

fn writer_loop(rx: Receiver<Vec<u8>>) {
    loop {
        let Some(pipe) = create_pipe(IN_PIPE, true) else {
            std::thread::sleep(std::time::Duration::from_millis(500));
            continue;
        };
        let _ = unsafe { ConnectNamedPipe(pipe.0, None) };
        LINKED.store(true, Ordering::Relaxed);
        push_line("[zeno] bridge connected");

        loop {
            match rx.recv_timeout(std::time::Duration::from_millis(30)) {
                Ok(frame) => {
                    let res = unsafe { WriteFile(pipe.0, Some(&frame), None, None) };
                    if res.is_err() {
                        LINKED.store(false, Ordering::Relaxed);
                        push_line("[zeno] bridge lost — reconnecting");
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = unsafe { CloseHandle(pipe.0) };
                    return;
                }
            }
        }
        unsafe {
            let _ = CloseHandle(pipe.0);
        }
    }
}

fn reader_loop() {
    loop {
        let Some(pipe) = create_pipe(OUT_PIPE, false) else {
            std::thread::sleep(std::time::Duration::from_millis(500));
            continue;
        };
        if unsafe { ConnectNamedPipe(pipe.0, None) }.is_ok() {
            LINKED.store(true, Ordering::Relaxed);
        }

        let mut pending: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];

        loop {
            let mut read: u32 = 0;
            let res = unsafe { ReadFile(pipe.0, Some(&mut chunk), Some(&mut read), None) };
            if res.is_err() || read == 0 {
                break;
            }
            pending.extend_from_slice(&chunk[..read as usize]);
            while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                let line = String::from_utf8_lossy(&pending[..pos]).trim_end_matches('\r').to_string();
                pending.drain(..=pos);
                if !line.is_empty() {
                    push_line(&line);
                }
            }
            if pending.len() > 1 << 20 {
                pending.clear();
            }
        }

        unsafe {
            let _ = CloseHandle(pipe.0);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn push_line(line: &str) {
    let mut buf = output_buf().lock().unwrap();
    buf.push(line.to_string());
    if buf.len() > 4096 {
        let excess = buf.len() - 4096;
        buf.drain(..excess);
    }
}
