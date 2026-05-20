//! Demonstrates `Device::enumerate_processes_with_options(Scope::Full)` and
//! `Process::get_parameters`.
//!
//! Given a process name, prints every running match with its pid + ppid +
//! path, and marks the "main" process (the one whose parent PID is *not*
//! another same-named process) so you can pick it out of a Chromium-style
//! multi-process app (Chrome, Electron, Discord, VSCode, Weixin, ...).
//!
//! Usage:
//! ```text
//! cargo run -p get_process_parameters -- chrome.exe
//! cargo run -p get_process_parameters -- Code.exe
//! cargo run -p get_process_parameters -- Weixin.exe
//! ```

use frida::{Frida, Scope};
use std::collections::HashSet;
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

fn main() {
    let target_name = match std::env::args().nth(1) {
        Some(n) => n,
        None => {
            eprintln!("usage: get_process_parameters <process-name>");
            eprintln!();
            eprintln!("Prints pid + ppid + path for each running process matching");
            eprintln!("<process-name>, marking the 'main' entry (the one whose");
            eprintln!("parent PID is not another same-named process — i.e. the");
            eprintln!("Chromium-model main process, not one of its helpers).");
            std::process::exit(1);
        }
    };

    let dm = frida::DeviceManager::obtain(&FRIDA);
    let device = dm.get_local_device().unwrap();

    // Scope::Full asks frida-core to populate each Process's parameter
    // table (ppid / path / user / started). Plain enumerate_processes()
    // uses Scope::Minimal and returns an empty parameter map.
    let processes = device.enumerate_processes_with_options(Scope::Full);

    let matches: Vec<_> = processes
        .iter()
        .filter(|p| p.get_name() == target_name)
        .collect();

    if matches.is_empty() {
        println!("no processes named {target_name:?}");
        return;
    }

    let same_name_pids: HashSet<u32> = matches.iter().map(|p| p.get_pid()).collect();

    for p in &matches {
        let params = p.get_parameters();
        let pid = p.get_pid();
        let ppid = params.get("ppid").and_then(|v| v.get_int()).unwrap_or(0) as u32;
        let path = params
            .get("path")
            .and_then(|v| v.get_string())
            .unwrap_or("?");
        let marker = if same_name_pids.contains(&ppid) {
            "  helper"
        } else {
            "★ main "
        };
        println!("{marker}  pid={pid:>6}  ppid={ppid:>6}  {path}");
    }
}
