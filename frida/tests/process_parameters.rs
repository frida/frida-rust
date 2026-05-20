//! Integration tests for `Device::enumerate_processes_with_options` and
//! `Process::get_parameters`.
//!
//! Tests run against the real frida-core (auto-downloaded via the
//! `auto-download` feature) and inspect the running test process itself —
//! its pid is guaranteed to be present in the enumeration.
//!
//! No `device.attach(0)` happens here: enumerate_processes only reads
//! /proc-style host metadata, so the docker test job does not need
//! `--cap-add=SYS_PTRACE`.

use frida::{DeviceManager, Frida, Scope, Variant};
use std::sync::{LazyLock, Mutex, MutexGuard};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

// Frida-core is a process-wide singleton; serialize the tests so two
// threads don't race the device-manager / process-enumeration state.
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

#[test]
fn get_parameters_returns_data_under_full_scope() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let device = dm
        .get_local_device()
        .expect("local device should be available");

    let processes = device.enumerate_processes_with_options(Scope::Full);
    assert!(
        !processes.is_empty(),
        "Scope::Full enumeration returned no processes — the test runner itself should be present"
    );

    let own_pid = std::process::id();
    let me = processes
        .iter()
        .find(|p| p.get_pid() == own_pid)
        .expect("test process pid should appear in the Scope::Full enumeration");

    let params = me.get_parameters();
    assert!(
        !params.is_empty(),
        "Scope::Full Process::get_parameters() must populate the parameter table"
    );

    // Don't hard-code key names: those differ by host OS (e.g. Windows
    // emits `icons`, Linux emits `user` as a Map of uid/gid/name).
    // Assert structural shape instead: at least one Variant decoded
    // into String and at least one decoded into Int64. That covers the
    // common ppid (Int64 widened from uint32) + path (String) shape and
    // catches the original `todo!()` panic regression on unknown sigs.
    let has_string = params.values().any(|v| matches!(v, Variant::String(_)));
    let has_int = params.values().any(|v| matches!(v, Variant::Int64(_)));
    assert!(
        has_string,
        "expected at least one String-typed parameter, got: {:?}",
        params.keys().collect::<Vec<_>>()
    );
    assert!(
        has_int,
        "expected at least one Int64-typed parameter, got: {:?}",
        params.keys().collect::<Vec<_>>()
    );
}

#[test]
fn variant_iteration_never_panics_on_unknown_signatures() {
    // Core regression target of this PR: `Variant::from_ptr` previously
    // `todo!()`d on any GVariant signature the wrapper hadn't enumerated,
    // which panicked the whole process the first time frida-core handed
    // back something unexpected — Windows packs process icons as "ay"
    // byte arrays, so `get_parameters()` died on the first matching pid.
    //
    // The fix: route unknown sigs into `Variant::Unsupported(sig)`. This
    // test enumerates everything frida emits and exercises each accessor;
    // a future regression that reintroduces a panic on unknown sigs will
    // crash this test instead of a production caller.
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let device = dm
        .get_local_device()
        .expect("local device should be available");

    let processes = device.enumerate_processes_with_options(Scope::Full);
    for p in &processes {
        for (_key, v) in p.get_parameters() {
            // Run every accessor and the Debug impl — any panic here
            // breaks the contract that Variant must survive arbitrary
            // GVariant input from frida-core.
            let _ = v.get_string();
            let _ = v.get_int();
            let _ = v.get_bool();
            let _ = v.get_map();
            let _ = v.get_maplist();
            let _ = format!("{v:?}");
        }
    }
}

#[test]
fn get_parameters_is_empty_under_minimal_scope() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let device = dm
        .get_local_device()
        .expect("local device should be available");

    // Minimal scope must NOT populate the parameter table — that's the
    // whole reason Scope::Full exists. The plain enumerate_processes()
    // alias also uses Minimal; regressions here would silently bloat
    // every caller's enumeration.
    let processes = device.enumerate_processes_with_options(Scope::Minimal);
    let own_pid = std::process::id();
    let me = processes
        .iter()
        .find(|p| p.get_pid() == own_pid)
        .expect("test process pid should appear in the Scope::Minimal enumeration");

    let params = me.get_parameters();
    assert!(
        params.is_empty(),
        "Scope::Minimal Process::get_parameters() must return an empty map, got keys {:?}",
        params.keys().collect::<Vec<_>>()
    );
}
