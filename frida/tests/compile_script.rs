//! Integration tests for `Session::compile_script` and
//! `Session::create_script_from_bytes`.
//!
//! These exercise the real frida-core runtime (the test process attaches
//! to itself, pid=0). CI runs this via `cargo test --features=auto-download`,
//! which fetches the matching frida-core devkit.

use frida::{DeviceManager, Error, Frida, Message, ScriptHandler, ScriptOption, ScriptRuntime};
use std::sync::{LazyLock, Mutex, MutexGuard};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

// Frida-core is a process-wide singleton: concurrent self-attach from
// multiple cargo-test threads corrupts its agent state (observed as
// STATUS_STACK_BUFFER_OVERRUN on Windows). Every #[test] in this file
// must hold this lock for the full attach -> detach span.
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

struct NoopHandler;

impl ScriptHandler for NoopHandler {
    fn on_message(&mut self, _message: Message, _data: Option<Vec<u8>>) {}
}

fn qjs_options(name: &str) -> ScriptOption {
    ScriptOption::new()
        .set_name(name)
        .set_runtime(ScriptRuntime::QJS)
}

#[test]
fn compile_script_produces_loadable_bytecode() {
    let _serial = serial_guard();
    let device_manager = DeviceManager::obtain(&FRIDA);
    let device = device_manager
        .get_local_device()
        .expect("local device should be available");
    let session = device
        .attach(0)
        .expect("attach to self (pid=0) should succeed");

    let source = r#"console.log("hello from precompiled bytecode");"#;

    let mut compile_opts = qjs_options("roundtrip");
    let bytecode = session
        .compile_script(source, &mut compile_opts)
        .expect("compile_script should succeed for valid JS");

    assert!(
        !bytecode.is_empty(),
        "compile_script should return a non-empty bytecode blob"
    );

    let mut load_opts = qjs_options("roundtrip");
    let mut script = session
        .create_script_from_bytes(&bytecode, &mut load_opts)
        .expect("create_script_from_bytes should accept the just-compiled bytecode");

    script
        .handle_message(NoopHandler)
        .expect("handle_message should succeed");
    script
        .load()
        .expect("loading bytecode script should succeed");
    script.unload().expect("unloading should succeed");

    session.detach().expect("detach should succeed");
}

#[test]
fn compile_script_rejects_source_with_interior_nul() {
    let _serial = serial_guard();
    let device_manager = DeviceManager::obtain(&FRIDA);
    let device = device_manager
        .get_local_device()
        .expect("local device should be available");
    let session = device
        .attach(0)
        .expect("attach to self (pid=0) should succeed");

    let source_with_nul = "console.log(\"a\0b\");";

    let mut opts = qjs_options("nul-check");
    let err = session
        .compile_script(source_with_nul, &mut opts)
        .expect_err("source containing an interior NUL must not reach the C side");

    assert!(
        matches!(err, Error::CStringFailed),
        "expected Error::CStringFailed, got {:?}",
        err
    );

    session.detach().expect("detach should succeed");
}

#[test]
fn create_script_from_bytes_accepts_default_options() {
    // Regression: the new method must work with bare `ScriptOption::default()`
    // (no name, no explicit runtime), just like `create_script` does today.
    let _serial = serial_guard();
    let device_manager = DeviceManager::obtain(&FRIDA);
    let device = device_manager
        .get_local_device()
        .expect("local device should be available");
    let session = device
        .attach(0)
        .expect("attach to self (pid=0) should succeed");

    let source = r#"console.log("default-opts");"#;
    let mut compile_opts = ScriptOption::default();
    let bytecode = session
        .compile_script(source, &mut compile_opts)
        .expect("compile_script should succeed with default options");

    let mut load_opts = ScriptOption::default();
    let mut script = session
        .create_script_from_bytes(&bytecode, &mut load_opts)
        .expect("create_script_from_bytes should succeed with default options");

    script
        .handle_message(NoopHandler)
        .expect("handle_message should succeed");
    script.load().expect("load should succeed");
    script.unload().expect("unload should succeed");

    session.detach().expect("detach should succeed");
}
