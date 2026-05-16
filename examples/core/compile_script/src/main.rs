use frida::{DeviceManager, Frida, Message, ScriptHandler, ScriptOption, ScriptRuntime};
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

const BYTECODE_PATH: &str = "compiled.bin";

const SCRIPT_SOURCE: &str = r#"
    console.log("Hello from precompiled bytecode! pid=" + Process.id);
"#;

fn main() {
    let device_manager = DeviceManager::obtain(&FRIDA);
    let device = device_manager
        .get_local_device()
        .expect("local device unavailable");

    println!("[*] Frida version: {}", Frida::version());
    println!("[*] Device: {}", device.get_name());

    let session = device.attach(0).expect("attach to self failed");
    println!("[*] Attached to self (pid=0)");

    // 1. Compile JS -> bytecode with the QJS runtime.
    //    Bytecode is runtime-specific: load with the same runtime.
    let mut compile_opts = ScriptOption::new()
        .set_name("compile_script_example")
        .set_runtime(ScriptRuntime::QJS);
    let bytecode = session
        .compile_script(SCRIPT_SOURCE, &mut compile_opts)
        .expect("compile_script failed");
    println!("[*] Compiled {} bytes of bytecode", bytecode.len());

    // 2. Demonstrate the ship-as-artifact workflow: write to disk, read back.
    std::fs::write(BYTECODE_PATH, &bytecode).expect("write bytecode failed");
    println!("[*] Wrote bytecode to {}", BYTECODE_PATH);
    let loaded = std::fs::read(BYTECODE_PATH).expect("read bytecode failed");
    println!("[*] Read {} bytes back from disk", loaded.len());

    // 3. Load the bytecode through create_script_from_bytes.
    let mut load_opts = ScriptOption::new()
        .set_name("compile_script_example")
        .set_runtime(ScriptRuntime::QJS);
    let mut script = session
        .create_script_from_bytes(&loaded, &mut load_opts)
        .expect("create_script_from_bytes failed");

    script
        .handle_message(Handler)
        .expect("handle_message failed");
    script.load().expect("script load failed");
    println!("[*] Script loaded from bytecode");

    script.unload().expect("script unload failed");
    println!("[*] Script unloaded");

    session.detach().expect("session detach failed");
    println!("[*] Session detached");

    let _ = std::fs::remove_file(BYTECODE_PATH);
}

struct Handler;

impl ScriptHandler for Handler {
    fn on_message(&mut self, message: Message, _data: Option<Vec<u8>>) {
        println!("- {:?}", message);
    }
}
