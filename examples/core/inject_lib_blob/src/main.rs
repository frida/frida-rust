#[cfg(target_os = "linux")]
use frida::{Frida, Inject};
#[cfg(target_os = "linux")]
use std::sync::LazyLock;

#[cfg(target_os = "linux")]
static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

#[cfg(target_os = "linux")]
fn main() {
    let device_manager = frida::DeviceManager::obtain(&FRIDA);
    let local_device = device_manager.get_local_device();
    let args: Vec<String> = std::env::args().collect();
    let pid = args[1].parse().unwrap();

    if let Ok(mut device) = local_device {
        println!("[*] Frida version: {}", frida::Frida::version());
        println!("[*] Device name: {}", device.get_name());

        let script_source = include_bytes!("../../../../target/release/libinject_example.so");
        let id = device
            .inject_library_blob_sync(pid, script_source, "injected_function", "w00t")
            .unwrap();

        println!("*** Injected, id={}", id);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("This example only works on Linux.");
}
