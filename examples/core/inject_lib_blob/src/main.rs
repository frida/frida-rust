use frida::{Frida, Inject};
use lazy_static::lazy_static;

lazy_static! {
    static ref FRIDA: Frida = unsafe { Frida::obtain() };
}

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
