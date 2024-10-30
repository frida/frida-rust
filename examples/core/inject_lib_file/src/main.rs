use frida::{Frida, Inject};
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

fn main() {
    let device_manager = frida::DeviceManager::obtain(&FRIDA);
    let local_device = device_manager.get_local_device();
    let args: Vec<String> = std::env::args().collect();
    let pid = args[1].parse::<u32>().unwrap();
    let path = args[2].parse::<String>().unwrap();

    if let Ok(mut device) = local_device {
        println!("[*] Frida version: {}", frida::Frida::version());
        println!("[*] Device name: {}", device.get_name());

        let id = device
            .inject_library_file_sync(pid, path, "injected_function", "w00t")
            .unwrap();

        println!("*** Injected, id={}", id);
    }
}
