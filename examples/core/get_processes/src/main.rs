use frida::Frida;
use lazy_static::lazy_static;

lazy_static! {
    static ref FRIDA: Frida = unsafe { Frida::obtain() };
}

fn main() {
    let device_manager = frida::DeviceManager::obtain(&FRIDA);
    let local_device = device_manager.get_local_device().unwrap();
    let processes = local_device.enumerate_processes();

    for process in processes {
        println!("{} {:?}", process.get_name(), process.get_pid());
    }
}
