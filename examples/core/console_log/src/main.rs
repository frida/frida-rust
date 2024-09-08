use frida::{DeviceManager, Frida, ScriptHandler, ScriptOption, ScriptRuntime};
use lazy_static::lazy_static;

lazy_static! {
    static ref FRIDA: Frida = unsafe { Frida::obtain() };
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <PID>", args[0]);
        return;
    }

    let device_manager = DeviceManager::obtain(&FRIDA);
    let pid: u32 = args[1].parse().unwrap();

    if let Some(device) = device_manager.enumerate_all_devices().first() {
        println!("[*] First device: {}", device.get_name());

        let session = device.attach(pid).unwrap();

        if !session.is_detached() {
            println!("[*] Attached");

            let mut script_option = ScriptOption::new()
                .set_name("example")
                .set_runtime(ScriptRuntime::QJS);
            let mut script = session
                .create_script("console.log('Log test');", &mut script_option)
                .unwrap();

            script.handle_message(Handler).unwrap();

            script.load().unwrap();
            println!("[*] Script loaded");

            script.unload().unwrap();
            println!("[*] Script unloaded");

            session.detach().unwrap();
            println!("[*] Session detached");
        }
    };
}

struct Handler;

impl ScriptHandler for Handler {
    fn on_message(&mut self, message: &frida::Message) {
        println!("{:?}", message);
    }
}
