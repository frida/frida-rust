use frida::{Frida, Message};
use lazy_static::lazy_static;
use std::io::{self, Write};
use std::{thread, time::Duration};

lazy_static! {
    static ref FRIDA: Frida = unsafe { Frida::obtain() };
}

fn main() {
    let device_manager = frida::DeviceManager::obtain(&FRIDA);
    let local_device = device_manager.get_device_by_type(frida::DeviceType::Local);

    print!("Enter pid: ",);
    io::stdout().flush().expect("Failed to flush stdout");

    let mut pid_input = String::new();
    io::stdin()
        .read_line(&mut pid_input)
        .expect("Failed to read pid");

    let pid = pid_input
        .trim()
        .parse()
        .expect("Please enter a valid number");

    if let Ok(device) = local_device {
        println!("[*] Frida version: {}", frida::Frida::version());
        println!("[*] Device name: {}", device.get_name());

        // Attach to the program
        let session = match device.attach(pid) {
            Ok(s) => s,
            Err(_) => {
                println!("Error attaching to process {}", pid);
                return;
            }
        };

        if session.is_detached() {
            println!("Session is detached");
            return;
        }

        println!("[*] Attached to PID {}", pid);

        let script_source = r#"
            var globalVar = 0;
            console.log("Logging message from JS");
            console.warn("Warning message from JS");
            console.debug("Debug message from JS");
            console.error("Error message from JS");

            rpc.exports = {
                increment: function() {
                    globalVar += 1;
                    return globalVar;
                },
                getvalue: function() {
                    return globalVar;
                }
            };

            ;sdfsa // <- Intentional error here
        "#;
        let mut script_option = frida::ScriptOption::default();
        let mut script = match session.create_script(script_source, &mut script_option) {
            Ok(s) => s,
            Err(err) => {
                println!("{}", err);
                return;
            }
        };

        let msg_handler = script.handle_message(Handler);
        if let Err(err) = msg_handler {
            panic!("{:?}", err);
        }

        script.load().unwrap();
        println!("[*] Script loaded.");

        println!("{:?}", script.list_exports().unwrap());

        for _ in 0..2 {
            thread::sleep(Duration::from_secs(1));
            println!("{:?}", script.list_exports().unwrap());
        }

        script.unload().unwrap();
        println!("[*] Script unloaded");

        session.detach().unwrap();
        println!("[*] Session detached");
    }

    println!("Exiting...");
}

struct Handler;

impl frida::ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message) {
        println!("- {:?}", message);
    }
}
