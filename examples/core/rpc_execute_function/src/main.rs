use frida::{Frida, Message};
use serde_json::json;
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

fn main() {
    let device_manager = frida::DeviceManager::obtain(&FRIDA);
    let local_device = device_manager.get_local_device();

    if let Ok(device) = local_device {
        println!("[*] Frida version: {}", frida::Frida::version());
        println!("[*] Device name: {}", device.get_name());

        // Attach to the program
        let session = device.attach(0).unwrap();

        let script_source = r#"
            var globalVar = 0;

            rpc.exports = {
                increment: function() {
                    globalVar += 1;
                    console.log("globalVar incremented by 1");
                },

                nIncrement: function(n) {
                    globalVar += n;
                    console.log("globalVar incremented by " + n);
                },

                getValue: function() {
                    return globalVar;
                },
                
                sumVals: function(vals, b) {
                    let sum = 0
                    for (let i=0; i < vals.length; i++) {
                        sum += vals[i]
                    }
                    return sum;
                },
                
                bye: function(name) {
                    console.log("Bye " + name);
                }
            };
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

        let js_functions = script.list_exports().unwrap();
        println!("{:?}", &js_functions);

        // Example calling a function in JS and giving the function name from `list_exports`
        // Expect a log message to be printed.
        let _ = script.exports.call(&js_functions[0], None); // Increment

        // Example calling a JS function, giving the function name as &str, and a "Number" parameter.
        let _ = script.exports.call("nIncrement", Some(json!([2])));

        // // Example showing how to get the returned value.
        let js_global_var = script.exports.call("getValue", None).unwrap().unwrap();
        println!("js_global_var: {}", js_global_var);

        // Example sending a String as parameter.
        // Expect a log message to be printed.
        let _ = script.exports.call("bye", Some(json!(["Potato"])));

        // Example showing sending multiple arguments.
        let total = script
            .exports
            .call("sumVals", Some(json!([[1, 2, 3, 4], true])))
            .unwrap()
            .unwrap();
        println!("total: {}", total);

        // Here I show how errors look like
        if let Err(err_msg) = script
            .exports
            .call("NonExistentFunc", Some(json!([[1, 2, 3, 4], true])))
        {
            println!("This is an error from JS: {}", err_msg);
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
    fn on_message(&mut self, message: Message, _data: Option<Vec<u8>>) {
        println!("- {:?}", message);
    }
}
